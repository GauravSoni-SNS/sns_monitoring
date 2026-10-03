//! Agent supervisor (spec §2, §3, §27, §42). Boots subsystems, runs collectors as
//! independent tasks with restart-on-fault isolation, and performs the graceful shutdown
//! lifecycle. This type is OS-independent; the Windows Service host (`service_win`) drives
//! it via the shutdown signal.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sns_core::collectors::system::{agent_shutdown_event, session_ended, session_started, ShutdownReason};
use sns_core::collectors::usb::{self, UsbDeviceInfo};
use sns_core::collectors::{screenshot, Collector};
use sns_core::config::{AgentConfig, Policy};
use sns_core::health::{ComponentHealth, HealthSnapshot, Status};
use sns_core::security::KeyManager;
use sns_core::storage::dropbox::{self, DropRecord};
use sns_core::storage::filesystem;
use sns_core::storage::retention::{self, StorageLevel};
use sns_core::storage::Storage;
use sns_shared::events::{ActivityEvent, EventType};
use sns_shared::ids::new_event_id;

use sns_core::clock::now_utc_iso;

pub struct Paths {
    // data root; consumed by the screenshot/retention/health tasks (#2, #3).
    #[allow(dead_code)]
    pub root: PathBuf,
    pub agent_json: PathBuf,
    pub policy_json: PathBuf,
    pub keyring: PathBuf,
    pub db: PathBuf,
}

impl Paths {
    pub fn from_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Paths {
            agent_json: root.join("config").join("agent.json"),
            policy_json: root.join("config").join("policy.json"),
            keyring: root.join("keys").join("keyring.json"),
            db: root.join("database").join("activity.db"),
            root,
        }
    }
}

pub struct Agent {
    cfg: AgentConfig,
    policy: Policy,
    storage: Storage,
    #[allow(dead_code)] // held to keep the DEK alive + zeroize on drop (spec §6, §21)
    keys: KeyManager,
    shutdown: Arc<AtomicBool>,
    data_root: PathBuf,
    // Last integrity result, surfaced in the health snapshot (spec §26).
    integrity_pass: bool,
    integrity_checked_at: String,
    // Only emit STORAGE_WARNING/CRITICAL on level transitions, not every tick.
    last_storage_level: StorageLevel,
    // Session logon/logoff signals pushed by the SCM control handler (spec §5, §15).
    session_inbox: Arc<Mutex<Vec<SessionSignal>>>,
    // Last-seen USB device set (all classes), for change detection (spec §16).
    prev_usb: Vec<UsbDeviceInfo>,
    // Throttle for the heavier auto-cleanup (browser purge + screenshot heuristic): run at
    // most once per CLEANUP_INTERVAL. `None` until the first run.
    last_cleanup: Option<std::time::Instant>,
}

/// Minimum spacing between auto-cleanup passes (browser purge + screenshot cleanup).
const CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6 * 3600);

/// A session change observed by the service control handler (spec §5, §15). Machine-level,
/// no auth secrets — just the numeric session id.
#[derive(Debug, Clone, Copy)]
pub enum SessionSignal {
    Started { session_id: u32 },
    Ended { session_id: u32 },
}

impl Agent {
    /// Boot sequence (spec §3): config → keys → db → integrity → AGENT_STARTUP → collectors.
    pub fn boot(paths: &Paths, shutdown: Arc<AtomicBool>) -> anyhow::Result<Self> {
        let cfg = AgentConfig::load(&paths.agent_json)?;
        let policy = Policy::load(&paths.policy_json)?;
        let keys = KeyManager::load(&paths.keyring)?;

        let mut storage = Storage::open(&paths.db, &cfg.device_id, &policy.durability.sqlite_synchronous)?;

        if !storage.integrity_check()? {
            tracing::error!("sqlite integrity_check failed; entering degraded mode");
            // Record but do not crash — safe read mode (spec §8, §42).
            let ev = lifecycle(&cfg.device_id, EventType::IntegrityFailure);
            let _ = storage.insert_activity_event(&ev);
        }

        storage.upsert_device(
            &cfg.system_name,
            sns_core::identity::hostname().as_deref(),
            os_version().as_deref(),
            &cfg.agent_version,
        )?;

        // Fast tail verification of the hash chain (spec §3, §22).
        let report = storage.verify_integrity()?;
        if !report.is_pass() {
            tracing::error!(invalid = report.invalid_records, "integrity chain break at boot");
            let ev = lifecycle(&cfg.device_id, EventType::IntegrityFailure);
            storage.insert_activity_event(&ev)?;
        }

        storage.insert_activity_event(&lifecycle(&cfg.device_id, EventType::AgentStartup))?;
        storage.audit("AGENT_STARTUP", Some("service"), None)?;

        Ok(Self {
            cfg,
            policy,
            storage,
            keys,
            shutdown,
            data_root: paths.root.clone(),
            integrity_pass: report.is_pass(),
            integrity_checked_at: now_utc_iso(),
            last_storage_level: StorageLevel::Ok,
            session_inbox: Arc::new(Mutex::new(Vec::new())),
            // Baseline currently-attached USB devices so we only emit CHANGES after boot
            // (no spurious "connected" for devices already plugged at startup).
            prev_usb: usb::list_usb_devices(),
            last_cleanup: None,
        })
    }

    /// Adopt the SCM control handler's session-signal inbox (Windows host). The handler
    /// pushes logon/logoff signals; the run loop drains them into chained events.
    pub fn attach_session_inbox(&mut self, inbox: Arc<Mutex<Vec<SessionSignal>>>) {
        self.session_inbox = inbox;
    }

    /// Drain session signals from the control handler into USER_SESSION_STARTED/ENDED events.
    /// `pub` so the lifecycle integration test can exercise it without the SCM.
    pub fn drain_session_signals(&mut self) {
        let signals: Vec<SessionSignal> = {
            let mut q = self.session_inbox.lock().unwrap();
            std::mem::take(&mut *q)
        };
        for sig in signals {
            let ev = match sig {
                SessionSignal::Started { session_id } => {
                    session_started(&self.cfg.device_id, &session_id.to_string(), "")
                }
                SessionSignal::Ended { session_id } => {
                    session_ended(&self.cfg.device_id, &session_id.to_string(), "")
                }
            };
            if let Err(e) = self.storage.insert_activity_event(&ev) {
                tracing::warn!(error = %e, "failed to persist session event");
            }
        }
    }

    /// Main supervised run loop. Each collector poll is isolated: an error restarts that
    /// collector with backoff and never stops the agent (spec §42).
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut collectors = self.build_collectors();
        let mut backoff: Vec<Duration> = vec![Duration::from_secs(0); collectors.len()];

        // Screenshot scheduler runs on its own cadence, independent of collector polling.
        let mut screenshot = ScreenshotScheduler::new(&self.policy);
        // Maintenance (storage level, retention, health snapshot) every ~60 ticks.
        let mut tick: u64 = 0;

        // Publish an initial health snapshot immediately so the CLI/admin have data.
        self.run_maintenance();

        while !self.shutdown.load(Ordering::Relaxed) {
            for (i, c) in collectors.iter_mut().enumerate() {
                match c.poll() {
                    Ok(events) => {
                        backoff[i] = Duration::from_secs(0);
                        for ev in events {
                            if let Err(e) = self.storage.insert_activity_event(&ev) {
                                tracing::error!(error = %e, "failed to persist event");
                            }
                        }
                    }
                    Err(e) => {
                        // Isolated fault: log, back off this collector only.
                        backoff[i] = next_backoff(backoff[i]);
                        tracing::warn!(collector = c.name(), error = %e, retry_in = ?backoff[i], "collector fault");
                    }
                }
            }

            // USB mass-storage connect/disconnect (spec §16). Cheap poll each tick.
            self.check_usb();

            // Session logon/logoff events pushed by the SCM control handler (spec §5, §15).
            self.drain_session_signals();

            // Ingest anything the user-session agent dropped (screenshots/events captured
            // where the interactive desktop actually is — see storage::dropbox).
            self.ingest_dropbox();

            // In-process capture path: only meaningful when the agent itself runs in an
            // interactive session (dev `--console`). Under the service (session 0) the
            // capture backend returns empty and this no-ops; production capture arrives via
            // the dropbox above.
            if screenshot.due() {
                if let Err(e) = self.capture_screenshots() {
                    tracing::warn!(error = %e, "screenshot capture failed");
                }
                screenshot.mark();
            }

            tick += 1;
            if tick % 60 == 0 {
                self.run_maintenance();
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Ok(())
    }

    /// Storage-level check, retention prune, and health snapshot (spec §17, §18, §25, §26).
    /// Never propagates errors — maintenance failure must not stop collection (spec §42).
    fn run_maintenance(&mut self) {
        let used = filesystem::dir_size_bytes(&self.data_root);

        // Storage thresholds → STORAGE_WARNING/CRITICAL on transition only (spec §18, §25-26).
        let level = retention::storage_level(used, &self.policy.storage);
        if level != self.last_storage_level {
            match level {
                StorageLevel::Warning => {
                    let _ = self.storage.insert_activity_event(
                        &lifecycle(&self.cfg.device_id, EventType::StorageWarning),
                    );
                    tracing::warn!(used, max = self.policy.storage.max_bytes, "storage warning");
                }
                StorageLevel::Critical => {
                    let _ = self.storage.insert_activity_event(
                        &lifecycle(&self.cfg.device_id, EventType::StorageCritical),
                    );
                    tracing::error!(used, max = self.policy.storage.max_bytes, "storage critical");
                }
                StorageLevel::Ok => {}
            }
            self.last_storage_level = level;
        }

        // Retention prune (non-chained tables; un-synced protected unless policy permits).
        match self.storage.prune_retention(
            self.policy.retention.screenshot_days,
            self.policy.retention.event_days,
            self.policy.retention.delete_unsynced,
        ) {
            Ok(out) if out.total() > 0 => {
                let meta = serde_json::json!({
                    "screenshots": out.screenshots_deleted,
                    "browser": out.browser_deleted,
                    "system": out.system_deleted,
                })
                .to_string();
                let _ = self.storage.audit("DATA_RETENTION_DELETE", Some("service"), Some(&meta));
                tracing::info!(deleted = out.total(), "retention prune");
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "retention prune failed"),
        }

        // Heavier auto-cleanup (browser purge + screenshot heuristic), throttled.
        let due = self.last_cleanup.map(|t| t.elapsed() >= CLEANUP_INTERVAL).unwrap_or(true);
        if due {
            self.run_auto_cleanup();
            self.last_cleanup = Some(std::time::Instant::now());
        }

        if let Err(e) = self.publish_health(used) {
            tracing::warn!(error = %e, "failed to publish health snapshot");
        }
    }

    /// Auto browser-history removal + screenshot cleanup per the current policy. Re-reads
    /// policy.json so panel edits take effect without a restart. Browser deletion re-seals the
    /// chain (feature #5). Runs in session 0 (SYSTEM) which can unwrap the machine-DPAPI DEK.
    fn run_auto_cleanup(&mut self) {
        // Re-read policy (panel may have changed retention since boot).
        let retention = match Policy::load(self.data_root.join("config").join("policy.json")) {
            Ok(p) => p.retention,
            Err(_) => self.policy.retention.clone(),
        };

        // Browser history.
        let br = &retention.browser;
        if br.mode != "none" {
            let cutoff = sns_core::clock::iso_days_ago(br.days);
            match self.storage.purge_browser(&br.mode, &br.domains, &cutoff) {
                Ok(n) if n > 0 => {
                    let _ = self.storage.audit("BROWSER_HISTORY_PURGED", Some("service"), Some(&format!("{{\"deleted\":{n},\"mode\":\"{}\"}}", br.mode)));
                    tracing::info!(deleted = n, mode = %br.mode, "auto browser purge");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "auto browser purge failed"),
            }
        }

        // Screenshots: age gate + heuristic.
        let sc = &retention.screenshot_cleanup;
        let age_cut = sns_core::clock::iso_days_ago(sc.max_age_days);
        let aged = self.storage.screenshots_for_cleanup(Some(&age_cut)).unwrap_or_default();
        let aged_ids: std::collections::HashSet<String> = aged.iter().map(|(id, _)| id.clone()).collect();
        let mut path_of: std::collections::HashMap<String, String> =
            aged.iter().cloned().map(|(id, p)| (id, p)).collect();

        let mut heuristic_ids: Vec<String> = Vec::new();
        if sc.heuristic_enabled {
            let survivors: Vec<(String, String)> = self
                .storage
                .screenshots_for_cleanup(None)
                .unwrap_or_default()
                .into_iter()
                .filter(|(id, _)| !aged_ids.contains(id))
                .collect();
            let frames: Vec<(String, Option<sns_core::collectors::screenshot::Fingerprint>)> = survivors
                .iter()
                .map(|(id, path)| {
                    let fp = std::fs::read(path)
                        .ok()
                        .and_then(|blob| sns_core::security::crypto::decrypt(self.keys.data_key(), &blob).ok())
                        .and_then(|png| sns_core::collectors::screenshot::fingerprint(&png).ok());
                    (id.clone(), fp)
                })
                .collect();
            for (id, p) in &survivors {
                path_of.insert(id.clone(), p.clone());
            }
            heuristic_ids = sns_core::collectors::screenshot::plan_cleanup(&frames, true);
        }

        let mut all_ids: Vec<String> = aged_ids.iter().cloned().collect();
        all_ids.extend(heuristic_ids.iter().cloned());
        if !all_ids.is_empty() {
            match self.storage.delete_screenshots_by_ids(&all_ids) {
                Ok(n) => {
                    for id in &all_ids {
                        if let Some(p) = path_of.get(id) {
                            let _ = std::fs::remove_file(p);
                        }
                    }
                    let _ = self.storage.audit(
                        "SCREENSHOTS_CLEANED",
                        Some("service"),
                        Some(&format!("{{\"age\":{},\"heuristic\":{},\"deleted\":{}}}", aged_ids.len(), heuristic_ids.len(), n)),
                    );
                    tracing::info!(deleted = n, "auto screenshot cleanup");
                }
                Err(e) => tracing::warn!(error = %e, "auto screenshot cleanup failed"),
            }
        }
    }

    /// Write `runtime/health.json` for the CLI (`sns-agentctl health`) and admin panel
    /// (spec §25, §26). No secrets in the snapshot.
    fn publish_health(&self, used_bytes: u64) -> anyhow::Result<()> {
        let snapshot = HealthSnapshot {
            agent_status: Status::Running,
            database: if self.storage.integrity_check().unwrap_or(false) {
                ComponentHealth::Healthy
            } else {
                ComponentHealth::Degraded
            },
            encryption: ComponentHealth::Healthy,
            storage_used_bytes: used_bytes,
            storage_max_bytes: self.policy.storage.max_bytes,
            last_event_utc: self.storage.last_activity_time().unwrap_or(None),
            last_screenshot_utc: self.storage.last_screenshot_time().unwrap_or(None),
            last_integrity_check_utc: Some(self.integrity_checked_at.clone()),
            last_integrity_pass: Some(self.integrity_pass),
            agent_version: self.cfg.agent_version.clone(),
            configuration_version: self.policy.schema_version,
        };
        let dir = self.data_root.join("runtime");
        std::fs::create_dir_all(&dir)?;
        // Write atomically: temp file then rename, so a reader never sees a partial file.
        let tmp = dir.join("health.json.tmp");
        let final_path = dir.join("health.json");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&snapshot)?)?;
        std::fs::rename(&tmp, &final_path)?;
        Ok(())
    }

    /// Capture the authorized display(s) → encrypt → hash → store → SCREENSHOT_CREATED
    /// (spec §19). Capture is best-effort: if the platform grab yields no frame yet, we
    /// skip silently (no empty files). Real DXGI/GDI capture lives in `screenshot`.
    fn capture_screenshots(&mut self) -> anyhow::Result<()> {
        if !self.policy.screenshot.enabled {
            return Ok(());
        }
        for monitor_id in enumerate_monitors(&self.policy.screenshot.monitors) {
            let png = screenshot::capture_monitor(monitor_id, self.policy.screenshot.max_dimension)?;
            if png.is_empty() {
                continue; // no frame available (capture backend not active) — never store empty
            }
            let meta = screenshot::persist_capture(
                &self.data_root,
                self.keys.data_key(),
                &self.cfg.device_id,
                Some(monitor_id),
                &png,
            )?;
            self.storage.insert_screenshot(&meta)?;

            let m = serde_json::json!({
                "screenshot_id": meta.screenshot_id,
                "monitor": monitor_id,
            })
            .to_string();
            let mut ev = lifecycle(&self.cfg.device_id, EventType::ScreenshotCreated);
            ev.metadata_json = Some(m);
            self.storage.insert_activity_event(&ev)?;
        }
        Ok(())
    }

    /// Detect USB device connect/disconnect (any class) and chain the events (spec §16).
    /// Records device identity (VID/PID/serial/description) only — never file contents.
    fn check_usb(&mut self) {
        let cur = usb::list_usb_devices();
        let (arrivals, removals) = usb::diff_devices(&self.prev_usb, &cur);
        let emit = |storage: &mut Storage, dev_id: &str, d: &UsbDeviceInfo, ty: EventType| {
            let meta = serde_json::json!({
                "instance_id": d.instance_id,
                "vendor_id": d.vendor_id,
                "product_id": d.product_id,
                "serial": d.serial,
                "description": d.description,
            })
            .to_string();
            let mut ev = lifecycle(dev_id, ty);
            ev.metadata_json = Some(meta);
            let _ = storage.insert_activity_event(&ev);
        };
        for d in &arrivals {
            emit(&mut self.storage, &self.cfg.device_id, d, EventType::UsbDeviceConnected);
            tracing::info!(desc = ?d.description, vid = ?d.vendor_id, "usb device connected");
        }
        for d in &removals {
            emit(&mut self.storage, &self.cfg.device_id, d, EventType::UsbDeviceDisconnected);
            tracing::info!(desc = ?d.description, "usb device disconnected");
        }
        self.prev_usb = cur;
    }

    /// Ingest drop-box manifests written by the user-session agent, into SQLite (single
    /// writer = the service). Each manifest is deleted only after its row commits, so a
    /// crash mid-ingest re-processes it next tick (idempotent via unique ids). Never
    /// propagates errors — a bad manifest must not stop collection (spec §42).
    fn ingest_dropbox(&mut self) {
        for path in dropbox::list_manifests(&self.data_root) {
            // `processed` gates deletion: only remove the manifest once its data is safely
            // in SQLite (or provably already there). A hard failure keeps it for retry.
            let processed = match dropbox::read_record(&path) {
                Ok(DropRecord::Screenshot(meta)) => match self.storage.insert_screenshot(&meta) {
                    Ok(true) => {
                        // Newly inserted → emit SCREENSHOT_CREATED exactly once.
                        let m = serde_json::json!({
                            "screenshot_id": meta.screenshot_id,
                            "monitor": meta.monitor_id,
                        })
                        .to_string();
                        let mut ev = lifecycle(&self.cfg.device_id, EventType::ScreenshotCreated);
                        ev.metadata_json = Some(m);
                        let _ = self.storage.insert_activity_event(&ev);
                        true
                    }
                    Ok(false) => true, // already present (idempotent re-ingest) → safe to drop
                    Err(e) => {
                        tracing::warn!(error = %e, "ingest: screenshot insert failed; will retry");
                        false
                    }
                },
                Ok(DropRecord::Activity(ev)) => {
                    match self.storage.activity_exists(&ev.event_id) {
                        Ok(true) => true, // already ingested
                        Ok(false) => match self.storage.insert_activity_event(&ev) {
                            Ok(_) => true,
                            Err(e) => {
                                tracing::warn!(error = %e, "ingest: activity insert failed; will retry");
                                false
                            }
                        },
                        Err(e) => {
                            tracing::warn!(error = %e, "ingest: existence check failed; will retry");
                            false
                        }
                    }
                }
                // A corrupt/unparseable manifest will never succeed: quarantine it so it does
                // not loop forever, rather than deleting (which loses evidence) or retrying.
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "ingest: bad manifest; quarantining");
                    let _ = self.quarantine_manifest(&path);
                    false
                }
            };
            if processed {
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    /// Move an unparseable manifest to `runtime/incoming/bad/` so ingestion does not loop.
    fn quarantine_manifest(&self, path: &std::path::Path) -> std::io::Result<()> {
        let bad = self.data_root.join("runtime").join("incoming").join("bad");
        std::fs::create_dir_all(&bad)?;
        if let Some(name) = path.file_name() {
            std::fs::rename(path, bad.join(name))?;
        }
        Ok(())
    }

    fn build_collectors(&self) -> Vec<Box<dyn Collector>> {
        use sns_core::collectors::application::ApplicationCollector;
        use sns_core::collectors::browser::{BrowserCollector, Granularity};

        let mut v: Vec<Box<dyn Collector>> = Vec::new();
        if self.policy.application.enabled {
            v.push(Box::new(ApplicationCollector::new(
                &self.cfg.device_id,
                self.policy.application.capture_window_title,
            )));
        }
        if self.policy.browser.enabled {
            let g = if self.policy.browser.granularity == "url" { Granularity::Url } else { Granularity::Domain };
            v.push(Box::new(BrowserCollector::new(&self.cfg.device_id, g)));
        }
        // Screenshot + system/session/USB collectors are driven by timers / the service
        // control handler respectively (wired in the Windows host); see BUILD-STATUS.md.
        v
    }

    /// Graceful shutdown (spec §6, §7, §28). Idempotent.
    pub fn shutdown(&mut self, reason: ShutdownReason) {
        tracing::info!(reason = reason.as_str(), "agent shutdown starting");
        let ev = agent_shutdown_event(&self.cfg.device_id, &self.cfg.agent_version, reason);
        if let Err(e) = self.storage.insert_activity_event(&ev) {
            tracing::error!(error = %e, "failed to write AGENT_SHUTDOWN");
        }
        let _ = self.storage.audit("AGENT_SHUTDOWN", Some("service"), None);
        if let Err(e) = self.storage.checkpoint_truncate() {
            tracing::error!(error = %e, "wal checkpoint failed on shutdown");
        }
        // `keys` (KeyManager → DataKey → Zeroizing) is dropped when `self` drops → DEK wiped.
    }
}

fn lifecycle(device_id: &str, ty: EventType) -> ActivityEvent {
    ActivityEvent {
        event_id: new_event_id(),
        device_id: device_id.to_string(),
        event_type: ty,
        timestamp_utc: now_utc_iso(),
        application_name: None,
        process_name: None,
        window_title: None,
        metadata_json: None,
    }
}

fn next_backoff(current: Duration) -> Duration {
    let next = if current.is_zero() { Duration::from_secs(2) } else { current * 2 };
    next.min(Duration::from_secs(300)) // cap 5m; avoid rapid restart loop (spec §27)
}

/// Interval timer for screenshots (spec §19). Fires immediately on first check, then on
/// each `interval`. Monotonic `Instant` — unaffected by wall-clock changes.
struct ScreenshotScheduler {
    enabled: bool,
    interval: Duration,
    last: Option<Instant>,
}

impl ScreenshotScheduler {
    fn new(policy: &Policy) -> Self {
        Self {
            enabled: policy.screenshot.enabled,
            interval: Duration::from_secs(policy.screenshot.interval_seconds),
            last: None,
        }
    }

    fn due(&self) -> bool {
        if !self.enabled {
            return false;
        }
        match self.last {
            None => true,
            Some(t) => t.elapsed() >= self.interval,
        }
    }

    fn mark(&mut self) {
        self.last = Some(Instant::now());
    }
}

/// Monitor ids to capture. Phase 1 captures the primary display (id 0); multi-display
/// enumeration is a DXGI refinement (`_policy_value` will select "primary" vs "all" then).
fn enumerate_monitors(_policy_value: &str) -> Vec<u32> {
    vec![0]
}

fn os_version() -> Option<String> {
    // Placeholder; Windows host fills this from RtlGetVersion at boot.
    None
}
