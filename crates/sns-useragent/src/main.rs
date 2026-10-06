//! `sns-useragent` — the user-session collector (session-0-isolation companion to the
//! service). Runs inside the interactive desktop session (started at logon), where the
//! screen, foreground window, and browser are actually reachable. It captures and writes
//! records to the service's drop box (`runtime/incoming/`); the session-0 service ingests
//! them into SQLite. See docs/SCREENSHOT.md and docs/SERVICE-LIFECYCLE.md.
//!
//! It never writes to SQLite directly (single-writer = the service). It uses the same
//! machine-DPAPI-wrapped DEK (LocalMachine scope is readable from the user session), so
//! screenshots are encrypted before they ever leave this process.
//!
//! This is NOT covert: it is a named, installed component launched by a visible scheduled
//! task, writing only to the agent's own ACL-protected directory.
//
// Release builds run windowless (GUI subsystem) so no blank console appears at logon — it
// is a background agent and logs to a file, not a console. Debug builds keep the console so
// developers still see stderr/`Error:` output when running it by hand.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sns_core::collectors::application::{self, ApplicationCollector};
use sns_core::collectors::browser::{BrowserCollector, Granularity};
use sns_core::collectors::idle;
use sns_core::collectors::print;
use sns_core::collectors::screenshot;
use sns_core::collectors::usbfiles;
use sns_core::config::{AgentConfig, Policy};
use sns_core::security::KeyManager;
use sns_core::storage::dropbox::{self, DropRecord};

fn data_root() -> PathBuf {
    std::env::var_os("SNS_DATA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(sns_core::DEFAULT_DATA_ROOT))
}

fn main() -> anyhow::Result<()> {
    let root = data_root();
    init_logging(&root);

    // Only one capture agent per machine — a second (duplicate task fire / manual overlap)
    // exits immediately so we never double-capture.
    // Session-scoped ("Local\") so a standard user can create it (the "Global\" namespace
    // needs SeCreateGlobalPrivilege, which limited users lack). One agent per session is the
    // correct scope anyway — fast-user-switching gives each user their own capture.
    let _singleton = match sns_core::singleton::acquire("Local\\SNSSecurityCaptureAgent") {
        Some(g) => g,
        None => {
            tracing::info!("another capture agent is already running; exiting");
            return Ok(());
        }
    };

    let cfg = AgentConfig::load(root.join("config").join("agent.json"))?;
    let policy = Policy::load(root.join("config").join("policy.json"))?;
    let keys = KeyManager::load(root.join("keys").join("keyring.json"))?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let sig = shutdown.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            sig.store(true, Ordering::Relaxed);
        });

        let interval = Duration::from_secs(policy.screenshot.interval_seconds.max(1));
        let mut last_shot: Option<Instant> = None;

        // Interactive collectors run here, in the user session (spec §13, §14).
        let mut app = ApplicationCollector::new(&cfg.device_id, policy.application.capture_window_title);
        let granularity = if policy.browser.granularity == "url" { Granularity::Url } else { Granularity::Domain };
        let browser = BrowserCollector::new(&cfg.device_id, granularity);
        let mut idle = idle::IdleTracker::new();

        // Exfil watch (metadata only). USB file snapshot baselined so pre-existing files are
        // not reported as "copied"; only files written after start fire events.
        let mut usb_snapshot = usbfiles::snapshot_removable();
        let mut last_usb_scan = Instant::now();
        let usb_scan_every = Duration::from_secs(20);
        let mut print_tracker = print::PrintTracker::new();
        // Baseline existing spooler jobs so only new ones after start are reported.
        print_tracker.newly_seen(&print::current_jobs());
        let mut last_print_scan = Instant::now();
        let print_scan_every = Duration::from_secs(5);

        tracing::info!(device = %cfg.device_id, "user-session agent started");
        while !shutdown.load(Ordering::Relaxed) {
            // Foreground application (and browser, if the foreground is a browser).
            if policy.application.enabled {
                sample_apps(&root, &policy, &mut app, &browser);
            }

            // Idle / active transitions (coarse presence; reads time-of-last-input only).
            if policy.idle.enabled {
                sample_idle(&root, &cfg.device_id, &policy, &mut idle);
            }

            // Exfil: files written to removable drives (metadata only).
            if policy.exfil.usb_file_watch && last_usb_scan.elapsed() >= usb_scan_every {
                sample_usb_files(&root, &cfg.device_id, &mut usb_snapshot);
                last_usb_scan = Instant::now();
            }

            // Exfil: documents sent to printers (metadata only).
            if policy.exfil.print_watch && last_print_scan.elapsed() >= print_scan_every {
                sample_print(&root, &cfg.device_id, &mut print_tracker);
                last_print_scan = Instant::now();
            }

            // Screenshots on the configured interval.
            if policy.screenshot.enabled {
                let due = last_shot.map(|t| t.elapsed() >= interval).unwrap_or(true);
                if due {
                    if let Err(e) = capture_once(&root, &cfg, &policy, &keys) {
                        tracing::warn!(error = %e, "screenshot capture failed");
                    }
                    last_shot = Some(Instant::now());
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        tracing::info!("user-session agent stopping");
        anyhow::Ok(())
    })
}

/// Sample the foreground window; on a focus/title change emit ACTIVE_APPLICATION_CHANGED,
/// and if the foreground process is a browser also emit BROWSER_ACTIVITY (domain/title).
/// Only records process name + window caption — never keystrokes/clipboard/passwords.
fn sample_apps(
    root: &std::path::Path,
    policy: &Policy,
    app: &mut ApplicationCollector,
    browser: &BrowserCollector,
) {
    let Some(sample) = application::foreground_sample() else { return };
    let browser_name = application::is_browser_process(&sample.process_name);

    let events = app.on_sample(sample);
    let changed = !events.is_empty();
    for ev in events {
        let stem = ev.event_id.clone();
        if let Err(e) = dropbox::write_record(root, &stem, &DropRecord::Activity(ev)) {
            tracing::warn!(error = %e, "failed to drop activity record");
        }
    }

    // Emit a browser-activity record only on an actual change (tab/window switch changes
    // the caption), to avoid per-second spam. The site value is the live on-screen address
    // bar (URL/domain) read via UI Automation — mode-agnostic (covers normal/guest/private
    // that is currently visible), never history recovery or private-store reading. Falls
    // back to nothing if the address bar is unreadable (we do not record page titles as
    // sites, since a title is not a URL).
    if changed && policy.browser.enabled {
        if let Some(bname) = browser_name {
            if let Some(url) = sns_core::collectors::browser::foreground_browser_url() {
                let ev = browser.build_event(bname, &url);
                let stem = ev.event_id.clone();
                if let Err(e) = dropbox::write_record(root, &stem, &DropRecord::Activity(ev)) {
                    tracing::warn!(error = %e, "failed to drop browser record");
                }
            }
        }
    }
}

/// Sample idle time and, on a state flip (active↔idle past the policy threshold), drop a
/// SESSION_IDLE / SESSION_ACTIVE record. Reads only the time of the last input — never the
/// input itself (no keystrokes/mouse/clipboard; spec §17).
fn sample_idle(
    root: &std::path::Path,
    device_id: &str,
    policy: &Policy,
    idle: &mut idle::IdleTracker,
) {
    let secs = idle::idle_seconds();
    if let Some(now_idle) = idle.update(secs, policy.idle.threshold_seconds) {
        let ev = idle::build_event(device_id, now_idle, secs);
        let stem = ev.event_id.clone();
        if let Err(e) = dropbox::write_record(root, &stem, &DropRecord::Activity(ev)) {
            tracing::warn!(error = %e, "failed to drop idle record");
        }
    }
}

/// Re-snapshot removable drives and drop FILE_COPIED_TO_USB records for files that newly
/// appeared or changed size. Metadata only (name + size); never reads file contents.
fn sample_usb_files(
    root: &std::path::Path,
    device_id: &str,
    prev: &mut usbfiles::UsbSnapshot,
) {
    let cur = usbfiles::snapshot_removable();
    for f in usbfiles::diff_snapshots(prev, &cur) {
        let ev = usbfiles::build_event(device_id, &f);
        let stem = ev.event_id.clone();
        if let Err(e) = dropbox::write_record(root, &stem, &DropRecord::Activity(ev)) {
            tracing::warn!(error = %e, "failed to drop usb-file record");
        }
    }
    *prev = cur;
}

/// Poll the print spooler and drop DOCUMENT_PRINTED records for new jobs. Metadata only
/// (document name, printer, pages); never reads the document content.
fn sample_print(
    root: &std::path::Path,
    device_id: &str,
    tracker: &mut print::PrintTracker,
) {
    for j in tracker.newly_seen(&print::current_jobs()) {
        let ev = print::build_event(device_id, &j);
        let stem = ev.event_id.clone();
        if let Err(e) = dropbox::write_record(root, &stem, &DropRecord::Activity(ev)) {
            tracing::warn!(error = %e, "failed to drop print record");
        }
    }
}

/// Capture each authorized monitor, encrypt+store the file, and drop a manifest for the
/// service to ingest. Skips silently if the capture backend yields no frame.
fn capture_once(
    root: &std::path::Path,
    cfg: &AgentConfig,
    policy: &Policy,
    keys: &KeyManager,
) -> anyhow::Result<()> {
    // Phase 1 captures the primary display; multi-monitor enumeration is a DXGI refinement.
    for monitor_id in [0u32] {
        let png = screenshot::capture_monitor(monitor_id, policy.screenshot.max_dimension)?;
        if png.is_empty() {
            continue;
        }
        let meta = screenshot::persist_capture(root, keys.data_key(), &cfg.device_id, Some(monitor_id), &png)?;
        let stem = meta.screenshot_id.clone();
        dropbox::write_record(root, &stem, &DropRecord::Screenshot(meta))?;
        tracing::info!(id = %stem, "captured + dropped screenshot manifest");
    }
    Ok(())
}

fn init_logging(root: &std::path::Path) {
    let logs = root.join("logs");
    let _ = std::fs::create_dir_all(&logs);
    // IST-dated log filename (suffix in India Standard Time).
    let (y, m, d) = sns_core::clock::ymd_utc();
    let file = tracing_appender::rolling::never(&logs, format!("useragent-{y:04}-{m:02}-{d:02}.log"));
    let _ = tracing_subscriber::fmt()
        .with_writer(file)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SNS_LOG").unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}
