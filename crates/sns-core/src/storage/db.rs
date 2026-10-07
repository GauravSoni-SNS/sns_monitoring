//! SQLite storage (spec §13, §14). WAL, transactional, single-writer. Owns the integrity
//! chain head so activity events are sealed and inserted atomically.

use std::path::Path;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sns_shared::events::ActivityEvent;
use sns_shared::models::ScreenshotMeta;
use sns_shared::sync::SyncStatus;
use sns_shared::GENESIS_HASH;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::clock::{iso_days_ago, now_utc_iso};
use crate::error::{CoreError, Result};
use crate::security::integrity::{StoredEvent, VerifyReport};
use crate::security::integrity;

const MIGRATION_0001: &str = include_str!("../../../../migrations/0001_init.sql");

/// Per-table counts from a retention pass (spec §17, §18 DATA_RETENTION_DELETE audit).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionOutcome {
    pub screenshots_deleted: usize,
    pub browser_deleted: usize,
    pub system_deleted: usize,
}

impl RetentionOutcome {
    pub fn total(&self) -> usize {
        self.screenshots_deleted + self.browser_deleted + self.system_deleted
    }
}

/// Read-model rows returned to the admin backend (serialized to JSON).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ActivityRow {
    pub event_id: String,
    pub event_type: String,
    pub timestamp_utc: String,
    pub application_name: Option<String>,
    pub window_title: Option<String>,
    pub metadata_json: Option<String>,
}

/// Wire shape for central-server upload (Phase D). Matches the server's `WireEvent`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncEvent {
    pub event_id: String,
    pub event_type: String,
    pub timestamp_utc: String,
    pub application_name: Option<String>,
    pub window_title: Option<String>,
    pub metadata_json: Option<String>,
    pub event_hash: Option<String>,
    pub previous_event_hash: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditRow {
    pub action: String,
    pub timestamp_utc: String,
    pub actor: Option<String>,
    pub metadata_json: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceRow {
    pub device_id: String,
    pub system_name: String,
    pub hostname: Option<String>,
    pub os_version: Option<String>,
    pub agent_version: Option<String>,
    pub last_seen_at: Option<String>,
}

/// One row of the usage-time report (spec §17 duration; Phase-2 B).
#[derive(Debug, Clone, serde::Serialize)]
pub struct UsageItem {
    pub name: String,
    pub seconds: i64,
    pub sessions: i64,
}

fn parse_sync_status(s: &str) -> SyncStatus {
    match s {
        "QUEUED" => SyncStatus::Queued,
        "SYNCING" => SyncStatus::Syncing,
        "SYNCED" => SyncStatus::Synced,
        "SYNC_FAILED" => SyncStatus::SyncFailed,
        _ => SyncStatus::LocalOnly,
    }
}

/// Aggregate (name, timestamp) rows (ascending) into per-name usage seconds. Each segment
/// is the gap to the next focus change, capped at `idle_cap` and dropped if non-positive.
fn aggregate_usage(rows: &[(String, String)], idle_cap: i64) -> Vec<UsageItem> {
    use std::collections::HashMap;
    let mut totals: HashMap<String, (i64, i64)> = HashMap::new();
    for pair in rows.windows(2) {
        let (name, t0) = &pair[0];
        let (_, t1) = &pair[1];
        let (Ok(a), Ok(b)) = (
            OffsetDateTime::parse(t0, &Rfc3339),
            OffsetDateTime::parse(t1, &Rfc3339),
        ) else {
            continue;
        };
        let secs = (b - a).whole_seconds();
        if secs <= 0 {
            continue;
        }
        let capped = secs.min(idle_cap);
        let e = totals.entry(name.clone()).or_insert((0, 0));
        e.0 += capped;
        e.1 += 1;
    }
    let mut out: Vec<UsageItem> = totals
        .into_iter()
        .map(|(name, (seconds, sessions))| UsageItem { name, seconds, sessions })
        .collect();
    out.sort_by(|a, b| b.seconds.cmp(&a.seconds));
    out
}

/// Sum idle spans from ordered (event_type, timestamp) rows of SESSION_IDLE/SESSION_ACTIVE.
/// A SESSION_IDLE opens an interval; the next SESSION_ACTIVE closes it. A trailing open idle
/// is closed at `now_iso`. Negative/garbage spans are skipped.
fn sum_idle(rows: &[(String, String)], now_iso: &str) -> i64 {
    let mut total = 0i64;
    let mut idle_start: Option<OffsetDateTime> = None;
    for (etype, ts) in rows {
        let Ok(t) = OffsetDateTime::parse(ts, &Rfc3339) else { continue };
        match etype.as_str() {
            "SESSION_IDLE" => idle_start = Some(t),
            "SESSION_ACTIVE" => {
                if let Some(start) = idle_start.take() {
                    let secs = (t - start).whole_seconds();
                    if secs > 0 {
                        total += secs;
                    }
                }
            }
            _ => {}
        }
    }
    // Still idle now: close the open interval at `now`.
    if let Some(start) = idle_start {
        if let Ok(now) = OffsetDateTime::parse(now_iso, &Rfc3339) {
            let secs = (now - start).whole_seconds();
            if secs > 0 {
                total += secs;
            }
        }
    }
    total
}

fn row_to_screenshot(r: &rusqlite::Row) -> ScreenshotMeta {
    let sync: String = r.get(9).unwrap_or_else(|_| "LOCAL_ONLY".into());
    ScreenshotMeta {
        screenshot_id: r.get(0).unwrap_or_default(),
        device_id: r.get(1).unwrap_or_default(),
        timestamp_utc: r.get(2).unwrap_or_default(),
        file_path: r.get(3).unwrap_or_default(),
        file_size: r.get(4).unwrap_or(0),
        sha256: r.get(5).unwrap_or_default(),
        encryption_version: r.get(6).unwrap_or(1),
        monitor_id: r.get(7).ok(),
        created_at: r.get(8).unwrap_or_default(),
        sync_status: parse_sync_status(&sync),
    }
}

pub struct Storage {
    conn: Connection,
    device_id: String,
    /// Cached chain head; kept in lockstep with the last committed activity event.
    chain_head: String,
}

impl Storage {
    /// Open (creating if needed) and apply pragmas + migrations. `synchronous` is
    /// "NORMAL" or "FULL" from policy.
    pub fn open(db_path: impl AsRef<Path>, device_id: &str, synchronous: &str) -> Result<Self> {
        if let Some(parent) = db_path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open_with_flags(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        conn.busy_timeout(std::time::Duration::from_millis(5000))?;
        // journal_mode returns the new mode as a row, so use query_row (not pragma_update).
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        // `synchronous` is validated upstream to NORMAL|FULL, safe to inline.
        let sync = if synchronous.eq_ignore_ascii_case("FULL") { "FULL" } else { "NORMAL" };
        conn.execute_batch(&format!(
            "PRAGMA synchronous={sync}; PRAGMA foreign_keys=ON;"
        ))?;

        let mut s = Self { conn, device_id: device_id.to_string(), chain_head: GENESIS_HASH.into() };
        s.migrate()?;
        s.chain_head = s.load_head_hash()?;
        Ok(s)
    }

    /// Light open for the admin panel / CLI: skips the per-request migration + journal-mode
    /// change (the service owns WAL) to remove the contention that slowed the panel. Opened
    /// READ_WRITE — SQLite WAL must touch the shared `-shm`/`-wal` files even to read, and the
    /// admin appends to `audit_log` (login / screenshot-view / tamper). The caller therefore
    /// still needs write access to `database\` (elevated / SYSTEM), which is by design. It
    /// never writes `activity_events`, so the hash chain is untouched.
    pub fn open_reader(db_path: impl AsRef<Path>, device_id: &str) -> Result<Self> {
        let conn = Connection::open_with_flags(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE, // no CREATE: fail cleanly if the DB is missing
        )?;
        conn.busy_timeout(std::time::Duration::from_millis(5000))?;
        Ok(Self { conn, device_id: device_id.to_string(), chain_head: GENESIS_HASH.into() })
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(MIGRATION_0001)?;
        let already: bool = self
            .conn
            .query_row("SELECT 1 FROM schema_migrations WHERE version = 1", [], |_| Ok(true))
            .unwrap_or(false);
        if !already {
            self.conn.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?1)",
                params![now_utc_iso()],
            )?;
        }
        Ok(())
    }

    /// `PRAGMA integrity_check` — physical DB health after a crash/power loss (spec §8).
    pub fn integrity_check(&self) -> Result<bool> {
        let result: String =
            self.conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        Ok(result == "ok")
    }

    fn load_head_hash(&self) -> Result<String> {
        let head: Option<String> = self
            .conn
            .query_row(
                "SELECT event_hash FROM activity_events ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .ok();
        Ok(head.unwrap_or_else(|| GENESIS_HASH.to_string()))
    }

    /// Seal an activity event against the current chain head and insert it in one
    /// transaction. Returns the new head hash.
    pub fn insert_activity_event(&mut self, event: &ActivityEvent) -> Result<String> {
        let sealed = event.seal(&self.chain_head);
        let created = now_utc_iso();
        self.conn.execute(
            "INSERT INTO activity_events
               (event_id, device_id, user_id, event_type, timestamp_utc,
                application_name, process_name, window_title, metadata_json,
                event_hash, previous_event_hash, created_at, sync_status)
             VALUES (?1,?2,NULL,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                event.event_id,
                event.device_id,
                event.event_type.as_str(),
                event.timestamp_utc,
                event.application_name,
                event.process_name,
                event.window_title,
                event.metadata_json,
                sealed.event_hash,
                sealed.previous_event_hash,
                created,
                SyncStatus::LocalOnly.as_str(),
            ],
        )?;
        self.chain_head = sealed.event_hash.clone();
        Ok(sealed.event_hash)
    }

    /// Load the whole activity chain in insertion order for verification (spec §22).
    pub fn load_activity_chain(&self) -> Result<Vec<StoredEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id, device_id, event_type, timestamp_utc, application_name,
                    process_name, window_title, metadata_json, event_hash, previous_event_hash
             FROM activity_events ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            let event_type_str: String = r.get(2)?;
            let event_type = serde_json::from_value(serde_json::Value::String(event_type_str))
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e)))?;
            Ok(StoredEvent {
                event: ActivityEvent {
                    event_id: r.get(0)?,
                    device_id: r.get(1)?,
                    event_type,
                    timestamp_utc: r.get(3)?,
                    application_name: r.get(4)?,
                    process_name: r.get(5)?,
                    window_title: r.get(6)?,
                    metadata_json: r.get(7)?,
                },
                event_hash: r.get(8)?,
                previous_event_hash: r.get(9)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Run full chain verification (spec §22). Emits nothing itself; caller records
    /// an INTEGRITY_FAILURE system event if this fails.
    pub fn verify_integrity(&self) -> Result<VerifyReport> {
        Ok(integrity::verify_chain(&self.load_activity_chain()?))
    }

    /// Insert or refresh the single device row (spec §14).
    pub fn upsert_device(
        &self,
        system_name: &str,
        hostname: Option<&str>,
        os_version: Option<&str>,
        agent_version: &str,
    ) -> Result<()> {
        let now = now_utc_iso();
        self.conn.execute(
            "INSERT INTO devices
               (device_id, system_name, hostname, os_version, agent_version,
                created_at, updated_at, last_seen_at)
             VALUES (?1,?2,?3,?4,?5,?6,?6,?6)
             ON CONFLICT(device_id) DO UPDATE SET
               system_name=excluded.system_name,
               hostname=excluded.hostname,
               os_version=excluded.os_version,
               agent_version=excluded.agent_version,
               updated_at=excluded.updated_at,
               last_seen_at=excluded.last_seen_at",
            params![self.device_id, system_name, hostname, os_version, agent_version, now],
        )?;
        Ok(())
    }

    /// Append an audit-log entry (append-only; spec §14, §40).
    pub fn audit(&self, action: &str, actor: Option<&str>, metadata_json: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO audit_log(action, timestamp_utc, actor, metadata_json)
             VALUES (?1,?2,?3,?4)",
            params![action, now_utc_iso(), actor, metadata_json],
        )?;
        Ok(())
    }

    /// Insert screenshot metadata (spec §14, §19). Blob already encrypted on disk.
    /// Idempotent: `INSERT OR IGNORE` on the unique `screenshot_id`. Returns `true` only if
    /// a new row was inserted, so callers emit SCREENSHOT_CREATED exactly once even if a
    /// drop-box manifest is re-ingested after a crash.
    pub fn insert_screenshot(&self, m: &ScreenshotMeta) -> Result<bool> {
        let rows = self.conn.execute(
            "INSERT OR IGNORE INTO screenshots
               (screenshot_id, device_id, timestamp_utc, file_path, file_size, sha256,
                encryption_version, monitor_id, created_at, sync_status)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                m.screenshot_id, m.device_id, m.timestamp_utc, m.file_path, m.file_size,
                m.sha256, m.encryption_version, m.monitor_id, m.created_at, m.sync_status.as_str(),
            ],
        )?;
        Ok(rows == 1)
    }

    /// Does an activity event with this id already exist? Used for idempotent drop-box
    /// ingestion so a re-processed manifest never duplicates a chained event.
    pub fn activity_exists(&self, event_id: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(1) FROM activity_events WHERE event_id = ?1",
            params![event_id],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Screenshot count, for diagnostics/data-validation (spec §32, §41).
    pub fn screenshot_count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(1) FROM screenshots", [], |r| r.get(0))?)
    }

    /// Recent activity rows (newest first) for the admin timeline (spec §33), with an
    /// optional UTC timestamp range `[from, to)` for date-wise filtering.
    pub fn recent_activity(&self, limit: u32, from: Option<&str>, to: Option<&str>) -> Result<Vec<ActivityRow>> {
        self.activity_query(None, limit, from, to)
    }

    /// Recent browser-activity rows (BROWSER_ACTIVITY), with the same optional range.
    pub fn recent_browser(&self, limit: u32, from: Option<&str>, to: Option<&str>) -> Result<Vec<ActivityRow>> {
        self.activity_query(Some("BROWSER_ACTIVITY"), limit, from, to)
    }

    /// Shared activity reader: optional exact event-type filter + optional `[from, to)` UTC
    /// range. Timestamps sort lexicographically = chronologically (RFC-3339 Z).
    fn activity_query(
        &self,
        event_type: Option<&str>,
        limit: u32,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Result<Vec<ActivityRow>> {
        use rusqlite::types::Value;
        let mut sql = String::from(
            "SELECT event_id, event_type, timestamp_utc, application_name, window_title, metadata_json
             FROM activity_events WHERE 1=1",
        );
        let mut args: Vec<Value> = Vec::new();
        if let Some(t) = event_type {
            sql.push_str(" AND event_type = ?");
            args.push(Value::Text(t.to_string()));
        }
        if let Some(f) = from {
            sql.push_str(" AND timestamp_utc >= ?");
            args.push(Value::Text(f.to_string()));
        }
        if let Some(t) = to {
            sql.push_str(" AND timestamp_utc < ?");
            args.push(Value::Text(t.to_string()));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        args.push(Value::Integer(limit as i64));

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok(ActivityRow {
                event_id: r.get(0)?,
                event_type: r.get(1)?,
                timestamp_utc: r.get(2)?,
                application_name: r.get(3)?,
                window_title: r.get(4)?,
                metadata_json: r.get(5)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Screenshot metadata list (newest first) for the admin gallery (spec §33).
    pub fn list_screenshots(&self, limit: u32) -> Result<Vec<ScreenshotMeta>> {
        self.list_screenshots_range(limit, None, None)
    }

    /// Screenshots newest-first, optionally bounded to `[from, to)` (RFC-3339 strings; same
    /// +05:30 format as stored timestamps, so string comparison is chronological).
    pub fn list_screenshots_range(
        &self,
        limit: u32,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Result<Vec<ScreenshotMeta>> {
        use rusqlite::types::Value;
        let mut sql = String::from(
            "SELECT screenshot_id, device_id, timestamp_utc, file_path, file_size, sha256,
                    encryption_version, monitor_id, created_at, sync_status
             FROM screenshots WHERE 1=1",
        );
        let mut params: Vec<Value> = Vec::new();
        if let Some(f) = from {
            sql.push_str(" AND timestamp_utc >= ?");
            params.push(Value::Text(f.to_string()));
        }
        if let Some(t) = to {
            sql.push_str(" AND timestamp_utc < ?");
            params.push(Value::Text(t.to_string()));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        params.push(Value::Integer(limit as i64));
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| Ok(row_to_screenshot(r)))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Fetch one screenshot's metadata by id (for authorized on-demand viewing, spec §33).
    pub fn get_screenshot(&self, screenshot_id: &str) -> Result<Option<ScreenshotMeta>> {
        let mut stmt = self.conn.prepare(
            "SELECT screenshot_id, device_id, timestamp_utc, file_path, file_size, sha256,
                    encryption_version, monitor_id, created_at, sync_status
             FROM screenshots WHERE screenshot_id = ?1",
        )?;
        let mut rows = stmt.query_map([screenshot_id], |r| Ok(row_to_screenshot(r)))?;
        Ok(rows.next().and_then(|r| r.ok()))
    }

    /// Recent audit-log rows (newest first) for the admin audit page (spec §33).
    pub fn recent_audit(&self, limit: u32) -> Result<Vec<AuditRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT action, timestamp_utc, actor, metadata_json
             FROM audit_log ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |r| {
            Ok(AuditRow {
                action: r.get(0)?,
                timestamp_utc: r.get(1)?,
                actor: r.get(2)?,
                metadata_json: r.get(3)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Usage-time by app or domain (Phase-2 B). Aggregates focus duration from the ordered
    /// event stream: each segment = time until the next focus change, capped at `idle_cap`
    /// seconds so a window left focused (e.g. overnight) does not inflate totals. `name_col`
    /// is `application_name` (apps) or `window_title` (browser domains) — a fixed column, not
    /// user input. Pure aggregation over already-collected data; no new capture.
    pub fn usage_by(
        &self,
        name_col: &str,
        event_type: &str,
        since_iso: &str,
        idle_cap_secs: i64,
    ) -> Result<Vec<UsageItem>> {
        let col = if name_col == "window_title" { "window_title" } else { "application_name" };
        let sql = format!(
            "SELECT COALESCE({col}, '(unknown)'), timestamp_utc
             FROM activity_events
             WHERE event_type = ?1 AND timestamp_utc >= ?2
             ORDER BY id ASC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows: Vec<(String, String)> = stmt
            .query_map(params![event_type, since_iso], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(aggregate_usage(&rows, idle_cap_secs))
    }

    /// Total idle seconds since `since_iso`, from the SESSION_IDLE/SESSION_ACTIVE event
    /// stream (feature #2). Each complete SESSION_IDLE → SESSION_ACTIVE pair contributes its
    /// span; if the session is still idle now (a trailing SESSION_IDLE with no following
    /// SESSION_ACTIVE), the open interval up to `now` is included. Pure read over already-
    /// collected transition events.
    pub fn idle_seconds_since(&self, since_iso: &str) -> Result<i64> {
        let mut stmt = self.conn.prepare(
            "SELECT event_type, timestamp_utc
             FROM activity_events
             WHERE event_type IN ('SESSION_IDLE','SESSION_ACTIVE') AND timestamp_utc >= ?1
             ORDER BY id ASC",
        )?;
        let rows: Vec<(String, String)> = stmt
            .query_map(params![since_iso], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(sum_idle(&rows, &now_utc_iso()))
    }

    /// Device row for the dashboard (spec §32).
    pub fn device_row(&self) -> Result<Option<DeviceRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT device_id, system_name, hostname, os_version, agent_version, last_seen_at
             FROM devices LIMIT 1",
        )?;
        let mut rows = stmt.query_map([], |r| {
            Ok(DeviceRow {
                device_id: r.get(0)?,
                system_name: r.get(1)?,
                hostname: r.get(2)?,
                os_version: r.get(3)?,
                agent_version: r.get(4)?,
                last_seen_at: r.get(5)?,
            })
        })?;
        Ok(rows.next().and_then(|r| r.ok()))
    }

    /// Activity-event count, for diagnostics/data-validation.
    pub fn activity_count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(1) FROM activity_events", [], |r| r.get(0))?)
    }

    /// Insert a browser-activity row (spec §18). Domain/URL only; no credentials/cookies.
    pub fn insert_browser_event(
        &self,
        event_id: &str,
        browser: &str,
        url_or_domain: &str,
        timestamp_utc: &str,
        duration_seconds: Option<u64>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO browser_events
               (event_id, device_id, browser, url_or_domain, timestamp_utc, duration_seconds,
                created_at, sync_status)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                event_id, self.device_id, browser, url_or_domain, timestamp_utc,
                duration_seconds, now_utc_iso(), SyncStatus::LocalOnly.as_str(),
            ],
        )?;
        Ok(())
    }

    /// Insert a non-chained system/lifecycle row (spec §14). No hash chain here.
    pub fn insert_system_event(
        &self,
        event_id: &str,
        event_type: &str,
        metadata_json: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO system_events
               (event_id, device_id, event_type, timestamp_utc, metadata_json, created_at)
             VALUES (?1,?2,?3,?4,?5,?4)",
            params![event_id, self.device_id, event_type, now_utc_iso(), metadata_json],
        )?;
        Ok(())
    }

    /// Latest activity-event timestamp, for the health snapshot (spec §26).
    pub fn last_activity_time(&self) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT MAX(timestamp_utc) FROM activity_events", [], |r| r.get(0))
            .ok()
            .flatten())
    }

    /// Latest screenshot timestamp, for the health snapshot (spec §26).
    pub fn last_screenshot_time(&self) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT MAX(timestamp_utc) FROM screenshots", [], |r| r.get(0))
            .ok()
            .flatten())
    }

    /// Retention prune (spec §17, §25). Prunes the **non-chained** tables only —
    /// `screenshots`, `browser_events`, `system_events`. `activity_events` is the
    /// tamper-evident hash chain and is intentionally NOT pruned in Phase 1: deleting a
    /// chained row would (correctly) fail integrity verification, and Phase-1 data is all
    /// `LOCAL_ONLY` anyway. Un-synced rows are protected unless `delete_unsynced` is set,
    /// so with the default policy this deletes nothing (§17 "don't delete data we need").
    /// Returns per-table counts; caller writes the DATA_RETENTION_DELETE audit entry.
    pub fn prune_retention(
        &self,
        screenshot_days: u32,
        event_days: u32,
        delete_unsynced: bool,
    ) -> Result<RetentionOutcome> {
        // Only SYNCED rows are deletable unless policy explicitly permits un-synced deletes.
        let sync_ok = if delete_unsynced { "1=1" } else { "sync_status = 'SYNCED'" };
        let ss_cut = iso_days_ago(screenshot_days);
        let ev_cut = iso_days_ago(event_days);

        // Screenshots: collect file paths, delete rows, then unlink files.
        let paths: Vec<String> = {
            let sql = format!(
                "SELECT file_path FROM screenshots WHERE timestamp_utc < ?1 AND ({sync_ok})"
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let rows = stmt.query_map([&ss_cut], |r| r.get::<_, String>(0))?;
            rows.filter_map(|r| r.ok()).collect()
        };
        let screenshots_deleted = self.conn.execute(
            &format!("DELETE FROM screenshots WHERE timestamp_utc < ?1 AND ({sync_ok})"),
            [&ss_cut],
        )?;
        for p in &paths {
            if let Err(e) = std::fs::remove_file(p) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(path = %p, error = %e, "retention: failed to unlink screenshot");
                }
            }
        }

        let browser_deleted = self.conn.execute(
            &format!("DELETE FROM browser_events WHERE timestamp_utc < ?1 AND ({sync_ok})"),
            [&ev_cut],
        )?;

        // system_events has no sync_status column; only prune when un-synced deletion is
        // explicitly permitted (they are local-only lifecycle records).
        let system_deleted = if delete_unsynced {
            self.conn.execute(
                "DELETE FROM system_events WHERE timestamp_utc < ?1",
                [&ev_cut],
            )?
        } else {
            0
        };

        Ok(RetentionOutcome { screenshots_deleted, browser_deleted, system_deleted })
    }

    /// Re-seal the entire activity chain: recompute `previous_event_hash` / `event_hash` for
    /// every row in insertion order so the chain is valid again after rows were deleted.
    /// This is the deliberate trade-off for allowing real deletion (feature #5): the chain
    /// stays verifiable, but it can no longer prove that *nothing* was ever removed. Returns
    /// the number of rows re-sealed. Updates `chain_head`.
    pub fn reseal_chain(&mut self) -> Result<usize> {
        let tx = self.conn.transaction()?;
        let rows: Vec<(i64, ActivityEvent)> = {
            let mut stmt = tx.prepare(
                "SELECT id, event_id, device_id, event_type, timestamp_utc, application_name,
                        process_name, window_title, metadata_json
                 FROM activity_events ORDER BY id ASC",
            )?;
            let mapped = stmt.query_map([], |r| {
                let et: String = r.get(3)?;
                let event_type = serde_json::from_value(serde_json::Value::String(et))
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e)))?;
                Ok((
                    r.get::<_, i64>(0)?,
                    ActivityEvent {
                        event_id: r.get(1)?,
                        device_id: r.get(2)?,
                        event_type,
                        timestamp_utc: r.get(4)?,
                        application_name: r.get(5)?,
                        process_name: r.get(6)?,
                        window_title: r.get(7)?,
                        metadata_json: r.get(8)?,
                    },
                ))
            })?;
            let mut v = Vec::new();
            for row in mapped {
                v.push(row?);
            }
            v
        };

        let mut prev = GENESIS_HASH.to_string();
        let mut n = 0usize;
        {
            let mut up = tx.prepare(
                "UPDATE activity_events SET event_hash = ?1, previous_event_hash = ?2 WHERE id = ?3",
            )?;
            for (id, ev) in &rows {
                let hash = ev.compute_hash(&prev);
                up.execute(params![hash, prev, id])?;
                prev = hash;
                n += 1;
            }
        }
        tx.commit()?;
        self.chain_head = prev;
        Ok(n)
    }

    /// Delete browser-activity rows per the selected mode, then re-seal the chain. `mode`:
    /// `"auto"` deletes all BROWSER_ACTIVITY older than the cutoff; `"selection"` deletes only
    /// those whose domain (window_title) matches one of `domains` (case-insensitive substring)
    /// older than the cutoff; `"none"` deletes nothing. `older_than_iso` is the cutoff (events
    /// strictly older are eligible). Manual/explicit action, so sync-status is not a guard.
    /// Returns rows deleted.
    pub fn purge_browser(
        &mut self,
        mode: &str,
        domains: &[String],
        older_than_iso: &str,
    ) -> Result<usize> {
        let deleted = match mode {
            "auto" => self.conn.execute(
                "DELETE FROM activity_events
                 WHERE event_type = 'BROWSER_ACTIVITY' AND timestamp_utc < ?1",
                params![older_than_iso],
            )?,
            "selection" => {
                let pats: Vec<&String> = domains.iter().filter(|d| !d.is_empty()).collect();
                if pats.is_empty() {
                    0
                } else {
                    // Build  (window_title LIKE %?% OR ...)  with one bound param per domain.
                    let likes = pats
                        .iter()
                        .map(|_| "window_title LIKE '%'||?||'%'")
                        .collect::<Vec<_>>()
                        .join(" OR ");
                    let sql = format!(
                        "DELETE FROM activity_events
                         WHERE event_type = 'BROWSER_ACTIVITY' AND timestamp_utc < ? AND ({likes})"
                    );
                    use rusqlite::types::Value;
                    let mut params_vec: Vec<Value> = vec![Value::Text(older_than_iso.to_string())];
                    for d in &pats {
                        params_vec.push(Value::Text((*d).clone()));
                    }
                    self.conn.execute(&sql, rusqlite::params_from_iter(params_vec))?
                }
            }
            _ => 0, // "none" or unknown
        };
        if deleted > 0 {
            self.reseal_chain()?;
        }
        Ok(deleted)
    }

    /// Screenshots for cleanup, oldest first, as `(id, file_path)`. If `before_iso` is set,
    /// only those strictly older are returned (age gate).
    pub fn screenshots_for_cleanup(&self, before_iso: Option<&str>) -> Result<Vec<(String, String)>> {
        let (sql, has_cut) = match before_iso {
            Some(_) => (
                "SELECT screenshot_id, file_path FROM screenshots WHERE timestamp_utc < ?1 ORDER BY timestamp_utc ASC",
                true,
            ),
            None => ("SELECT screenshot_id, file_path FROM screenshots ORDER BY timestamp_utc ASC", false),
        };
        let mut stmt = self.conn.prepare(sql)?;
        let map = |r: &rusqlite::Row| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?));
        let rows: Vec<(String, String)> = if has_cut {
            stmt.query_map(params![before_iso.unwrap()], map)?.filter_map(|r| r.ok()).collect()
        } else {
            stmt.query_map([], map)?.filter_map(|r| r.ok()).collect()
        };
        Ok(rows)
    }

    /// Delete screenshot rows by id (caller unlinks the files). Returns rows deleted.
    /// Screenshots are not part of the integrity chain, so no re-seal is needed.
    pub fn delete_screenshots_by_ids(&self, ids: &[String]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut n = 0;
        let tx_ids = ids.to_vec();
        for id in &tx_ids {
            n += self.conn.execute("DELETE FROM screenshots WHERE screenshot_id = ?1", params![id])?;
        }
        Ok(n)
    }

    /// The most recent lifecycle event type (startup/shutdown). Used at boot to tell whether
    /// the previous run ended cleanly (`AGENT_SHUTDOWN`/`SYSTEM_SHUTDOWN`) or was killed
    /// (last lifecycle event is `AGENT_STARTUP` with no matching shutdown ⇒ tamper/forced stop).
    pub fn last_lifecycle_event(&self) -> Result<Option<String>> {
        let v: Option<String> = self
            .conn
            .query_row(
                "SELECT event_type FROM activity_events
                 WHERE event_type IN ('AGENT_STARTUP','AGENT_SHUTDOWN','SYSTEM_SHUTDOWN')
                 ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        Ok(v)
    }

    /// Events not yet pushed to the central server (Phase D), oldest first, up to `limit`.
    /// Returns the wire fields including the chain hashes so the server can re-verify.
    pub fn unsynced_events(&self, limit: u32) -> Result<Vec<SyncEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id, event_type, timestamp_utc, application_name, window_title,
                    metadata_json, event_hash, previous_event_hash
             FROM activity_events
             WHERE sync_status = 'LOCAL_ONLY'
             ORDER BY id ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |r| {
            Ok(SyncEvent {
                event_id: r.get(0)?,
                event_type: r.get(1)?,
                timestamp_utc: r.get(2)?,
                application_name: r.get(3)?,
                window_title: r.get(4)?,
                metadata_json: r.get(5)?,
                event_hash: r.get(6)?,
                previous_event_hash: r.get(7)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Screenshots not yet uploaded to the central server (oldest first).
    pub fn unsynced_screenshots(&self, limit: u32) -> Result<Vec<ScreenshotMeta>> {
        let mut stmt = self.conn.prepare(
            "SELECT screenshot_id, device_id, timestamp_utc, file_path, file_size, sha256,
                    encryption_version, monitor_id, created_at, sync_status
             FROM screenshots WHERE sync_status = 'LOCAL_ONLY'
             ORDER BY id ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |r| Ok(row_to_screenshot(r)))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Mark the given screenshots as SYNCED after a successful upload.
    pub fn mark_screenshots_synced(&self, ids: &[String]) -> Result<usize> {
        let mut n = 0;
        for id in ids {
            n += self.conn.execute(
                "UPDATE screenshots SET sync_status = 'SYNCED' WHERE screenshot_id = ?1",
                params![id],
            )?;
        }
        Ok(n)
    }

    /// Mark the given events as SYNCED after a successful server upload.
    pub fn mark_events_synced(&self, event_ids: &[String]) -> Result<usize> {
        let mut n = 0;
        for id in event_ids {
            n += self.conn.execute(
                "UPDATE activity_events SET sync_status = 'SYNCED' WHERE event_id = ?1",
                params![id],
            )?;
        }
        Ok(n)
    }

    /// Graceful-shutdown checkpoint (spec §6, §28). wal_checkpoint returns a status row,
    /// so query it rather than pragma_update.
    pub fn checkpoint_truncate(&self) -> Result<()> {
        self.conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .map_err(CoreError::from)
    }

    pub fn chain_head(&self) -> &str {
        &self.chain_head
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sns_shared::events::EventType;

    fn ev(id: &str, app: &str) -> ActivityEvent {
        ActivityEvent {
            event_id: id.into(),
            device_id: "dev_T".into(),
            event_type: EventType::ApplicationStarted,
            timestamp_utc: now_utc_iso(),
            application_name: Some(app.into()),
            process_name: Some(app.into()),
            window_title: None,
            metadata_json: None,
        }
    }

    #[test]
    fn usage_aggregation_caps_idle_and_sums_per_name() {
        let rows = vec![
            ("chrome.exe".to_string(), "2026-08-11T10:00:00Z".to_string()),
            ("code.exe".to_string(),   "2026-08-11T10:05:00Z".to_string()), // chrome 300s
            ("chrome.exe".to_string(), "2026-08-11T10:06:00Z".to_string()), // code 60s
            ("chrome.exe".to_string(), "2026-08-12T10:06:00Z".to_string()), // chrome 24h -> capped 900
        ];
        let out = super::aggregate_usage(&rows, 900);
        let chrome = out.iter().find(|u| u.name == "chrome.exe").unwrap();
        // 300 (first) + 900 (capped overnight) = 1200, across 2 sessions.
        assert_eq!(chrome.seconds, 1200);
        assert_eq!(chrome.sessions, 2);
        let code = out.iter().find(|u| u.name == "code.exe").unwrap();
        assert_eq!(code.seconds, 60);
        // sorted desc by seconds
        assert_eq!(out[0].name, "chrome.exe");
    }

    #[test]
    fn idle_sum_closes_pairs_and_trailing() {
        // Two complete idle intervals (600s + 300s) and a trailing open idle closed at `now`.
        let rows = vec![
            ("SESSION_IDLE".to_string(),   "2026-08-11T10:00:00Z".to_string()),
            ("SESSION_ACTIVE".to_string(), "2026-08-11T10:10:00Z".to_string()), // 600s
            ("SESSION_IDLE".to_string(),   "2026-08-11T11:00:00Z".to_string()),
            ("SESSION_ACTIVE".to_string(), "2026-08-11T11:05:00Z".to_string()), // 300s
            ("SESSION_IDLE".to_string(),   "2026-08-11T12:00:00Z".to_string()), // open
        ];
        // now = 12:02:00Z closes the trailing idle at 120s.
        let total = super::sum_idle(&rows, "2026-08-11T12:02:00Z");
        assert_eq!(total, 600 + 300 + 120);
    }

    #[test]
    fn unsynced_queue_and_mark_synced() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("activity.db");
        let mut s = Storage::open(&db, "dev_T", "NORMAL").unwrap();
        s.upsert_device("SNS-PC-001", Some("HOST"), Some("Win"), "1.0.0").unwrap();
        s.insert_activity_event(&ev("evt_1", "chrome.exe")).unwrap();
        s.insert_activity_event(&ev("evt_2", "code.exe")).unwrap();

        let pending = s.unsynced_events(100).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].event_id, "evt_1"); // oldest first

        let n = s.mark_events_synced(&["evt_1".into(), "evt_2".into()]).unwrap();
        assert_eq!(n, 2);
        assert!(s.unsynced_events(100).unwrap().is_empty());
    }

    #[test]
    fn insert_and_verify_chain() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("activity.db");
        let mut s = Storage::open(&db, "dev_T", "NORMAL").unwrap();
        s.upsert_device("SNS-PC-001", Some("HOST"), Some("Win"), "1.0.0").unwrap();
        s.insert_activity_event(&ev("evt_1", "chrome.exe")).unwrap();
        s.insert_activity_event(&ev("evt_2", "code.exe")).unwrap();
        s.insert_activity_event(&ev("evt_3", "explorer.exe")).unwrap();

        assert!(s.integrity_check().unwrap());
        let report = s.verify_integrity().unwrap();
        assert!(report.is_pass());
        assert_eq!(report.events_checked, 3);
    }

    fn browser_ev(id: &str, domain: &str, ts: &str) -> ActivityEvent {
        ActivityEvent {
            event_id: id.into(),
            device_id: "dev_T".into(),
            event_type: EventType::BrowserActivity,
            timestamp_utc: ts.into(),
            application_name: Some("chrome".into()),
            process_name: Some("chrome".into()),
            window_title: Some(domain.into()),
            metadata_json: Some("{\"browser\":\"chrome\"}".into()),
        }
    }

    #[test]
    fn purge_browser_selection_reseals_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("activity.db");
        let mut s = Storage::open(&db, "dev_T", "NORMAL").unwrap();
        s.upsert_device("SNS-PC-001", Some("HOST"), Some("Win"), "1.0.0").unwrap();
        s.insert_activity_event(&ev("evt_1", "chrome.exe")).unwrap();
        s.insert_activity_event(&browser_ev("b_g", "google.com", "2026-08-11T10:00:00+05:30")).unwrap();
        s.insert_activity_event(&browser_ev("b_y", "youtube.com", "2026-08-11T10:01:00+05:30")).unwrap();
        s.insert_activity_event(&browser_ev("b_k", "github.com", "2026-08-11T10:02:00+05:30")).unwrap();

        // Remove google + youtube older than a future cutoff; keep github.
        let n = s
            .purge_browser("selection", &["google.com".into(), "youtube.com".into()], "2026-12-01T00:00:00+05:30")
            .unwrap();
        assert_eq!(n, 2);

        // Chain still verifies after the re-seal.
        let report = s.verify_integrity().unwrap();
        assert!(report.is_pass());
        assert_eq!(report.events_checked, 2); // chrome.exe + github

        // github survived, google/youtube gone.
        let rows = s.recent_browser(100, None, None).unwrap();
        assert!(rows.iter().any(|r| r.window_title.as_deref() == Some("github.com")));
        assert!(!rows.iter().any(|r| r.window_title.as_deref() == Some("google.com")));
    }

    fn screenshot_meta(dir: &std::path::Path, ts: &str, sync: SyncStatus) -> (ScreenshotMeta, std::path::PathBuf) {
        let id = format!("scr_{}", ts.replace([':', '-'], ""));
        let path = dir.join(format!("{id}.enc"));
        std::fs::write(&path, b"ciphertext").unwrap();
        (
            ScreenshotMeta {
                screenshot_id: id,
                device_id: "dev_T".into(),
                timestamp_utc: ts.into(),
                file_path: path.to_string_lossy().into_owned(),
                file_size: 10,
                sha256: "x".into(),
                encryption_version: 1,
                monitor_id: Some(0),
                created_at: ts.into(),
                sync_status: sync,
            },
            path,
        )
    }

    #[test]
    fn retention_protects_unsynced_but_prunes_when_permitted() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("activity.db");
        let s = Storage::open(&db, "dev_T", "NORMAL").unwrap();
        s.upsert_device("SNS-PC-001", None, None, "1.0.0").unwrap();

        // Ancient LOCAL_ONLY screenshot: must survive default retention (spec §17, §25).
        let (m, path) = screenshot_meta(dir.path(), "2000-01-01T00:00:00Z", SyncStatus::LocalOnly);
        s.insert_screenshot(&m).unwrap();

        let out = s.prune_retention(7, 30, false).unwrap();
        assert_eq!(out.screenshots_deleted, 0, "un-synced data must not be deleted by default");
        assert!(path.exists());

        // With delete_unsynced=true the same old row is pruned and its file removed.
        let out2 = s.prune_retention(7, 30, true).unwrap();
        assert_eq!(out2.screenshots_deleted, 1);
        assert!(!path.exists());
    }

    #[test]
    fn retention_never_touches_activity_chain() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("activity.db");
        let mut s = Storage::open(&db, "dev_T", "NORMAL").unwrap();
        s.upsert_device("SNS-PC-001", None, None, "1.0.0").unwrap();
        s.insert_activity_event(&ev("evt_1", "a")).unwrap();
        s.insert_activity_event(&ev("evt_2", "b")).unwrap();

        // Even aggressive retention leaves the chained activity table intact so integrity
        // verification still passes (spec §22, §24).
        s.prune_retention(0, 0, true).unwrap();
        assert!(s.verify_integrity().unwrap().is_pass());
        assert_eq!(s.load_activity_chain().unwrap().len(), 2);
    }

    #[test]
    fn head_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("activity.db");
        let head_after_two;
        {
            let mut s = Storage::open(&db, "dev_T", "NORMAL").unwrap();
            // Device row must exist first: activity_events.device_id FKs devices (as in boot()).
            s.upsert_device("SNS-PC-001", None, None, "1.0.0").unwrap();
            s.insert_activity_event(&ev("evt_1", "a")).unwrap();
            head_after_two = s.insert_activity_event(&ev("evt_2", "b")).unwrap();
        }
        // Reopen: the cached head must be reconstructed from disk so the chain continues.
        let s2 = Storage::open(&db, "dev_T", "NORMAL").unwrap();
        assert_eq!(s2.chain_head(), head_after_two);
    }
}
