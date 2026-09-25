//! SQLite storage (spec §13, §14). WAL, transactional, single-writer. Owns the integrity
//! chain head so activity events are sealed and inserted atomically.

use std::path::Path;

use rusqlite::{params, Connection, OpenFlags};
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
        let mut stmt = self.conn.prepare(
            "SELECT screenshot_id, device_id, timestamp_utc, file_path, file_size, sha256,
                    encryption_version, monitor_id, created_at, sync_status
             FROM screenshots ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |r| Ok(row_to_screenshot(r)))?;
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
