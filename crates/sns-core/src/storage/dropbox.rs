//! Session-bridge drop box (spec §5, §19 + session-0 isolation).
//!
//! Interactive collection (screenshots, app focus, browser) must run in the user's session,
//! not the session-0 service. The user-session agent (`sns-useragent`) captures and writes
//! records here as JSON manifests; the service ingests them into SQLite on its maintenance
//! tick and deletes the manifest. This keeps a single DB writer (the service) while letting
//! capture happen where the desktop actually is. It is NOT a covert channel — it is a plain,
//! ACL-protected directory under the agent's own ProgramData tree.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sns_shared::events::ActivityEvent;
use sns_shared::models::ScreenshotMeta;

use crate::error::Result;

/// One dropped record. Screenshots reference an already-written encrypted file (the
/// user-session agent wrote it via `persist_capture`); activity events are self-contained.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DropRecord {
    Screenshot(ScreenshotMeta),
    Activity(ActivityEvent),
}

/// `runtime/incoming/` under the data root.
pub fn incoming_dir(data_root: &Path) -> PathBuf {
    data_root.join("runtime").join("incoming")
}

/// Atomically write a record: temp file then rename, so the ingester never reads a partial
/// manifest. `stem` should be unique (e.g. the screenshot/event id).
pub fn write_record(data_root: &Path, stem: &str, rec: &DropRecord) -> Result<()> {
    let dir = incoming_dir(data_root);
    std::fs::create_dir_all(&dir)?;
    let tmp = dir.join(format!("{stem}.json.tmp"));
    let final_path = dir.join(format!("{stem}.json"));
    std::fs::write(&tmp, serde_json::to_vec(rec)?)?;
    std::fs::rename(&tmp, &final_path)?;
    Ok(())
}

/// List complete manifest files (`*.json`, ignoring `*.json.tmp`) oldest-first-ish.
pub fn list_manifests(data_root: &Path) -> Vec<PathBuf> {
    let dir = incoming_dir(data_root);
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().map(|x| x == "json").unwrap_or(false) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Parse a manifest file into a record.
pub fn read_record(path: &Path) -> Result<DropRecord> {
    let raw = std::fs::read(path)?;
    Ok(serde_json::from_slice(&raw)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sns_shared::sync::SyncStatus;

    #[test]
    fn write_list_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let meta = ScreenshotMeta {
            screenshot_id: "scr_1".into(),
            device_id: "dev_T".into(),
            timestamp_utc: "2026-08-11T10:00:00Z".into(),
            file_path: "x.enc".into(),
            file_size: 1,
            sha256: "h".into(),
            encryption_version: 1,
            monitor_id: Some(0),
            created_at: "2026-08-11T10:00:00Z".into(),
            sync_status: SyncStatus::LocalOnly,
        };
        write_record(dir.path(), "scr_1", &DropRecord::Screenshot(meta)).unwrap();

        let manifests = list_manifests(dir.path());
        assert_eq!(manifests.len(), 1);
        // .tmp files are never listed.
        assert!(manifests[0].extension().unwrap() == "json");
        match read_record(&manifests[0]).unwrap() {
            DropRecord::Screenshot(m) => assert_eq!(m.screenshot_id, "scr_1"),
            _ => panic!("wrong kind"),
        }
    }
}
