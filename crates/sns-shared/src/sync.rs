//! Sync-status state machine (spec §24) and Phase-2 interfaces (spec §47).
//!
//! Phase 1 writes only `LOCAL_ONLY`. The traits below are defined now so Phase-1 code
//! and schema are drop-in ready for Phase-2 sync — no implementation here.

use serde::{Deserialize, Serialize};

/// Per-record sync state. Stored as the exact string in the DB `sync_status` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SyncStatus {
    LocalOnly,
    Queued,
    Syncing,
    Synced,
    SyncFailed,
}

impl SyncStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SyncStatus::LocalOnly => "LOCAL_ONLY",
            SyncStatus::Queued => "QUEUED",
            SyncStatus::Syncing => "SYNCING",
            SyncStatus::Synced => "SYNCED",
            SyncStatus::SyncFailed => "SYNC_FAILED",
        }
    }

    /// Legal transitions (spec §24). Enforced by Phase-2 code; documented here.
    pub fn can_transition_to(self, next: SyncStatus) -> bool {
        use SyncStatus::*;
        matches!(
            (self, next),
            (LocalOnly, Queued)
                | (Queued, Syncing)
                | (Syncing, Synced)
                | (Syncing, SyncFailed)
                | (SyncFailed, Queued)
        )
    }
}

// ---------------------------------------------------------------------------
// Phase-2 interfaces (traits only; NO network implementation in Phase 1). §47
// ---------------------------------------------------------------------------

/// A batch reference the queue hands to an uploader.
#[derive(Debug, Clone)]
pub struct SyncBatch {
    pub event_ids: Vec<String>,
}

pub trait SyncQueue {
    fn enqueue_local_only(&self) -> anyhow::Result<usize>;
    fn next_batch(&self, max: usize) -> anyhow::Result<Option<SyncBatch>>;
    fn mark(&self, batch: &SyncBatch, status: SyncStatus) -> anyhow::Result<()>;
}

pub trait EventUploader {
    fn upload_events(&self, batch: &SyncBatch) -> anyhow::Result<()>;
}

pub trait ScreenshotUploader {
    fn upload_screenshot(&self, screenshot_id: &str) -> anyhow::Result<()>;
}

pub trait DeviceRegistration {
    fn register(&self, device_id: &str) -> anyhow::Result<()>;
}

pub trait SyncRetry {
    fn backoff_delay(&self, attempt: u32) -> std::time::Duration;
}

pub trait ServerHealth {
    fn is_reachable(&self) -> bool;
}

/// Orchestrates one sync cycle. Phase-2 implements; Phase-1 has no impl.
pub trait SyncService {
    fn run_cycle(&self) -> anyhow::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions() {
        assert!(SyncStatus::LocalOnly.can_transition_to(SyncStatus::Queued));
        assert!(SyncStatus::Syncing.can_transition_to(SyncStatus::Synced));
        assert!(SyncStatus::SyncFailed.can_transition_to(SyncStatus::Queued));
        assert!(!SyncStatus::LocalOnly.can_transition_to(SyncStatus::Synced));
        assert!(!SyncStatus::Synced.can_transition_to(SyncStatus::LocalOnly));
    }
}
