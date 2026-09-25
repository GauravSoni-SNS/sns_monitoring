//! Plain data models shared across crates.

use serde::{Deserialize, Serialize};

/// The single managed device (spec §9–11, §14).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub device_id: String,   // immutable
    pub system_name: String, // admin-set, mutable
    pub hostname: Option<String>,
    pub current_ip: Option<String>, // supplementary only, never an identifier (spec §11)
    pub os_version: Option<String>,
    pub agent_version: String,
    pub created_at: String,
    pub last_seen_at: Option<String>,
}

/// Screenshot metadata row (blob lives encrypted on disk; spec §14, §19, §20).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotMeta {
    pub screenshot_id: String,
    pub device_id: String,
    pub timestamp_utc: String,
    pub file_path: String,
    pub file_size: u64,
    pub sha256: String,
    pub encryption_version: u32,
    pub monitor_id: Option<u32>,
    pub created_at: String,
    pub sync_status: crate::sync::SyncStatus,
}

/// Browser activity row (domain-granularity by default; no credentials/cookies; spec §18).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserEvent {
    pub event_id: String,
    pub device_id: String,
    pub browser: String,
    pub url_or_domain: Option<String>,
    pub timestamp_utc: String,
    pub duration_seconds: Option<u64>,
    pub sync_status: crate::sync::SyncStatus,
}
