//! Agent health snapshot (spec §26). Serialized for `sns-agentctl health` and the admin
//! dashboard. Contains no secrets.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Running,
    Degraded,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComponentHealth {
    Healthy,
    Degraded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSnapshot {
    pub agent_status: Status,
    pub database: ComponentHealth,
    pub encryption: ComponentHealth,
    pub storage_used_bytes: u64,
    pub storage_max_bytes: u64,
    pub last_event_utc: Option<String>,
    pub last_screenshot_utc: Option<String>,
    pub last_integrity_check_utc: Option<String>,
    pub last_integrity_pass: Option<bool>,
    pub agent_version: String,
    pub configuration_version: u32,
}

impl HealthSnapshot {
    /// e.g. "2.4 GB / 10 GB" for the dashboard.
    pub fn storage_human(&self) -> String {
        fn gb(b: u64) -> f64 {
            b as f64 / 1_073_741_824.0
        }
        format!("{:.1} GB / {:.0} GB", gb(self.storage_used_bytes), gb(self.storage_max_bytes))
    }
}
