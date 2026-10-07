//! Configuration load + validation (spec §14, §40, and CONFIGURATION.md).
//! Two files: `agent.json` (identity + runtime) and `policy.json` (collection policy).
//! Invalid config is rejected at boot so collectors never run on bad settings.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

// ------------------------------- agent.json --------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub schema_version: u32,
    pub device_id: String,   // immutable (spec §9)
    pub system_name: String, // admin-set, mutable (spec §10)
    pub agent_version: String,
    pub admin: AdminConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    pub bind: String, // loopback by default (spec §31)
    pub port: u16,
    pub password_hash: String, // Argon2id PHC; never plaintext
    pub session_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub max_file_mb: u64,
    pub max_files: u32,
}

impl AgentConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read(path)?;
        let cfg: AgentConfig = serde_json::from_slice(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(CoreError::Config(format!(
                "unsupported agent schema_version {}",
                self.schema_version
            )));
        }
        if !self.device_id.starts_with("dev_") {
            return Err(CoreError::Config("device_id must start with dev_".into()));
        }
        if self.system_name.trim().is_empty() {
            return Err(CoreError::Config("system_name must not be empty".into()));
        }
        if self.admin.password_hash.is_empty() {
            return Err(CoreError::Config("admin password not set".into()));
        }
        // Default posture: admin bound to loopback only (spec §31). Non-loopback is a
        // deliberate override that must be explicit; we reject it by default here.
        if !is_loopback(&self.admin.bind) {
            return Err(CoreError::Config(
                "admin.bind must be a loopback address by default".into(),
            ));
        }
        Ok(())
    }
}

fn is_loopback(addr: &str) -> bool {
    addr == "127.0.0.1" || addr == "::1" || addr.eq_ignore_ascii_case("localhost")
}

// ------------------------------- policy.json -------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub schema_version: u32,
    pub screenshot: ScreenshotPolicy,
    pub application: ApplicationPolicy,
    pub browser: BrowserPolicy,
    pub usb: TogglePolicy,
    pub storage: StoragePolicy,
    pub retention: RetentionPolicy,
    pub durability: DurabilityPolicy,
    /// Idle/active tracking. `#[serde(default)]` so policy.json files written before this
    /// field was added still load (back-compat).
    #[serde(default = "default_idle")]
    pub idle: IdlePolicy,
    /// Exfil-adjacent monitoring (USB file copies, print jobs). Metadata only.
    #[serde(default)]
    pub exfil: ExfilPolicy,
    /// Central-server sync (Phase D). Off unless a server is configured.
    #[serde(default)]
    pub sync: SyncPolicy,
}

/// Central-server sync configuration. The agent registers once with `enroll_token`, stores the
/// returned device token back into `device_token`, then uploads un-synced events on a cadence.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncPolicy {
    #[serde(default)]
    pub enabled: bool,
    /// Base URL of the central server, e.g. `https://sns.example.com`.
    #[serde(default)]
    pub server_url: String,
    /// One-time org enroll token (used only until a device token is obtained).
    #[serde(default)]
    pub enroll_token: String,
    /// Device bearer token, filled in by the agent after a successful registration.
    #[serde(default)]
    pub device_token: String,
}

/// Exfil-adjacent monitoring. Watches for files written to removable drives and documents
/// sent to printers. Records **metadata only** (name, size, pages, destination) — never file
/// contents (spec §16).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExfilPolicy {
    pub usb_file_watch: bool,
    pub print_watch: bool,
}

impl Default for ExfilPolicy {
    fn default() -> Self {
        ExfilPolicy { usb_file_watch: true, print_watch: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlePolicy {
    pub enabled: bool,
    /// Seconds of no keyboard/mouse input before the session is considered idle.
    pub threshold_seconds: u64,
}

fn default_idle() -> IdlePolicy {
    IdlePolicy { enabled: true, threshold_seconds: 300 }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotPolicy {
    pub enabled: bool,
    pub interval_seconds: u64,
    pub monitors: String, // "all" | "primary"
    pub max_dimension: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationPolicy {
    pub enabled: bool,
    pub capture_window_title: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserPolicy {
    pub enabled: bool,
    pub granularity: String, // "domain" | "url"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TogglePolicy {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePolicy {
    pub max_bytes: u64,
    pub warn_pct: u8,
    pub critical_pct: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub screenshot_days: u32,
    pub event_days: u32,
    /// Never delete un-synced data unless this is true (spec §25).
    pub delete_unsynced: bool,
    /// Browser-history auto-removal. `#[serde(default)]` keeps old policy.json loadable.
    #[serde(default)]
    pub browser: BrowserRetention,
    /// Screenshot cleanup (heuristic junk-prune + age).
    #[serde(default)]
    pub screenshot_cleanup: ScreenshotCleanup,
}

/// Browser-history retention. Three modes:
///  - `none`       — keep everything (default).
///  - `auto`       — remove ALL browser events older than `days`.
///  - `selection`  — remove browser events whose domain matches `domains`, older than `days`.
/// Deletion re-seals the tamper-evident chain so integrity verification still passes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserRetention {
    pub mode: String,
    pub domains: Vec<String>,
    pub days: u32,
}

impl Default for BrowserRetention {
    fn default() -> Self {
        BrowserRetention { mode: "none".into(), domains: Vec::new(), days: 60 }
    }
}

/// Screenshot cleanup policy. `heuristic_enabled` drops lock-screen / blank / near-duplicate
/// frames; `max_age_days` removes anything older regardless of content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotCleanup {
    pub heuristic_enabled: bool,
    pub max_age_days: u32,
}

impl Default for ScreenshotCleanup {
    fn default() -> Self {
        ScreenshotCleanup { heuristic_enabled: true, max_age_days: 60 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurabilityPolicy {
    pub sqlite_synchronous: String, // "NORMAL" | "FULL"
}

impl Policy {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read(path)?;
        let p: Policy = serde_json::from_slice(&raw)?;
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(CoreError::Config("unsupported policy schema_version".into()));
        }
        if self.screenshot.enabled && self.screenshot.interval_seconds < 60 {
            return Err(CoreError::Config(
                "screenshot interval_seconds must be >= 60".into(),
            ));
        }
        if !(self.storage.warn_pct < self.storage.critical_pct
            && self.storage.critical_pct <= 100)
        {
            return Err(CoreError::Config(
                "require warn_pct < critical_pct <= 100".into(),
            ));
        }
        if self.storage.max_bytes == 0 {
            return Err(CoreError::Config("storage.max_bytes must be > 0".into()));
        }
        if self.idle.enabled && self.idle.threshold_seconds < 30 {
            return Err(CoreError::Config(
                "idle.threshold_seconds must be >= 30".into(),
            ));
        }
        Ok(())
    }

    /// Defaults from spec §19, §25.
    pub fn default_policy() -> Self {
        Policy {
            schema_version: 1,
            screenshot: ScreenshotPolicy {
                enabled: true,
                interval_seconds: 900,
                monitors: "all".into(),
                max_dimension: 1920,
            },
            application: ApplicationPolicy { enabled: true, capture_window_title: true },
            browser: BrowserPolicy { enabled: true, granularity: "domain".into() },
            usb: TogglePolicy { enabled: true },
            storage: StoragePolicy { max_bytes: 10_737_418_240, warn_pct: 80, critical_pct: 90 },
            retention: RetentionPolicy {
                screenshot_days: 7,
                event_days: 30,
                delete_unsynced: false,
                browser: BrowserRetention::default(),
                screenshot_cleanup: ScreenshotCleanup::default(),
            },
            durability: DurabilityPolicy { sqlite_synchronous: "NORMAL".into() },
            idle: default_idle(),
            exfil: ExfilPolicy::default(),
            sync: SyncPolicy::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_valid() {
        assert!(Policy::default_policy().validate().is_ok());
    }

    #[test]
    fn rejects_fast_screenshot_interval() {
        let mut p = Policy::default_policy();
        p.screenshot.interval_seconds = 5;
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_bad_thresholds() {
        let mut p = Policy::default_policy();
        p.storage.warn_pct = 95;
        p.storage.critical_pct = 90;
        assert!(p.validate().is_err());
    }

    #[test]
    fn agent_config_rejects_non_loopback_bind() {
        let cfg = AgentConfig {
            schema_version: 1,
            device_id: "dev_X".into(),
            system_name: "SNS-PC-001".into(),
            agent_version: "1.0.0".into(),
            admin: AdminConfig {
                bind: "0.0.0.0".into(),
                port: 7731,
                password_hash: "$argon2id$x".into(),
                session_ttl_seconds: 1800,
            },
            logging: LoggingConfig { level: "info".into(), max_file_mb: 20, max_files: 10 },
        };
        assert!(cfg.validate().is_err());
    }
}
