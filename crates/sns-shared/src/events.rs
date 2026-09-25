//! Controlled event enum (spec §16) and the tamper-evident event chain (spec §22).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Controlled event vocabulary. Only technically-appropriate events are emitted.
/// Serialized as the exact SCREAMING_SNAKE_CASE strings stored in the DB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    ApplicationStarted,
    ApplicationStopped,
    ActiveApplicationChanged,
    BrowserActivity,
    ScreenshotCreated,
    UserSessionStarted,
    UserSessionEnded,
    UsbDeviceConnected,
    UsbDeviceDisconnected,
    SystemStartup,
    SystemShutdown,
    AgentStartup,
    AgentShutdown,
    ConfigurationChanged,
    StorageWarning,
    StorageCritical,
    IntegrityFailure,
}

impl EventType {
    /// Stable wire/DB string. Kept in sync with `serde(rename_all)`.
    pub fn as_str(&self) -> &'static str {
        use EventType::*;
        match self {
            ApplicationStarted => "APPLICATION_STARTED",
            ApplicationStopped => "APPLICATION_STOPPED",
            ActiveApplicationChanged => "ACTIVE_APPLICATION_CHANGED",
            BrowserActivity => "BROWSER_ACTIVITY",
            ScreenshotCreated => "SCREENSHOT_CREATED",
            UserSessionStarted => "USER_SESSION_STARTED",
            UserSessionEnded => "USER_SESSION_ENDED",
            UsbDeviceConnected => "USB_DEVICE_CONNECTED",
            UsbDeviceDisconnected => "USB_DEVICE_DISCONNECTED",
            SystemStartup => "SYSTEM_STARTUP",
            SystemShutdown => "SYSTEM_SHUTDOWN",
            AgentStartup => "AGENT_STARTUP",
            AgentShutdown => "AGENT_SHUTDOWN",
            ConfigurationChanged => "CONFIGURATION_CHANGED",
            StorageWarning => "STORAGE_WARNING",
            StorageCritical => "STORAGE_CRITICAL",
            IntegrityFailure => "INTEGRITY_FAILURE",
        }
    }
}

/// An activity/lifecycle event, pre-persistence. `event_hash`/`previous_event_hash`
/// are filled by [`ActivityEvent::seal`] just before it enters the storage writer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub event_id: String,
    pub device_id: String,
    pub event_type: EventType,
    /// ISO-8601 UTC.
    pub timestamp_utc: String,
    pub application_name: Option<String>,
    pub process_name: Option<String>,
    pub window_title: Option<String>,
    /// Arbitrary structured metadata; never contains secrets/keystrokes/passwords.
    pub metadata_json: Option<String>,
}

impl ActivityEvent {
    /// Deterministic canonical byte string over the immutable fields. Field order and
    /// separators are fixed so the same logical event always hashes identically across
    /// platforms and rebuilds. `\x1f` (unit separator) delimits fields.
    pub fn canonical(&self) -> String {
        fn f(o: &Option<String>) -> &str {
            o.as_deref().unwrap_or("")
        }
        [
            self.event_id.as_str(),
            self.device_id.as_str(),
            self.event_type.as_str(),
            self.timestamp_utc.as_str(),
            f(&self.application_name),
            f(&self.process_name),
            f(&self.window_title),
            f(&self.metadata_json),
        ]
        .join("\u{1f}")
    }

    /// `SHA-256(canonical || previous_hash)` (spec §22). Hex, lowercase.
    pub fn compute_hash(&self, previous_hash: &str) -> String {
        let mut h = Sha256::new();
        h.update(self.canonical().as_bytes());
        h.update(previous_hash.as_bytes());
        hex::encode(h.finalize())
    }

    /// Produce the persisted (event_hash, previous_event_hash) pair.
    pub fn seal(&self, previous_hash: &str) -> SealedHashes {
        SealedHashes {
            previous_event_hash: previous_hash.to_string(),
            event_hash: self.compute_hash(previous_hash),
        }
    }
}

/// The chain fields written alongside an [`ActivityEvent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedHashes {
    pub event_hash: String,
    pub previous_event_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GENESIS_HASH;

    fn ev(id: &str) -> ActivityEvent {
        ActivityEvent {
            event_id: id.into(),
            device_id: "dev_TEST".into(),
            event_type: EventType::ApplicationStarted,
            timestamp_utc: "2026-08-11T10:00:00Z".into(),
            application_name: Some("chrome.exe".into()),
            process_name: Some("chrome.exe".into()),
            window_title: None,
            metadata_json: None,
        }
    }

    #[test]
    fn hash_is_deterministic() {
        let e = ev("evt_1");
        assert_eq!(e.compute_hash(GENESIS_HASH), e.compute_hash(GENESIS_HASH));
    }

    #[test]
    fn chain_links_and_detects_tamper() {
        let a = ev("evt_1");
        let sa = a.seal(GENESIS_HASH);
        let b = ev("evt_2");
        let sb = b.seal(&sa.event_hash);
        // B's previous == A's hash.
        assert_eq!(sb.previous_event_hash, sa.event_hash);
        // Tamper A after the fact: recomputed hash no longer matches stored chain.
        let mut a_tampered = a.clone();
        a_tampered.application_name = Some("evil.exe".into());
        assert_ne!(a_tampered.compute_hash(GENESIS_HASH), sa.event_hash);
    }

    #[test]
    fn event_type_string_matches_serde() {
        let s = serde_json::to_string(&EventType::AgentShutdown).unwrap();
        assert_eq!(s, "\"AGENT_SHUTDOWN\"");
        assert_eq!(EventType::AgentShutdown.as_str(), "AGENT_SHUTDOWN");
    }
}
