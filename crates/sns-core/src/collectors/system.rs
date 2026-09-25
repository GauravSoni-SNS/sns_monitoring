//! System/lifecycle collector (spec §5, §7, §16). Emits session, USB, and agent/system
//! lifecycle events. No auth secrets are ever captured (spec §5).
//!
//! Session + USB signals arrive from the service control handler (SESSIONCHANGE) and a
//! device-notification registration; this module turns them into events. The builders are
//! final and unit-tested.

use sns_shared::events::{ActivityEvent, EventType};
use sns_shared::ids::new_event_id;

use crate::clock::now_utc_iso;

/// Build a lifecycle/system event with optional metadata (no secrets).
pub fn lifecycle_event(
    device_id: &str,
    event_type: EventType,
    metadata_json: Option<String>,
) -> ActivityEvent {
    ActivityEvent {
        event_id: new_event_id(),
        device_id: device_id.to_string(),
        event_type,
        timestamp_utc: now_utc_iso(),
        application_name: None,
        process_name: None,
        window_title: None,
        metadata_json,
    }
}

/// AGENT_SHUTDOWN carries a technical reason only (spec §7).
#[derive(Debug, Clone, Copy)]
pub enum ShutdownReason {
    ServiceStop,
    WindowsShutdown,
    Preshutdown,
    Uninstall,
}

impl ShutdownReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShutdownReason::ServiceStop => "SERVICE_STOP",
            ShutdownReason::WindowsShutdown => "WINDOWS_SHUTDOWN",
            ShutdownReason::Preshutdown => "PRESHUTDOWN",
            ShutdownReason::Uninstall => "UNINSTALL",
        }
    }
}

pub fn agent_shutdown_event(device_id: &str, agent_version: &str, reason: ShutdownReason) -> ActivityEvent {
    let meta = serde_json::json!({
        "reason": reason.as_str(),
        "agent_version": agent_version,
    })
    .to_string();
    lifecycle_event(device_id, EventType::AgentShutdown, Some(meta))
}

pub fn session_started(device_id: &str, session_id: &str, user: &str) -> ActivityEvent {
    let meta = serde_json::json!({ "session_id": session_id, "user": user }).to_string();
    lifecycle_event(device_id, EventType::UserSessionStarted, Some(meta))
}

pub fn session_ended(device_id: &str, session_id: &str, user: &str) -> ActivityEvent {
    let meta = serde_json::json!({ "session_id": session_id, "user": user }).to_string();
    lifecycle_event(device_id, EventType::UserSessionEnded, Some(meta))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_event_records_reason_not_data() {
        let ev = agent_shutdown_event("dev_T", "1.0.0", ShutdownReason::WindowsShutdown);
        assert_eq!(ev.event_type, EventType::AgentShutdown);
        let meta = ev.metadata_json.unwrap();
        assert!(meta.contains("WINDOWS_SHUTDOWN"));
        // No monitoring data leaked into the shutdown event (spec §7, §34).
        assert!(ev.window_title.is_none());
    }

    #[test]
    fn session_events_have_no_secrets() {
        let ev = session_started("dev_T", "1", "DOMAIN\\alice");
        let meta = ev.metadata_json.unwrap();
        assert!(meta.contains("session_id"));
        assert!(!meta.to_lowercase().contains("password"));
    }
}
