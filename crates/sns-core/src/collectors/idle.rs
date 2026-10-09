//! Idle / active-session tracking.
//!
//! Measures seconds since the last keyboard/mouse input (`GetLastInputInfo`) and records a
//! `SESSION_IDLE` / `SESSION_ACTIVE` event when the user crosses the configured threshold.
//! This is a coarse presence signal only: it reads the *time* of the last input, never the
//! input itself — no keystrokes, no mouse coordinates, no clipboard (spec §17). It makes
//! usage-time honest (time away from the keyboard is not counted as active use).

use sns_shared::events::{ActivityEvent, EventType};
use sns_shared::ids::new_event_id;

use crate::clock::now_utc_iso;

/// Seconds since the last user input on this session. Returns 0 on non-Windows / failure
/// (treated as "active", the safe default — never spuriously reports idle).
#[cfg(windows)]
pub fn idle_seconds() -> u64 {
    win::idle_seconds()
}

#[cfg(not(windows))]
pub fn idle_seconds() -> u64 {
    crate::collectors::platform_unix::idle_seconds()
}

/// Pure idle/active state machine. Fed the current idle-seconds each tick; emits a state
/// change exactly once when the user crosses the threshold in either direction.
#[derive(Debug, Default)]
pub struct IdleTracker {
    is_idle: bool,
}

impl IdleTracker {
    pub fn new() -> Self {
        Self { is_idle: false }
    }

    /// Returns `Some(now_idle)` when the idle/active state flips, else `None`. `now_idle`
    /// is `true` for a SESSION_IDLE transition, `false` for SESSION_ACTIVE.
    pub fn update(&mut self, idle_secs: u64, threshold_secs: u64) -> Option<bool> {
        let now_idle = idle_secs >= threshold_secs;
        if now_idle != self.is_idle {
            self.is_idle = now_idle;
            Some(now_idle)
        } else {
            None
        }
    }

    pub fn is_idle(&self) -> bool {
        self.is_idle
    }
}

/// Build the SESSION_IDLE / SESSION_ACTIVE event for a detected transition. `idle_secs` is
/// recorded in metadata so a reviewer can see how long the user had been away.
pub fn build_event(device_id: &str, now_idle: bool, idle_secs: u64) -> ActivityEvent {
    let event_type = if now_idle { EventType::SessionIdle } else { EventType::SessionActive };
    let meta = serde_json::json!({ "idle_seconds": idle_secs }).to_string();
    ActivityEvent {
        event_id: new_event_id(),
        device_id: device_id.to_string(),
        event_type,
        timestamp_utc: now_utc_iso(),
        application_name: None,
        process_name: None,
        window_title: None,
        metadata_json: Some(meta),
    }
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::System::SystemInformation::GetTickCount;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

    pub fn idle_seconds() -> u64 {
        unsafe {
            let mut lii = LASTINPUTINFO {
                cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
                dwTime: 0,
            };
            if GetLastInputInfo(&mut lii) == 0 {
                return 0; // query failed → treat as active
            }
            let now = GetTickCount();
            // GetTickCount wraps every ~49.7 days; saturating_sub keeps a wrap from
            // producing a huge bogus idle time (would just read 0 across the wrap).
            let ms = now.saturating_sub(lii.dwTime);
            (ms / 1000) as u64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_fire_once_per_edge() {
        let mut t = IdleTracker::new();
        // Below threshold → no change (starts active).
        assert_eq!(t.update(10, 300), None);
        // Cross into idle → one SESSION_IDLE.
        assert_eq!(t.update(300, 300), Some(true));
        // Still idle → no repeat.
        assert_eq!(t.update(900, 300), None);
        // Back to active → one SESSION_ACTIVE.
        assert_eq!(t.update(2, 300), Some(false));
        // Still active → no repeat.
        assert_eq!(t.update(5, 300), None);
    }

    #[test]
    fn event_shape_and_metadata() {
        let ev = build_event("dev_T", true, 420);
        assert_eq!(ev.event_type, EventType::SessionIdle);
        assert!(ev.metadata_json.unwrap().contains("420"));
        let ev2 = build_event("dev_T", false, 0);
        assert_eq!(ev2.event_type, EventType::SessionActive);
    }
}
