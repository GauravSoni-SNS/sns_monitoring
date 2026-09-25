//! Stable, time-sortable identifiers (spec §9, §15).
//!
//! ULID-based so Phase-2 sync can upsert/dedup idempotently. Prefixes keep IDs
//! self-describing in logs and the admin UI without changing sort order meaning.

use ulid::Ulid;

/// `dev_<ULID>` — generated once at install, immutable thereafter (spec §9).
pub fn new_device_id() -> String {
    format!("dev_{}", Ulid::new())
}

/// `evt_<ULID>` — unique per activity/browser/system event (spec §15).
pub fn new_event_id() -> String {
    format!("evt_{}", Ulid::new())
}

/// `scr_<ULID>` — unique per screenshot; also used as the opaque filename stem (spec §20).
pub fn new_screenshot_id() -> String {
    format!("scr_{}", Ulid::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_have_prefixes_and_are_unique() {
        let a = new_event_id();
        let b = new_event_id();
        assert!(a.starts_with("evt_"));
        assert_ne!(a, b);
        assert!(new_device_id().starts_with("dev_"));
        assert!(new_screenshot_id().starts_with("scr_"));
    }
}
