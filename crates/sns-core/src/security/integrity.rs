//! Tamper-evident chain verification (spec §22).
//!
//! For each stored activity event we recompute `SHA-256(canonical || previous_hash)` and
//! check it equals the stored `event_hash`, and that `previous_event_hash` equals the prior
//! row's `event_hash` (chain linkage). Any mismatch is a break, located precisely.

use sns_shared::events::ActivityEvent;
use sns_shared::GENESIS_HASH;

/// A row as persisted, reconstructed for verification.
pub struct StoredEvent {
    pub event: ActivityEvent,
    pub event_hash: String,
    pub previous_event_hash: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerifyReport {
    pub events_checked: usize,
    pub invalid_records: usize,
    /// `event_id`s of the first offending rows (bounded for logging).
    pub first_breaks: Vec<String>,
}

impl VerifyReport {
    pub fn is_pass(&self) -> bool {
        self.invalid_records == 0
    }
}

/// Verify an ordered slice (ascending by rowid / insertion order).
pub fn verify_chain(rows: &[StoredEvent]) -> VerifyReport {
    let mut invalid = 0usize;
    let mut breaks = Vec::new();
    let mut expected_prev = GENESIS_HASH.to_string();

    for row in rows {
        let mut bad = false;

        // 1) linkage: stored previous_hash must match the running chain head.
        if row.previous_event_hash != expected_prev {
            bad = true;
        }
        // 2) content: recomputed hash must match stored hash.
        let recomputed = row.event.compute_hash(&row.previous_event_hash);
        if recomputed != row.event_hash {
            bad = true;
        }

        if bad {
            invalid += 1;
            if breaks.len() < 16 {
                breaks.push(row.event.event_id.clone());
            }
        }
        // Advance using the STORED hash so a single tampered row reports one break
        // rather than cascading through every subsequent row.
        expected_prev = row.event_hash.clone();
    }

    VerifyReport {
        events_checked: rows.len(),
        invalid_records: invalid,
        first_breaks: breaks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sns_shared::events::EventType;

    fn mk(id: &str, app: &str, prev: &str) -> StoredEvent {
        let event = ActivityEvent {
            event_id: id.into(),
            device_id: "dev_T".into(),
            event_type: EventType::ApplicationStarted,
            timestamp_utc: "2026-08-11T10:00:00Z".into(),
            application_name: Some(app.into()),
            process_name: Some(app.into()),
            window_title: None,
            metadata_json: None,
        };
        let sealed = event.seal(prev);
        StoredEvent {
            event,
            event_hash: sealed.event_hash,
            previous_event_hash: sealed.previous_event_hash,
        }
    }

    fn chain() -> Vec<StoredEvent> {
        let a = mk("evt_1", "chrome.exe", GENESIS_HASH);
        let b = mk("evt_2", "code.exe", &a.event_hash);
        let c = mk("evt_3", "explorer.exe", &b.event_hash);
        vec![a, b, c]
    }

    #[test]
    fn clean_chain_passes() {
        let r = verify_chain(&chain());
        assert!(r.is_pass());
        assert_eq!(r.events_checked, 3);
    }

    #[test]
    fn content_tamper_is_caught() {
        let mut rows = chain();
        // Attacker edits the app name but cannot recompute the stored hash.
        rows[1].event.application_name = Some("evil.exe".into());
        let r = verify_chain(&rows);
        assert!(!r.is_pass());
        assert_eq!(r.invalid_records, 1);
        assert_eq!(r.first_breaks, vec!["evt_2".to_string()]);
    }

    #[test]
    fn deleted_row_breaks_linkage() {
        let mut rows = chain();
        rows.remove(1); // drop evt_2; evt_3.previous no longer matches head
        let r = verify_chain(&rows);
        assert!(!r.is_pass());
    }
}
