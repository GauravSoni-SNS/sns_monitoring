//! Retention + quota decisions (spec §25). Pure predicates here so they are unit-testable;
//! the storage task applies deletes transactionally (see STORAGE.md).

use sns_shared::sync::SyncStatus;

use crate::config::{RetentionPolicy, StoragePolicy};

#[derive(Debug, PartialEq, Eq)]
pub enum StorageLevel {
    Ok,
    Warning,
    Critical,
}

/// Map current usage to a level against policy thresholds (spec §25, §26).
pub fn storage_level(used_bytes: u64, policy: &StoragePolicy) -> StorageLevel {
    let pct = if policy.max_bytes == 0 {
        100
    } else {
        ((used_bytes as u128 * 100) / policy.max_bytes as u128) as u64
    };
    if pct >= policy.critical_pct as u64 {
        StorageLevel::Critical
    } else if pct >= policy.warn_pct as u64 {
        StorageLevel::Warning
    } else {
        StorageLevel::Ok
    }
}

/// Is a record old enough AND policy-permitted to delete? Un-synced data is protected
/// unless `delete_unsynced` is set (spec §25). In Phase 1 all data is `LOCAL_ONLY`, so
/// with the default policy only aged data whose loss is explicitly allowed is prunable.
pub fn is_deletable(age_days: u64, retention_days: u32, sync_status: SyncStatus, policy: &RetentionPolicy) -> bool {
    let old_enough = age_days >= retention_days as u64;
    if !old_enough {
        return false;
    }
    match sync_status {
        SyncStatus::Synced => true,
        _ => policy.delete_unsynced, // never drop un-synced data unless policy permits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage(max: u64, warn: u8, crit: u8) -> StoragePolicy {
        StoragePolicy { max_bytes: max, warn_pct: warn, critical_pct: crit }
    }

    #[test]
    fn levels() {
        let p = storage(100, 80, 90);
        assert_eq!(storage_level(50, &p), StorageLevel::Ok);
        assert_eq!(storage_level(85, &p), StorageLevel::Warning);
        assert_eq!(storage_level(95, &p), StorageLevel::Critical);
    }

    #[test]
    fn unsynced_data_protected_by_default() {
        let ret = RetentionPolicy { screenshot_days: 7, event_days: 30, delete_unsynced: false };
        // Old but LOCAL_ONLY → must NOT delete (spec §25).
        assert!(!is_deletable(60, 30, SyncStatus::LocalOnly, &ret));
        // Old and synced → deletable.
        assert!(is_deletable(60, 30, SyncStatus::Synced, &ret));
        // Not old enough → never.
        assert!(!is_deletable(10, 30, SyncStatus::Synced, &ret));
    }

    #[test]
    fn policy_can_permit_unsynced_deletion() {
        let ret = RetentionPolicy { screenshot_days: 7, event_days: 30, delete_unsynced: true };
        assert!(is_deletable(60, 30, SyncStatus::LocalOnly, &ret));
    }
}
