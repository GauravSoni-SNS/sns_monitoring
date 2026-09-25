//! Device identity (spec §9–11). `device_id` is generated once at install and is
//! immutable; `system_name` is admin-set and mutable; changing it never mints a new
//! `device_id`. IP/hostname are supplementary and never used as identity.

use sns_shared::ids::new_device_id;

use crate::error::{CoreError, Result};

pub struct Identity {
    pub device_id: String,
    pub system_name: String,
}

impl Identity {
    /// First-install identity: fresh immutable device_id + admin-provided system name.
    pub fn create(system_name: &str) -> Result<Self> {
        if system_name.trim().is_empty() {
            return Err(CoreError::Identity("system_name required".into()));
        }
        Ok(Self {
            device_id: new_device_id(),
            system_name: system_name.to_string(),
        })
    }

    /// Rename by an authorized admin. Returns the (unchanged) device_id to make the
    /// invariant explicit at call sites (spec §10).
    pub fn rename(&mut self, new_system_name: &str) -> Result<&str> {
        if new_system_name.trim().is_empty() {
            return Err(CoreError::Identity("system_name required".into()));
        }
        self.system_name = new_system_name.to_string();
        Ok(&self.device_id) // device_id is intentionally NOT regenerated
    }
}

/// Best-effort current hostname (supplementary metadata only).
pub fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME") // Windows
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_keeps_device_id() {
        let mut id = Identity::create("SNS-PC-007").unwrap();
        let original = id.device_id.clone();
        let after = id.rename("SNS-PC-999").unwrap().to_string();
        assert_eq!(after, original); // device_id stable across rename (spec §10)
        assert_eq!(id.system_name, "SNS-PC-999");
    }

    #[test]
    fn create_rejects_empty_name() {
        assert!(Identity::create("  ").is_err());
    }
}
