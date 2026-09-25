//! Admin authentication (spec §31, §40). Argon2id password verification + opaque session
//! tokens. Login failures are meant to be written to `audit_log` by the caller.

use sns_core::security::password::verify_password;

/// Verify a submitted admin password against the stored PHC hash from `agent.json`.
// Consumed by the axum login handler (Task #6); kept as the auth API surface.
#[allow(dead_code)]
pub fn check_login(submitted: &str, stored_hash: &str) -> bool {
    verify_password(submitted, stored_hash)
}

/// A 256-bit session token, hex-encoded. Issued after a successful login; stored server
/// side with a TTL. (Token store impl lands with the HTTP server.)
#[allow(dead_code)]
pub fn new_session_token() -> String {
    use sns_core::security::crypto::DataKey; // reuse the CSPRNG-backed key gen for 32 bytes
    let k = DataKey::generate();
    hex::encode(k.0.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sns_core::security::password::hash_password;

    #[test]
    fn login_checks_password() {
        let stored = hash_password("s3cret-admin-pw").unwrap();
        assert!(check_login("s3cret-admin-pw", &stored));
        assert!(!check_login("guess", &stored));
    }

    #[test]
    fn tokens_are_unique_and_sized() {
        let a = new_session_token();
        let b = new_session_token();
        assert_eq!(a.len(), 64); // 32 bytes hex
        assert_ne!(a, b);
    }
}
