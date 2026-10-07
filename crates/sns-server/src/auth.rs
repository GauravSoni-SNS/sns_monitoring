//! Token + password helpers and the in-memory admin-session store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// SHA-256 hex of a secret (device tokens, enroll tokens stored hashed).
pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

/// A fresh 256-bit random token, hex-encoded. Shown to the client once; only its hash is kept.
pub fn generate_token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// Argon2id hash for an admin password.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hash: {e}"))
}

pub fn verify_password(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

/// An authenticated admin session: which org, and the CSRF token, with an expiry.
#[derive(Clone)]
pub struct Session {
    pub org_id: i64,
    pub csrf: String,
    expires: Instant,
}

/// In-memory admin session store (one server instance). A horizontally-scaled deployment
/// would move this to Redis/DB; noted in PHASE-D-SERVER.md.
#[derive(Clone, Default)]
pub struct Sessions {
    map: Arc<Mutex<HashMap<String, Session>>>,
}

impl Sessions {
    pub fn issue(&self, org_id: i64, ttl: Duration) -> (String, String) {
        let token = generate_token();
        let csrf = generate_token();
        let s = Session { org_id, csrf: csrf.clone(), expires: Instant::now() + ttl };
        self.map.lock().unwrap().insert(token.clone(), s);
        (token, csrf)
    }

    /// Returns the session's org_id if the token is valid and unexpired.
    pub fn org_of(&self, token: &str) -> Option<i64> {
        let mut m = self.map.lock().unwrap();
        match m.get(token) {
            Some(s) if s.expires > Instant::now() => Some(s.org_id),
            Some(_) => {
                m.remove(token);
                None
            }
            None => None,
        }
    }

    pub fn csrf_ok(&self, token: &str, csrf: &str) -> bool {
        let m = self.map.lock().unwrap();
        m.get(token).map(|s| s.csrf == csrf && s.expires > Instant::now()).unwrap_or(false)
    }
}
