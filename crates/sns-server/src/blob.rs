//! Screenshot blob storage + org-key crypto (Phase E2).
//!
//! The agent re-encrypts each screenshot under the org's symmetric key before upload, so the
//! server stores ciphertext on disk. The dashboard decrypts it (server-side, with the org key)
//! only for that org's authorized admin. Blobs live on the server's filesystem keyed by
//! screenshot id; metadata lives in Postgres.

use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;

/// Directory where screenshot blobs are stored (override with SNS_BLOB_DIR).
pub fn blob_dir() -> PathBuf {
    PathBuf::from(std::env::var("SNS_BLOB_DIR").unwrap_or_else(|_| "blobs".into()))
}

fn blob_path(screenshot_id: &str) -> PathBuf {
    // Sanitize: ids are ULIDs (alphanumeric), but guard against path traversal anyway.
    let safe: String = screenshot_id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
    blob_dir().join(format!("{safe}.enc"))
}

/// Write an (already org-encrypted) blob to disk.
pub fn store(screenshot_id: &str, bytes: &[u8]) -> std::io::Result<()> {
    let dir = blob_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(blob_path(screenshot_id), bytes)
}

/// Read a stored blob (ciphertext) from disk.
pub fn load(screenshot_id: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(blob_path(screenshot_id))
}

fn key_from_hex(hex_key: &str) -> Option<[u8; 32]> {
    let v = hex::decode(hex_key).ok()?;
    if v.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&v);
    Some(k)
}

/// Encrypt with the org key → `nonce(12) || ciphertext`. (Used if the server ever needs to
/// encrypt; the agent normally produces this blob itself.)
pub fn encrypt(hex_key: &str, plain: &[u8]) -> Option<Vec<u8>> {
    let k = key_from_hex(hex_key)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k));
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), plain).ok()?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Some(out)
}

/// Decrypt a `nonce(12) || ciphertext` blob with the org key → plaintext PNG.
pub fn decrypt(hex_key: &str, blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 13 {
        return None;
    }
    let k = key_from_hex(hex_key)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k));
    let (nonce, ct) = blob.split_at(12);
    cipher.decrypt(Nonce::from_slice(nonce), ct).ok()
}

/// Delete a stored blob (best effort).
pub fn remove(screenshot_id: &str) {
    let _ = std::fs::remove_file(blob_path(screenshot_id));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_key_round_trip() {
        // 32-byte key as 64 hex chars (same shape the server issues).
        let key = "9f8ff33c2d9bdbad2e141d3f1f2054c66ccbcf2ad24086bf11cde4420687e5ad";
        let msg = b"\x89PNG\r\n\x1a\n fake screenshot bytes";
        let blob = encrypt(key, msg).unwrap();
        assert!(blob.len() > 12);
        assert_eq!(decrypt(key, &blob).unwrap(), msg);
        // Wrong key fails cleanly.
        let other = "00000000000000000000000000000000000000000000000000000000000000ff";
        assert!(decrypt(other, &blob).is_none());
    }
}
