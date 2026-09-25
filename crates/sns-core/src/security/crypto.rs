//! AES-256-GCM authenticated encryption (spec §21). Uses the RustCrypto `aes-gcm`
//! crate — no home-grown primitives. Fresh 96-bit random nonce per message; the nonce
//! is prepended to the ciphertext. Keys are held in `Zeroizing` and never logged.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Current on-disk envelope version (spec: `encryption_version`). Bump on format change.
pub const ENCRYPTION_VERSION: u32 = 1;

const KEY_LEN: usize = 32; // AES-256
const NONCE_LEN: usize = 12; // 96-bit GCM nonce

/// A 256-bit data-encryption key. Wrapped in `Zeroizing` so it is wiped on drop.
#[derive(Clone)]
pub struct DataKey(pub Zeroizing<[u8; KEY_LEN]>);

impl DataKey {
    /// Generate a fresh random DEK from the OS CSPRNG.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(k.as_mut_slice());
        DataKey(k)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        DataKey(Zeroizing::new(bytes))
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.0.as_slice()))
    }
}

/// Encrypt `plaintext`. Output layout: `nonce(12) || ciphertext_with_tag`.
pub fn encrypt(key: &DataKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = key.cipher();
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // random, unique per call
    let ct = cipher.encrypt(&nonce, plaintext).map_err(|_| CoreError::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a `nonce || ciphertext` blob produced by [`encrypt`]. Auth-tag failure
/// (tamper/wrong key) returns [`CoreError::Crypto`] without detail.
pub fn decrypt(key: &DataKey, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return Err(CoreError::Crypto);
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let cipher = key.cipher();
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ct).map_err(|_| CoreError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let k = DataKey::generate();
        let msg = b"authorized screenshot bytes";
        let blob = encrypt(&k, msg).unwrap();
        assert_ne!(&blob[NONCE_LEN..], msg); // actually encrypted
        assert_eq!(decrypt(&k, &blob).unwrap(), msg);
    }

    #[test]
    fn tamper_is_rejected() {
        let k = DataKey::generate();
        let mut blob = encrypt(&k, b"data").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01; // flip a ciphertext/tag bit
        assert!(matches!(decrypt(&k, &blob), Err(CoreError::Crypto)));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let blob = encrypt(&DataKey::generate(), b"data").unwrap();
        assert!(matches!(decrypt(&DataKey::generate(), &blob), Err(CoreError::Crypto)));
    }

    #[test]
    fn nonces_differ_across_messages() {
        let k = DataKey::generate();
        let a = encrypt(&k, b"x").unwrap();
        let b = encrypt(&k, b"x").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]); // unique nonce per encryption
    }
}
