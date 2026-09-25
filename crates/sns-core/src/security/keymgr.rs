//! Key management (spec §21). A random 256-bit DEK is generated at install and stored
//! **only in wrapped form**. On Windows it is wrapped with DPAPI (`CryptProtectData`,
//! LocalMachine scope) so it is bound to this host and unreadable by other machines/users.
//! The plaintext DEK lives only in a `Zeroizing` buffer in memory.
//!
//! Non-Windows builds use a clearly-marked DEV fallback (NOT for production) so the code
//! compiles and unit-tests on any platform.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::security::crypto::DataKey;

/// On-disk keyring. Contains only wrapped material — never a plaintext key.
#[derive(Serialize, Deserialize)]
struct Keyring {
    key_version: u32,
    /// DPAPI-wrapped (or dev-wrapped) DEK, hex-encoded.
    wrapped_dek_hex: String,
    protection: String, // "dpapi-localmachine" | "dev-insecure"
}

pub struct KeyManager {
    keyring_path: PathBuf,
    key_version: u32,
    dek: DataKey,
}

impl KeyManager {
    /// Load an existing keyring, unwrapping the DEK into memory.
    pub fn load(keyring_path: impl AsRef<Path>) -> Result<Self> {
        let path = keyring_path.as_ref().to_path_buf();
        let raw = std::fs::read(&path)?;
        let ring: Keyring = serde_json::from_slice(&raw)?;
        let wrapped = hex::decode(&ring.wrapped_dek_hex)
            .map_err(|_| CoreError::KeyManagement("bad wrapped-key hex".into()))?;
        let bytes = unwrap_dek(&wrapped)?;
        Ok(Self {
            keyring_path: path,
            key_version: ring.key_version,
            dek: DataKey::from_bytes(bytes),
        })
    }

    /// Generate a fresh DEK, wrap it, and persist the keyring (install step, spec §38.6).
    pub fn initialize(keyring_path: impl AsRef<Path>) -> Result<Self> {
        let path = keyring_path.as_ref().to_path_buf();
        if path.exists() {
            return Err(CoreError::KeyManagement("keyring already exists".into()));
        }
        let dek = DataKey::generate();
        let wrapped = wrap_dek(dek.0.as_slice())?;
        let ring = Keyring {
            key_version: 1,
            wrapped_dek_hex: hex::encode(&wrapped),
            protection: protection_label().into(),
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_vec_pretty(&ring)?)?;
        Ok(Self { keyring_path: path, key_version: 1, dek })
    }

    pub fn data_key(&self) -> &DataKey {
        &self.dek
    }

    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    /// Path is exposed for install-time ACL hardening.
    pub fn keyring_path(&self) -> &Path {
        &self.keyring_path
    }
}

fn protection_label() -> &'static str {
    if cfg!(windows) {
        "dpapi-localmachine"
    } else {
        "dev-insecure"
    }
}

// ----------------------------- Windows: DPAPI ------------------------------

#[cfg(windows)]
fn wrap_dek(plaintext: &[u8]) -> Result<Vec<u8>> {
    dpapi::protect(plaintext)
}

#[cfg(windows)]
fn unwrap_dek(wrapped: &[u8]) -> Result<[u8; 32]> {
    let out = dpapi::unprotect(wrapped)?;
    to_array_32(&out)
}

#[cfg(windows)]
mod dpapi {
    use super::{CoreError, Result};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
    };

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        }
    }

    /// SAFETY: all pointers point at live local buffers for the duration of the call;
    /// the returned blob is copied out then freed with `LocalFree`.
    pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let input = blob(plaintext);
            let mut output = std::mem::zeroed::<CRYPT_INTEGER_BLOB>();
            let ok = CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut output,
            );
            if ok == 0 {
                return Err(CoreError::KeyManagement("CryptProtectData failed".into()));
            }
            let out = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            LocalFree(output.pbData as _);
            Ok(out)
        }
    }

    pub fn unprotect(wrapped: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let input = blob(wrapped);
            let mut output = std::mem::zeroed::<CRYPT_INTEGER_BLOB>();
            let ok = CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut output,
            );
            if ok == 0 {
                return Err(CoreError::KeyManagement("CryptUnprotectData failed".into()));
            }
            let out = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            LocalFree(output.pbData as _);
            Ok(out)
        }
    }
}

// --------------------------- Non-Windows dev -------------------------------
// DEV ONLY. This is NOT secure key protection; production runs on Windows w/ DPAPI.
// Provided so the crate builds and unit-tests on Linux/macOS CI.

#[cfg(not(windows))]
fn wrap_dek(plaintext: &[u8]) -> Result<Vec<u8>> {
    Ok(plaintext.to_vec())
}

#[cfg(not(windows))]
fn unwrap_dek(wrapped: &[u8]) -> Result<[u8; 32]> {
    to_array_32(wrapped)
}

fn to_array_32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| CoreError::KeyManagement("unwrapped key not 32 bytes".into()))
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use crate::security::crypto;

    #[test]
    fn initialize_then_load_roundtrips_dek() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keyring.json");
        let km = KeyManager::initialize(&path).unwrap();
        let blob = crypto::encrypt(km.data_key(), b"secret").unwrap();

        // Reload from disk and decrypt with the recovered DEK.
        let km2 = KeyManager::load(&path).unwrap();
        assert_eq!(crypto::decrypt(km2.data_key(), &blob).unwrap(), b"secret");
    }

    #[test]
    fn keyring_file_has_no_plaintext_marker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keyring.json");
        KeyManager::initialize(&path).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("wrapped_dek_hex"));
        assert!(!contents.contains("\"dek\""));
    }
}
