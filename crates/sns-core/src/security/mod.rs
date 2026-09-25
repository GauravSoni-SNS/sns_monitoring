//! Security subsystem: encryption, key management, integrity, admin auth (spec §21, §22, §31).

pub mod crypto;
pub mod integrity;
pub mod keymgr;
pub mod password;

pub use crypto::{decrypt, encrypt, DataKey, ENCRYPTION_VERSION};
pub use keymgr::KeyManager;
