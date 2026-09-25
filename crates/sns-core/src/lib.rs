//! SNS agent core: config, identity, security (crypto/keys/integrity), storage,
//! health, and collector interfaces. OS-specific bits are gated behind `cfg(windows)`
//! with portable dev fallbacks so the crate builds and unit-tests on any platform.
//
// CoreError carries String detail on several variants, so `Result<_, CoreError>` exceeds
// clippy's large-err threshold. Intentional trade for readable diagnostics.
#![allow(clippy::result_large_err)]

pub mod clock;
pub mod collectors;
pub mod config;
pub mod error;
pub mod health;
pub mod identity;
pub mod security;
pub mod singleton;
pub mod storage;

pub use error::{CoreError, Result};

/// Default production data root (spec §12).
#[cfg(windows)]
pub const DEFAULT_DATA_ROOT: &str = r"C:\ProgramData\SNS\SecurityAgent";
/// Non-Windows dev fallback so the crate is usable in unit tests on any host.
#[cfg(not(windows))]
pub const DEFAULT_DATA_ROOT: &str = "/tmp/sns/SecurityAgent";
