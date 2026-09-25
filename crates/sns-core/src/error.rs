use thiserror::Error;

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("config error: {0}")]
    Config(String),

    #[error("identity error: {0}")]
    Identity(String),

    #[error("crypto error")] // deliberately opaque: never leak key/nonce/plaintext detail
    Crypto,

    #[error("key management error: {0}")]
    KeyManagement(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("integrity failure: {0}")]
    Integrity(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("db error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
