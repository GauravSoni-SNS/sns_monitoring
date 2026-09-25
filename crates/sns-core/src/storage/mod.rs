//! Storage subsystem: SQLite, screenshot filesystem, retention (spec §12–14, §25).

pub mod db;
pub mod dropbox;
pub mod filesystem;
pub mod retention;

pub use db::Storage;
