//! Shared models, IDs, event types, and Phase-2 sync interfaces for the SNS agent.
//!
//! This crate is OS-independent and unit-testable on any platform.

pub mod ids;
pub mod events;
pub mod models;
pub mod sync;

pub use events::{ActivityEvent, EventType};
pub use ids::{new_device_id, new_event_id, new_screenshot_id};
pub use models::{Device, ScreenshotMeta};
pub use sync::SyncStatus;

/// Genesis previous-hash for the very first event in the integrity chain (spec §22).
pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
