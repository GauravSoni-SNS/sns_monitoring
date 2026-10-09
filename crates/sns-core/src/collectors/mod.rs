//! Collector interfaces (spec §17–19, §42, §43). Each collector is an independent unit
//! the supervisor runs in its own task with restart-on-fault isolation — one failing
//! collector never stops the others (spec §42).
//!
//! Platform capture (Win32 foreground-window, session, USB, screen duplication) is
//! implemented in `cfg(windows)` submodules. This module defines the shared contract and
//! the emitted-event shapes. The actual Win32 capture bodies are the next build step
//! (see BUILD-STATUS.md); their event outputs and lifecycle are fixed here.

use sns_shared::events::ActivityEvent;

use crate::error::Result;

/// A source of activity events. Implementations must be cancellation-safe and must never
/// block on the network (offline-first, spec §23) or capture keystrokes/passwords/
/// clipboard (spec §17).
pub trait Collector: Send {
    /// Stable name for logging + supervisor bookkeeping.
    fn name(&self) -> &'static str;

    /// Poll once for new events. Called on the collector's own cadence by the supervisor.
    /// Returning `Err` triggers isolated restart-with-backoff, not agent shutdown.
    fn poll(&mut self) -> Result<Vec<ActivityEvent>>;
}

pub mod application;
pub mod browser;
pub mod idle;
#[cfg(unix)]
pub mod platform_unix;
pub mod print;
pub mod screenshot;
pub mod system;
pub mod transferapps;
pub mod usb;
pub mod usbfiles;
