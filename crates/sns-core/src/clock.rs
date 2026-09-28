//! Single source of timestamps. The product operates in **India Standard Time (IST,
//! UTC+05:30)**: recorded timestamps and date-derived paths use IST. Values are RFC-3339
//! with an explicit `+05:30` offset, so they remain unambiguous instants and sort
//! chronologically by string comparison (all share the same offset).
//!
//! Function names are kept (`now_utc_iso`, `ymd_utc`) for call-site compatibility; the
//! values they return are IST.

use time::format_description::well_known::Rfc3339;
use time::macros::offset;
use time::{Duration, OffsetDateTime, UtcOffset};

/// India Standard Time offset.
const IST: UtcOffset = offset!(+5:30);

fn now_ist() -> OffsetDateTime {
    OffsetDateTime::now_utc().to_offset(IST)
}

/// Current IST time as RFC-3339 with +05:30 offset, e.g. `2026-09-25T18:32:22+05:30`.
pub fn now_utc_iso() -> String {
    now_ist()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00+05:30".to_string())
}

/// (year, month, day) in IST for the screenshot day-buckets `data\Y\M\D\...` (spec §12).
pub fn ymd_utc() -> (i32, u8, u8) {
    let n = now_ist();
    (n.year(), n.month() as u8, n.day())
}

/// RFC-3339 IST cutoff `days` in the past (+05:30). Same offset as stored timestamps, so
/// string comparison in retention / date-range queries stays chronological.
pub fn iso_days_ago(days: u32) -> String {
    (now_ist() - Duration::days(days as i64))
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00+05:30".to_string())
}
