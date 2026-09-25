//! Single source of UTC timestamps in the canonical ISO-8601 form used everywhere
//! (DB columns, event canonicalization, filenames' day buckets).

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Current UTC time as RFC-3339 / ISO-8601, e.g. `2026-08-11T18:32:22Z`.
pub fn now_utc_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// (year, month, day) for the screenshot storage buckets `data\Y\M\D\...` (spec §12).
pub fn ymd_utc() -> (i32, u8, u8) {
    let n = OffsetDateTime::now_utc();
    (n.year(), n.month() as u8, n.day())
}

/// ISO-8601 UTC cutoff `days` in the past. Because timestamps are stored as RFC-3339
/// UTC (`...Z`), lexicographic `<` comparison equals chronological comparison, so this is
/// safe to use directly in SQL `WHERE timestamp_utc < ?` retention queries (spec §17, §25).
pub fn iso_days_ago(days: u32) -> String {
    let cutoff = OffsetDateTime::now_utc() - time::Duration::days(days as i64);
    cutoff.format(&Rfc3339).unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}
