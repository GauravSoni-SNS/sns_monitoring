//! Local alerting rules (Phase-2 #4). Pure, read-only evaluation over already-collected
//! events — no new capture surface, no network, no server. Rules live in
//! `config/alerts.json` (optional; sensible defaults if absent). The admin panel scans recent
//! events and surfaces matches in an Alerts view.
//!
//! Noise control: discrete events (USB, integrity) produce one alert each; "blocked app /
//! domain" and "after-hours" are de-duplicated (per app/domain, and per calendar day) so a
//! busy stream does not flood the view.

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::Result;
use crate::storage::db::ActivityRow;

fn d_true() -> bool {
    true
}

/// Alert rule set. All fields `#[serde(default)]` so a partial or missing `alerts.json`
/// still yields a valid configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRules {
    /// Flag every USB device connect (removable storage is the data-exfil case).
    #[serde(default = "d_true")]
    pub usb_connect: bool,
    /// Flag integrity-chain failures.
    #[serde(default = "d_true")]
    pub integrity_failure: bool,
    /// Process/app names (case-insensitive substring) that should raise an alert when used.
    #[serde(default)]
    pub blocked_apps: Vec<String>,
    /// Domains (case-insensitive substring) that should raise an alert when visited.
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    /// Working hours (IST). Activity outside `[start, end)` is flagged once per day.
    #[serde(default)]
    pub after_hours: Option<AfterHours>,
    /// Flag files written to removable drives (the data-exfil case).
    #[serde(default = "d_true")]
    pub usb_file_copy: bool,
    /// Flag documents sent to a printer.
    #[serde(default = "d_true")]
    pub document_printed: bool,
    /// Daily volume limit for data copied to USB, in MB. If the total copied to removable
    /// drives in a day exceeds this, raise one high alert for that day. `0` = disabled.
    #[serde(default)]
    pub usb_daily_mb_limit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AfterHours {
    pub work_start_hour: u8,
    pub work_end_hour: u8,
}

impl Default for AlertRules {
    fn default() -> Self {
        AlertRules {
            usb_connect: true,
            integrity_failure: true,
            blocked_apps: Vec::new(),
            blocked_domains: Vec::new(),
            after_hours: None,
            usb_file_copy: true,
            document_printed: true,
            usb_daily_mb_limit: 0,
        }
    }
}

impl AlertRules {
    /// Load from `config/alerts.json`, or return defaults if the file is absent.
    /// A malformed file is an error (so a typo is visible, not silently ignored).
    pub fn load_or_default(path: impl AsRef<Path>) -> Result<Self> {
        match std::fs::read(path.as_ref()) {
            Ok(raw) => Ok(serde_json::from_slice(&raw)?),
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }
}

/// A raised alert (read-model for the admin panel).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Alert {
    pub severity: Severity,
    pub kind: String,
    pub message: String,
    pub timestamp_utc: String,
    pub event_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Low,
}

fn hour_ist(ts: &str) -> Option<u8> {
    OffsetDateTime::parse(ts, &Rfc3339).ok().map(|t| t.hour())
}

fn date_part(ts: &str) -> &str {
    ts.split('T').next().unwrap_or(ts)
}

/// Evaluate `rules` over `rows` (any order) and return matching alerts, newest first,
/// capped at 200. De-duplicates blocked-app/-domain (per name) and after-hours (per day).
pub fn evaluate(rules: &AlertRules, rows: &[ActivityRow]) -> Vec<Alert> {
    let mut out: Vec<Alert> = Vec::new();
    let mut seen_app: HashSet<String> = HashSet::new();
    let mut seen_domain: HashSet<String> = HashSet::new();
    let mut seen_afterhours_day: HashSet<String> = HashSet::new();
    // Per-day total bytes copied to USB, for the volume-limit alert.
    let mut usb_day_bytes: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

    for r in rows {
        if rules.usb_daily_mb_limit > 0 && r.event_type == "FILE_COPIED_TO_USB" {
            if let Some(size) = r.metadata_json.as_deref().and_then(usb_size_bytes) {
                *usb_day_bytes.entry(date_part(&r.timestamp_utc).to_string()).or_insert(0) += size;
            }
        }
        match r.event_type.as_str() {
            "USB_DEVICE_CONNECTED" if rules.usb_connect => {
                out.push(Alert {
                    severity: Severity::High,
                    kind: "usb_connect".into(),
                    message: format!(
                        "USB device connected: {}",
                        r.window_title.clone().or_else(|| r.metadata_json.clone()).unwrap_or_else(|| "(unknown)".into())
                    ),
                    timestamp_utc: r.timestamp_utc.clone(),
                    event_id: r.event_id.clone(),
                });
            }
            "FILE_COPIED_TO_USB" if rules.usb_file_copy => {
                out.push(Alert {
                    severity: Severity::High,
                    kind: "usb_file_copy".into(),
                    message: format!(
                        "File written to removable drive: {}",
                        r.window_title.clone().unwrap_or_else(|| "(unknown)".into())
                    ),
                    timestamp_utc: r.timestamp_utc.clone(),
                    event_id: r.event_id.clone(),
                });
            }
            "DOCUMENT_PRINTED" if rules.document_printed => {
                out.push(Alert {
                    severity: Severity::Medium,
                    kind: "document_printed".into(),
                    message: format!(
                        "Document printed: {}",
                        r.window_title.clone().unwrap_or_else(|| "(unknown)".into())
                    ),
                    timestamp_utc: r.timestamp_utc.clone(),
                    event_id: r.event_id.clone(),
                });
            }
            "TAMPER_SUSPECTED" if rules.integrity_failure => {
                out.push(Alert {
                    severity: Severity::High,
                    kind: "tamper".into(),
                    message: "Agent stopped unexpectedly (forced stop / crash / power loss)".into(),
                    timestamp_utc: r.timestamp_utc.clone(),
                    event_id: r.event_id.clone(),
                });
            }
            "INTEGRITY_FAILURE" if rules.integrity_failure => {
                out.push(Alert {
                    severity: Severity::High,
                    kind: "integrity_failure".into(),
                    message: "Event-chain integrity failure detected".into(),
                    timestamp_utc: r.timestamp_utc.clone(),
                    event_id: r.event_id.clone(),
                });
            }
            "ACTIVE_APPLICATION_CHANGED" | "APPLICATION_STARTED" => {
                let name = r
                    .application_name
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if let Some(hit) = rules
                    .blocked_apps
                    .iter()
                    .find(|b| !b.is_empty() && name.contains(&b.to_ascii_lowercase()))
                {
                    if seen_app.insert(hit.to_ascii_lowercase()) {
                        out.push(Alert {
                            severity: Severity::Medium,
                            kind: "blocked_app".into(),
                            message: format!("Blocked application used: {hit}"),
                            timestamp_utc: r.timestamp_utc.clone(),
                            event_id: r.event_id.clone(),
                        });
                    }
                }
                flag_after_hours(rules, r, &mut seen_afterhours_day, &mut out);
            }
            "BROWSER_ACTIVITY" => {
                let site = r.window_title.as_deref().unwrap_or("").to_ascii_lowercase();
                if let Some(hit) = rules
                    .blocked_domains
                    .iter()
                    .find(|b| !b.is_empty() && site.contains(&b.to_ascii_lowercase()))
                {
                    if seen_domain.insert(hit.to_ascii_lowercase()) {
                        out.push(Alert {
                            severity: Severity::Medium,
                            kind: "blocked_domain".into(),
                            message: format!("Blocked site visited: {hit}"),
                            timestamp_utc: r.timestamp_utc.clone(),
                            event_id: r.event_id.clone(),
                        });
                    }
                }
                flag_after_hours(rules, r, &mut seen_afterhours_day, &mut out);
            }
            _ => {}
        }
    }

    // Daily USB volume-limit alerts (one per day over the limit).
    if rules.usb_daily_mb_limit > 0 {
        let limit_bytes = rules.usb_daily_mb_limit * 1_000_000;
        for (day, bytes) in &usb_day_bytes {
            if *bytes > limit_bytes {
                out.push(Alert {
                    severity: Severity::High,
                    kind: "usb_volume".into(),
                    message: format!(
                        "High data volume copied to USB on {day}: {:.1} MB (limit {} MB)",
                        *bytes as f64 / 1_000_000.0,
                        rules.usb_daily_mb_limit
                    ),
                    timestamp_utc: format!("{day}T23:59:59+05:30"),
                    event_id: format!("usbvol-{day}"),
                });
            }
        }
    }

    out.sort_by(|a, b| b.timestamp_utc.cmp(&a.timestamp_utc));
    out.truncate(200);
    out
}

/// Extract the `size` field (bytes) from a FILE_COPIED_TO_USB metadata JSON blob.
fn usb_size_bytes(meta: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(meta)
        .ok()
        .and_then(|v| v.get("size").and_then(|s| s.as_u64()))
}

fn flag_after_hours(
    rules: &AlertRules,
    r: &ActivityRow,
    seen_day: &mut HashSet<String>,
    out: &mut Vec<Alert>,
) {
    let Some(ah) = &rules.after_hours else { return };
    let Some(h) = hour_ist(&r.timestamp_utc) else { return };
    let outside = h < ah.work_start_hour || h >= ah.work_end_hour;
    if !outside {
        return;
    }
    let day = date_part(&r.timestamp_utc).to_string();
    if seen_day.insert(day.clone()) {
        out.push(Alert {
            severity: Severity::Low,
            kind: "after_hours".into(),
            message: format!(
                "After-hours activity on {day} (outside {:02}:00–{:02}:00 IST)",
                ah.work_start_hour, ah.work_end_hour
            ),
            timestamp_utc: r.timestamp_utc.clone(),
            event_id: r.event_id.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(etype: &str, app: Option<&str>, title: Option<&str>, ts: &str, id: &str) -> ActivityRow {
        ActivityRow {
            event_id: id.into(),
            event_type: etype.into(),
            timestamp_utc: ts.into(),
            application_name: app.map(|s| s.into()),
            window_title: title.map(|s| s.into()),
            metadata_json: None,
        }
    }

    #[test]
    fn usb_and_integrity_are_high() {
        let rules = AlertRules::default();
        let rows = vec![
            row("USB_DEVICE_CONNECTED", None, Some("SanDisk (E:)"), "2026-10-01T10:00:00+05:30", "e1"),
            row("INTEGRITY_FAILURE", None, None, "2026-10-01T11:00:00+05:30", "e2"),
        ];
        let a = evaluate(&rules, &rows);
        assert_eq!(a.len(), 2);
        assert!(a.iter().all(|x| x.severity == Severity::High));
    }

    #[test]
    fn usb_volume_limit_fires_per_day() {
        let mut rules = AlertRules::default();
        rules.usb_connect = false;
        rules.usb_file_copy = false; // isolate the volume alert
        rules.usb_daily_mb_limit = 10; // 10 MB/day
        let big = |id: &str, ts: &str, bytes: u64| ActivityRow {
            event_id: id.into(),
            event_type: "FILE_COPIED_TO_USB".into(),
            timestamp_utc: ts.into(),
            application_name: None,
            window_title: Some("x".into()),
            metadata_json: Some(format!("{{\"size\":{bytes}}}")),
        };
        let rows = vec![
            big("f1", "2026-10-01T10:00:00+05:30", 6_000_000),
            big("f2", "2026-10-01T11:00:00+05:30", 6_000_000), // day total 12 MB > 10
            big("f3", "2026-10-02T10:00:00+05:30", 3_000_000), // day total 3 MB < 10
        ];
        let a = evaluate(&rules, &rows);
        let vol: Vec<_> = a.iter().filter(|x| x.kind == "usb_volume").collect();
        assert_eq!(vol.len(), 1); // only Oct-01 over limit
        assert!(vol[0].message.contains("12.0 MB"));
    }

    #[test]
    fn blocked_app_and_domain_dedupe() {
        let rules = AlertRules {
            blocked_apps: vec!["steam".into()],
            blocked_domains: vec!["facebook.com".into()],
            usb_connect: false,
            integrity_failure: false,
            after_hours: None, usb_file_copy: false, document_printed: false, usb_daily_mb_limit: 0,
        };
        let rows = vec![
            row("ACTIVE_APPLICATION_CHANGED", Some("steam.exe"), None, "2026-10-01T10:00:00+05:30", "a1"),
            row("ACTIVE_APPLICATION_CHANGED", Some("steam.exe"), None, "2026-10-01T10:05:00+05:30", "a2"),
            row("BROWSER_ACTIVITY", Some("chrome"), Some("facebook.com"), "2026-10-01T10:10:00+05:30", "d1"),
            row("BROWSER_ACTIVITY", Some("chrome"), Some("m.facebook.com"), "2026-10-01T10:11:00+05:30", "d2"),
        ];
        let a = evaluate(&rules, &rows);
        // one per blocked app + one per blocked domain (deduped)
        assert_eq!(a.iter().filter(|x| x.kind == "blocked_app").count(), 1);
        assert_eq!(a.iter().filter(|x| x.kind == "blocked_domain").count(), 1);
    }

    #[test]
    fn after_hours_once_per_day() {
        let rules = AlertRules {
            usb_connect: false,
            integrity_failure: false,
            blocked_apps: vec![],
            blocked_domains: vec![],
            after_hours: Some(AfterHours { work_start_hour: 9, work_end_hour: 18 }), usb_file_copy: false, document_printed: false, usb_daily_mb_limit: 0,
        };
        let rows = vec![
            row("ACTIVE_APPLICATION_CHANGED", Some("code.exe"), None, "2026-10-01T22:00:00+05:30", "n1"),
            row("ACTIVE_APPLICATION_CHANGED", Some("code.exe"), None, "2026-10-01T23:00:00+05:30", "n2"),
            row("ACTIVE_APPLICATION_CHANGED", Some("code.exe"), None, "2026-10-02T02:00:00+05:30", "n3"),
            row("ACTIVE_APPLICATION_CHANGED", Some("code.exe"), None, "2026-10-02T12:00:00+05:30", "day"),
        ];
        let a = evaluate(&rules, &rows);
        let ah: Vec<_> = a.iter().filter(|x| x.kind == "after_hours").collect();
        assert_eq!(ah.len(), 2); // one for Oct-01, one for Oct-02; the 12:00 is in-hours
    }
}
