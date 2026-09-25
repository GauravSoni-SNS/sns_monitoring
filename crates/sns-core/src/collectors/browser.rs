//! Browser activity collector (spec §18). Records browser, domain (default granularity),
//! timestamp, and duration. Does NOT extract passwords, cookies, tokens, or recover deleted
//! history (spec §1, §18). Activity is captured as it happens, not by reading the browser's
//! own stores as a source of truth.
//!
//! The platform signal is the foreground browser window/tab title/URL surfaced by the OS
//! accessibility/window APIs (next build step). The domain-extraction + event logic below
//! is final and unit-tested.

use sns_shared::events::{ActivityEvent, EventType};
use sns_shared::ids::new_event_id;

use crate::clock::now_utc_iso;
use crate::collectors::Collector;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granularity {
    Domain,
    Url,
}

pub struct BrowserCollector {
    device_id: String,
    granularity: Granularity,
}

impl BrowserCollector {
    pub fn new(device_id: &str, granularity: Granularity) -> Self {
        Self { device_id: device_id.to_string(), granularity }
    }

    /// Build a BROWSER_ACTIVITY event from an observed navigation. `raw_url` may be a full
    /// URL or already a domain; we reduce to domain unless URL granularity is configured.
    pub fn build_event(&self, browser: &str, raw_url: &str) -> ActivityEvent {
        let value = match self.granularity {
            Granularity::Domain => extract_domain(raw_url).unwrap_or_else(|| raw_url.to_string()),
            Granularity::Url => raw_url.to_string(),
        };
        let meta = serde_json::json!({ "browser": browser }).to_string();
        ActivityEvent {
            event_id: new_event_id(),
            device_id: self.device_id.clone(),
            event_type: EventType::BrowserActivity,
            timestamp_utc: now_utc_iso(),
            application_name: Some(browser.to_string()),
            process_name: Some(browser.to_string()),
            window_title: Some(value),
            metadata_json: Some(meta),
        }
    }
}

impl Collector for BrowserCollector {
    fn name(&self) -> &'static str {
        "browser"
    }

    fn poll(&mut self) -> Result<Vec<ActivityEvent>> {
        // TODO(build step 7): read foreground browser tab (Chrome/Edge/Firefox) via
        // UI Automation; feed into build_event. No history/credential access.
        Ok(vec![])
    }
}

/// Reduce a URL to its host/domain. Strips scheme, userinfo, port, path, query.
/// Returns None if no host can be found.
pub fn extract_domain(raw: &str) -> Option<String> {
    let after_scheme = raw.split_once("://").map(|(_, r)| r).unwrap_or(raw);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // drop userinfo@
    let host_port = authority.rsplit_once('@').map(|(_, r)| r).unwrap_or(authority);
    // drop :port
    let host = host_port.split(':').next().unwrap_or(host_port);
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_extraction() {
        assert_eq!(extract_domain("https://mail.google.com/mail/u/0"), Some("mail.google.com".into()));
        assert_eq!(extract_domain("http://user:pass@Example.COM:8080/x?y"), Some("example.com".into()));
        assert_eq!(extract_domain("example.org/path"), Some("example.org".into()));
        assert_eq!(extract_domain(""), None);
    }

    #[test]
    fn domain_granularity_drops_path() {
        let c = BrowserCollector::new("dev_T", Granularity::Domain);
        let ev = c.build_event("chrome", "https://github.com/anthropics/secret-repo");
        assert_eq!(ev.window_title.as_deref(), Some("github.com")); // no path retained
        assert_eq!(ev.event_type, EventType::BrowserActivity);
    }

    #[test]
    fn url_granularity_keeps_full() {
        let c = BrowserCollector::new("dev_T", Granularity::Url);
        let ev = c.build_event("edge", "https://x.com/page?q=1");
        assert_eq!(ev.window_title.as_deref(), Some("https://x.com/page?q=1"));
    }
}
