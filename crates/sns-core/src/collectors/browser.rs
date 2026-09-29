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
        // The user-session agent drives browser capture directly via `build_event` fed by
        // `foreground_browser_url`; this collector path is unused there.
        Ok(vec![])
    }
}

/// Read the **foreground** browser window's address-bar text (URL/host) via UI Automation.
///
/// This is live, on-screen observation — the same surface a screenshot shows — so it
/// naturally covers whatever mode is currently visible (normal, guest, private). It is NOT
/// history recovery and NOT reading the browser's private stores/cookies/credentials: it
/// only reads the value already painted in the visible address bar. Returns `None` when the
/// foreground window is not a browser, has no readable address bar, or UIA is unavailable.
#[cfg(windows)]
pub fn foreground_browser_url() -> Option<String> {
    win_uia::address_bar_url()
}

#[cfg(not(windows))]
pub fn foreground_browser_url() -> Option<String> {
    None
}

/// Heuristic: does this address-bar value look like a site (URL/host) rather than a typed
/// search query? Accepts scheme-bearing values (`https://`, `chrome://`), `localhost`, and
/// any dotted host token. Rejects empty/whitespace-bearing text (typed searches).
pub fn looks_like_site(raw: &str) -> bool {
    let s = raw.trim();
    if s.is_empty() || s.contains(char::is_whitespace) {
        return false;
    }
    if s.contains("://") {
        return true;
    }
    let host = s.split(['/', '?', '#']).next().unwrap_or(s);
    let host = host.split(':').next().unwrap_or(host); // drop :port
    host.eq_ignore_ascii_case("localhost") || host.contains('.')
}

#[cfg(windows)]
mod win_uia {
    use std::cell::RefCell;

    use windows::core::Interface;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
    };
    use windows::Win32::System::Variant::VARIANT;
    use windows::Win32::UI::Accessibility::{
        CUIAutomation, IUIAutomation, IUIAutomationValuePattern, TreeScope_Descendants,
        UIA_ControlTypePropertyId, UIA_EditControlTypeId, UIA_ValuePatternId,
    };
    use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

    thread_local! {
        static UIA: RefCell<Option<IUIAutomation>> = const { RefCell::new(None) };
    }

    /// Cached per-thread UI Automation client (COM initialized MTA once per thread).
    fn automation() -> Option<IUIAutomation> {
        UIA.with(|cell| {
            if let Some(a) = cell.borrow().as_ref() {
                return Some(a.clone());
            }
            unsafe {
                // Ignore RPC_E_CHANGED_MODE if COM is already initialized on this thread.
                let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
                match CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) {
                    Ok(a) => {
                        *cell.borrow_mut() = Some(a);
                        cell.borrow().clone()
                    }
                    Err(_) => None,
                }
            }
        })
    }

    pub fn address_bar_url() -> Option<String> {
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0.is_null() {
                return None;
            }
            let uia = automation()?;
            let root = uia.ElementFromHandle(hwnd).ok()?;

            // Find edit controls in the window; the address bar is an Edit exposing a
            // ValuePattern whose value is the current URL/host.
            let cond = uia
                .CreatePropertyCondition(
                    UIA_ControlTypePropertyId,
                    &VARIANT::from(UIA_EditControlTypeId.0),
                )
                .ok()?;
            let edits = root.FindAll(TreeScope_Descendants, &cond).ok()?;
            let count = edits.Length().ok()?;

            for i in 0..count {
                let Ok(el) = edits.GetElement(i) else { continue };
                let Ok(unknown) = el.GetCurrentPattern(UIA_ValuePatternId) else { continue };
                let Ok(vp) = unknown.cast::<IUIAutomationValuePattern>() else { continue };
                let Ok(bstr) = vp.CurrentValue() else { continue };
                let value = bstr.to_string();
                if super::looks_like_site(&value) {
                    return Some(value);
                }
            }
            None
        }
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
    fn site_heuristic() {
        assert!(looks_like_site("github.com/anthropics"));
        assert!(looks_like_site("https://x.com/page?q=1"));
        assert!(looks_like_site("chrome://settings"));
        assert!(looks_like_site("localhost:7731"));
        assert!(!looks_like_site("how to build a service")); // typed search
        assert!(!looks_like_site("")); // empty
        assert!(!looks_like_site("   ")); // whitespace only
    }

    #[test]
    fn url_granularity_keeps_full() {
        let c = BrowserCollector::new("dev_T", Granularity::Url);
        let ev = c.build_event("edge", "https://x.com/page?q=1");
        assert_eq!(ev.window_title.as_deref(), Some("https://x.com/page?q=1"));
    }
}
