//! Application / active-window collector (spec §17).
//!
//! Collects: process name, active application, active window title (policy-gated),
//! start/stop, and focus changes. Does NOT collect keystrokes, passwords, auth secrets,
//! or clipboard (spec §17).
//!
//! Win32 capture (`GetForegroundWindow` → `GetWindowThreadProcessId` →
//! `QueryFullProcessImageName` → `GetWindowText`) is the next build step. The event-shape
//! logic below is final and unit-tested; `poll` currently returns no events until the
//! Win32 body lands (tracked in BUILD-STATUS.md).

use sns_shared::events::{ActivityEvent, EventType};
use sns_shared::ids::new_event_id;

use crate::clock::now_utc_iso;
use crate::collectors::Collector;
use crate::error::Result;

/// A foreground-window sample from the platform layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundSample {
    pub process_name: String,
    pub window_title: Option<String>,
}

pub struct ApplicationCollector {
    device_id: String,
    capture_window_title: bool,
    last: Option<ForegroundSample>,
}

impl ApplicationCollector {
    pub fn new(device_id: &str, capture_window_title: bool) -> Self {
        Self { device_id: device_id.to_string(), capture_window_title, last: None }
    }

    /// Diff a new foreground sample against the previous one and emit the appropriate
    /// event(s). Pure + testable; the Win32 layer feeds `sample` into this.
    pub fn on_sample(&mut self, sample: ForegroundSample) -> Vec<ActivityEvent> {
        if self.last.as_ref() == Some(&sample) {
            return vec![]; // no focus change
        }
        let title = if self.capture_window_title { sample.window_title.clone() } else { None };
        let event = ActivityEvent {
            event_id: new_event_id(),
            device_id: self.device_id.clone(),
            event_type: EventType::ActiveApplicationChanged,
            timestamp_utc: now_utc_iso(),
            application_name: Some(sample.process_name.clone()),
            process_name: Some(sample.process_name.clone()),
            window_title: title,
            metadata_json: None,
        };
        self.last = Some(sample);
        vec![event]
    }

    /// Platform foreground sampler.
    fn sample_foreground(&self) -> Option<ForegroundSample> {
        foreground_sample()
    }
}

/// Best-known browser process names (lowercased). Used to also emit BROWSER_ACTIVITY.
pub fn is_browser_process(process_name: &str) -> Option<&'static str> {
    match process_name.to_ascii_lowercase().as_str() {
        "chrome.exe" => Some("chrome"),
        "msedge.exe" => Some("edge"),
        "firefox.exe" => Some("firefox"),
        _ => None,
    }
}

/// Sample the current foreground window's process + title. `None` if there is no
/// foreground window (e.g. session 0, or a secure desktop). Never reads window contents,
/// keystrokes, or clipboard — only the process image name and the window caption.
#[cfg(windows)]
pub fn foreground_sample() -> Option<ForegroundSample> {
    win::sample()
}

#[cfg(not(windows))]
pub fn foreground_sample() -> Option<ForegroundSample> {
    None
}

#[cfg(windows)]
mod win {
    use super::ForegroundSample;
    use windows_sys::Win32::Foundation::{CloseHandle, HWND};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
    };

    pub fn sample() -> Option<ForegroundSample> {
        unsafe {
            let hwnd: HWND = GetForegroundWindow();
            if hwnd.is_null() {
                return None;
            }
            let mut pid: u32 = 0;
            GetWindowThreadProcessId(hwnd, &mut pid);
            if pid == 0 {
                return None;
            }
            let process_name = process_image_name(pid)?;
            let window_title = window_text(hwnd);
            Some(ForegroundSample { process_name, window_title })
        }
    }

    unsafe fn window_text(hwnd: HWND) -> Option<String> {
        let len = GetWindowTextLengthW(hwnd);
        if len <= 0 {
            return None;
        }
        let mut buf = vec![0u16; len as usize + 1];
        let n = GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
        if n <= 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..n as usize]))
    }

    unsafe fn process_image_name(pid: u32) -> Option<String> {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 4096];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut size);
        CloseHandle(h);
        if ok == 0 || size == 0 {
            return None;
        }
        let full = String::from_utf16_lossy(&buf[..size as usize]);
        // Keep just the executable file name, e.g. "chrome.exe".
        Some(full.rsplit(['\\', '/']).next().unwrap_or(&full).to_string())
    }
}

impl Collector for ApplicationCollector {
    fn name(&self) -> &'static str {
        "application"
    }

    fn poll(&mut self) -> Result<Vec<ActivityEvent>> {
        Ok(match self.sample_foreground() {
            Some(s) => self.on_sample(s),
            None => vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(proc: &str, title: &str) -> ForegroundSample {
        ForegroundSample { process_name: proc.into(), window_title: Some(title.into()) }
    }

    #[test]
    fn emits_only_on_focus_change() {
        let mut c = ApplicationCollector::new("dev_T", true);
        assert_eq!(c.on_sample(s("chrome.exe", "Gmail")).len(), 1);
        // Same sample again → no event.
        assert_eq!(c.on_sample(s("chrome.exe", "Gmail")).len(), 0);
        // Different app → event.
        let ev = c.on_sample(s("code.exe", "main.rs"));
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].event_type, EventType::ActiveApplicationChanged);
        assert_eq!(ev[0].process_name.as_deref(), Some("code.exe"));
    }

    #[test]
    fn window_title_suppressed_when_policy_off() {
        let mut c = ApplicationCollector::new("dev_T", false);
        let ev = c.on_sample(s("chrome.exe", "Secret Doc"));
        assert!(ev[0].window_title.is_none());
    }
}
