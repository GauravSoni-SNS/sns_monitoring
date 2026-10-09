//! Unix (Linux + macOS) platform layer for the collectors. The shared event/storage/sync/crypto
//! core is already cross-platform; this module provides the OS-specific captures that the Win32
//! code provides on Windows, so the agent has feature parity on Linux and macOS.
//!
//! DESIGN NOTES
//! - Low overhead: the frequent probes (foreground window, idle) are tiny, short-lived reads;
//!   screenshots run only on the configured interval (default 15 min). Per-second probes use
//!   lightweight system queries, and callers throttle heavier work.
//! - macOS requires the user to grant **Screen Recording** and **Accessibility** permission
//!   (TCC) — this cannot be silent. The installer opens the permission panes; until granted,
//!   screenshot/foreground capture return empty (graceful degradation), the agent keeps running.
//! - Linux Wayland restricts screen/window capture; we use the Wayland-friendly `grim`/portal
//!   path when present and fall back to X11 tools. Where a capture is unavailable, we degrade
//!   gracefully rather than failing.
//!
//! This layer shells out to standard, always-present OS utilities to avoid heavy native
//! dependencies (keeps the binary small). A later optimization can replace the hottest probes
//! (foreground, idle) with direct native library calls (libXss / CoreGraphics) — noted inline.
#![cfg(unix)]

use std::process::Command;

use crate::collectors::application::ForegroundSample;
use crate::collectors::print::PrintJob;
use crate::collectors::usb::{UsbDevice, UsbDeviceInfo};
use crate::collectors::usbfiles::UsbSnapshot;

/// Run a command and capture stdout as a trimmed String; None on failure/empty.
fn cmd(bin: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(bin).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

// =============================== foreground app ===============================

/// The focused application's process name + window title.
pub fn foreground_sample() -> Option<ForegroundSample> {
    #[cfg(target_os = "macos")]
    {
        // Frontmost app name via AppleScript (needs Accessibility permission for titles).
        let app = cmd(
            "osascript",
            &["-e", "tell application \"System Events\" to get name of first application process whose frontmost is true"],
        )?;
        let title = cmd(
            "osascript",
            &["-e", "tell application \"System Events\" to tell (first application process whose frontmost is true) to try
                     get value of attribute \"AXTitle\" of window 1
                   end try"],
        );
        Some(ForegroundSample { process_name: app, window_title: title.filter(|t| !t.is_empty()) })
    }
    #[cfg(target_os = "linux")]
    {
        // X11: active window id → pid/name/title via xdotool (Wayland: limited, degrades).
        let win = cmd("xdotool", &["getactivewindow"])?;
        let title = cmd("xdotool", &["getwindowname", &win]);
        let pid = cmd("xdotool", &["getwindowpid", &win]);
        let process_name = pid
            .and_then(|p| std::fs::read_to_string(format!("/proc/{p}/comm")).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".into());
        Some(ForegroundSample { process_name, window_title: title })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

// ============================== browser URL =================================

/// The URL/domain shown in the foreground browser's address bar (on-screen only; never
/// history/stores). macOS: AppleScript reads the active tab URL (needs Automation permission).
/// Linux: no reliable address-bar read without a browser extension/AT-SPI — returns None
/// (degrades; the window-title fallback is intentionally not used, as a title is not a URL).
pub fn foreground_browser_url() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let app = foreground_sample()?.process_name.to_ascii_lowercase();
        let script: String = if app.contains("safari") {
            "tell application \"Safari\" to get URL of front document".to_string()
        } else if app.contains("chrome") || app.contains("chromium") || app.contains("brave") || app.contains("edge") {
            let name = if app.contains("edge") { "Microsoft Edge" }
                else if app.contains("brave") { "Brave Browser" }
                else if app.contains("chromium") { "Chromium" }
                else { "Google Chrome" };
            format!("tell application \"{name}\" to get URL of active tab of front window")
        } else {
            return None;
        };
        let url = cmd("osascript", &["-e", &script])?;
        if url.is_empty() { None } else { Some(url) }
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

// =================================== idle ====================================

/// Seconds since the last user input (keyboard/mouse). 0 if unavailable (treated as active).
pub fn idle_seconds() -> u64 {
    #[cfg(target_os = "macos")]
    {
        // HIDIdleTime is nanoseconds since last HID event.
        if let Some(out) = cmd("sh", &["-c", "ioreg -c IOHIDSystem | awk '/HIDIdleTime/ {print $NF; exit}'"]) {
            if let Ok(ns) = out.trim().parse::<u128>() {
                return (ns / 1_000_000_000) as u64;
            }
        }
        0
    }
    #[cfg(target_os = "linux")]
    {
        // xprintidle returns milliseconds idle (X11). Wayland: not available → 0 (active).
        if let Some(ms) = cmd("xprintidle", &[]) {
            if let Ok(v) = ms.trim().parse::<u64>() {
                return v / 1000;
            }
        }
        0
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        0
    }
}

// ================================ screenshot =================================

/// Capture the primary screen as PNG bytes. Empty vec if capture is unavailable (no
/// permission / headless / Wayland without portal) — caller then stores nothing.
pub fn capture_screen_png(_max_dimension: u32) -> Vec<u8> {
    let tmp = std::env::temp_dir().join(format!("sns-shot-{}.png", std::process::id()));
    let path = tmp.to_string_lossy().to_string();
    let ok = {
        #[cfg(target_os = "macos")]
        {
            // -x: no sound, -t png. Needs Screen Recording permission.
            Command::new("screencapture").args(["-x", "-t", "png", &path]).status().map(|s| s.success()).unwrap_or(false)
        }
        #[cfg(target_os = "linux")]
        {
            // Try Wayland (grim) first, then X11 (scrot / imagemagick import).
            try_cmd("grim", &[&path])
                || try_cmd("scrot", &["-o", &path])
                || try_cmd("import", &["-window", "root", &path])
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            false
        }
    };
    if !ok {
        return Vec::new();
    }
    let bytes = std::fs::read(&tmp).unwrap_or_default();
    let _ = std::fs::remove_file(&tmp);
    bytes
}

#[allow(dead_code)]
fn try_cmd(bin: &str, args: &[&str]) -> bool {
    Command::new(bin).args(args).status().map(|s| s.success()).unwrap_or(false)
}

// ================================ usb devices ================================

/// Currently-connected USB devices (identity). Linux: lsusb; macOS: system_profiler.
pub fn list_usb_devices() -> Vec<UsbDeviceInfo> {
    let mut out = Vec::new();
    #[cfg(target_os = "linux")]
    {
        // lsusb line: "Bus 001 Device 004: ID 1bcf:08a0 Sunplus ... USB Optical Mouse"
        if let Some(text) = cmd("lsusb", &[]) {
            for line in text.lines() {
                if let Some(idx) = line.find("ID ") {
                    let rest = &line[idx + 3..];
                    let mut parts = rest.splitn(2, ' ');
                    let id = parts.next().unwrap_or("");
                    let desc = parts.next().unwrap_or("").trim().to_string();
                    let (vid, pid) = id.split_once(':').unwrap_or(("", ""));
                    out.push(UsbDeviceInfo {
                        instance_id: format!("USB\\VID_{}&PID_{}", vid.to_uppercase(), pid.to_uppercase()),
                        vendor_id: Some(vid.to_string()),
                        product_id: Some(pid.to_string()),
                        serial: None,
                        description: if desc.is_empty() { None } else { Some(desc) },
                    });
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        // Parse the human-readable system_profiler USB tree for product/vendor/serial lines.
        if let Some(text) = cmd("system_profiler", &["SPUSBDataType"]) {
            let mut cur = UsbDeviceInfo { instance_id: String::new(), vendor_id: None, product_id: None, serial: None, description: None };
            for line in text.lines() {
                let t = line.trim();
                if t.ends_with(':') && !t.contains("Product ID") && !t.contains("Vendor ID") && !t.contains("Serial") && !t.contains("USB") {
                    if cur.description.is_some() {
                        finalize_mac_usb(&mut out, &mut cur);
                    }
                    cur.description = Some(t.trim_end_matches(':').to_string());
                } else if let Some(v) = t.strip_prefix("Product ID:") {
                    cur.product_id = Some(v.trim().trim_start_matches("0x").to_string());
                } else if let Some(v) = t.strip_prefix("Vendor ID:") {
                    cur.vendor_id = Some(v.trim().split_whitespace().next().unwrap_or("").trim_start_matches("0x").to_string());
                } else if let Some(v) = t.strip_prefix("Serial Number:") {
                    cur.serial = Some(v.trim().to_string());
                }
            }
            if cur.description.is_some() {
                finalize_mac_usb(&mut out, &mut cur);
            }
        }
    }
    out
}

#[cfg(target_os = "macos")]
fn finalize_mac_usb(out: &mut Vec<UsbDeviceInfo>, cur: &mut UsbDeviceInfo) {
    let vid = cur.vendor_id.clone().unwrap_or_default();
    let pid = cur.product_id.clone().unwrap_or_default();
    cur.instance_id = format!("USB\\VID_{}&PID_{}", vid.to_uppercase(), pid.to_uppercase());
    out.push(cur.clone());
    *cur = UsbDeviceInfo { instance_id: String::new(), vendor_id: None, product_id: None, serial: None, description: None };
}

// ============================ removable (mass storage) =======================

/// Mounted removable volumes as (mount path, label) for connect/disconnect detection.
pub fn list_removable() -> Vec<UsbDevice> {
    let mut out = Vec::new();
    #[cfg(target_os = "macos")]
    {
        if let Ok(rd) = std::fs::read_dir("/Volumes") {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                out.push(UsbDevice { drive: format!("/Volumes/{name}"), label: Some(name) });
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        // Removable mounts typically under /media/<user>/<label> or /run/media/<user>/<label>.
        for base in ["/media", "/run/media"] {
            collect_mount_labels(base, &mut out);
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn collect_mount_labels(base: &str, out: &mut Vec<UsbDevice>) {
    if let Ok(users) = std::fs::read_dir(base) {
        for u in users.flatten() {
            if let Ok(vols) = std::fs::read_dir(u.path()) {
                for v in vols.flatten() {
                    let label = v.file_name().to_string_lossy().to_string();
                    out.push(UsbDevice { drive: v.path().to_string_lossy().to_string(), label: Some(label) });
                }
            }
        }
    }
}

/// Snapshot files (name + size) on removable volumes, for copy-to-USB detection.
pub fn snapshot_removable_files() -> UsbSnapshot {
    use crate::collectors::usbfiles::{DriveSnapshot, MAX_DEPTH, MAX_FILES_PER_DRIVE};
    let mut out = UsbSnapshot::new();
    for dev in list_removable() {
        let base = std::path::PathBuf::from(&dev.drive);
        let mut snap = DriveSnapshot::new();
        walk(&base, &base, 0, &mut snap, MAX_DEPTH, MAX_FILES_PER_DRIVE);
        out.insert(dev.drive, snap);
    }
    out
}

fn walk(
    base: &std::path::Path,
    dir: &std::path::Path,
    depth: usize,
    snap: &mut std::collections::HashMap<String, u64>,
    max_depth: usize,
    max_files: usize,
) {
    if depth > max_depth || snap.len() >= max_files {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        if snap.len() >= max_files {
            return;
        }
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            walk(base, &path, depth + 1, snap, max_depth, max_files);
        } else if ft.is_file() {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let rel = path.strip_prefix(base).unwrap_or(&path).to_string_lossy().to_string();
            snap.insert(rel, size);
        }
    }
}

// ================================ print jobs =================================

/// Current spooled print jobs (CUPS `lpstat`), both Linux and macOS.
pub fn current_print_jobs() -> Vec<PrintJob> {
    let mut out = Vec::new();
    // lpstat -o lists: "printer-123  user  1024  <date>"
    if let Some(text) = cmd("lpstat", &["-o"]) {
        for line in text.lines() {
            let mut f = line.split_whitespace();
            let job = f.next().unwrap_or("");
            if job.is_empty() {
                continue;
            }
            let printer = job.rsplitn(2, '-').nth(1).unwrap_or(job).to_string();
            let size_bytes = f.nth(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
            out.push(PrintJob {
                printer,
                document: job.to_string(),
                pages: 0,
                size_bytes,
                key: job.to_string(),
            });
        }
    }
    out
}

// ============================= installed apps ================================

/// Installed application display names (for transfer-app detection).
pub fn installed_app_names() -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        let mut names = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/Applications") {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                names.push(n.trim_end_matches(".app").to_string());
            }
        }
        names
    }
    #[cfg(target_os = "linux")]
    {
        let mut names = Vec::new();
        // dpkg (Debian/Ubuntu) package names.
        if let Some(text) = cmd("dpkg-query", &["-W", "-f=${Package}\\n"]) {
            names.extend(text.lines().map(|s| s.to_string()));
        }
        // rpm (Fedora/RHEL) if present.
        if let Some(text) = cmd("rpm", &["-qa", "--qf", "%{NAME}\\n"]) {
            names.extend(text.lines().map(|s| s.to_string()));
        }
        names
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Vec::new()
    }
}
