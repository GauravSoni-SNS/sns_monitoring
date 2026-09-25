//! USB mass-storage detection (spec §16). Polls removable drives and diffs the set to emit
//! USB_DEVICE_CONNECTED / USB_DEVICE_DISCONNECTED. Records only drive letter + volume label
//! — never reads, copies, or inspects file contents (spec §16). Storage devices are the
//! data-exfiltration-relevant case; broader device-class enumeration is a later refinement.

use serde::Serialize;

/// A removable volume currently present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsbDevice {
    pub drive: String,          // e.g. "E:"
    pub label: Option<String>,  // volume label if available
}

/// Diff previous vs current removable set (keyed by drive letter).
/// Returns (arrivals, removals). Pure + testable.
pub fn diff(prev: &[UsbDevice], cur: &[UsbDevice]) -> (Vec<UsbDevice>, Vec<UsbDevice>) {
    let has = |set: &[UsbDevice], d: &str| set.iter().any(|x| x.drive == d);
    let arrivals = cur.iter().filter(|c| !has(prev, &c.drive)).cloned().collect();
    let removals = prev.iter().filter(|p| !has(cur, &p.drive)).cloned().collect();
    (arrivals, removals)
}

/// Current removable (USB mass-storage) volumes.
#[cfg(windows)]
pub fn list_removable() -> Vec<UsbDevice> {
    win::list()
}

#[cfg(not(windows))]
pub fn list_removable() -> Vec<UsbDevice> {
    Vec::new()
}

#[cfg(windows)]
mod win {
    use super::UsbDevice;
    use windows_sys::Win32::Storage::FileSystem::{
        GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW,
    };

    // GetDriveTypeW return value for removable media (DRIVE_REMOVABLE); windows-sys does
    // not export the named constant.
    const DRIVE_REMOVABLE: u32 = 2;

    pub fn list() -> Vec<UsbDevice> {
        let mut out = Vec::new();
        let mask = unsafe { GetLogicalDrives() };
        if mask == 0 {
            return out;
        }
        for i in 0..26u32 {
            if mask & (1 << i) == 0 {
                continue;
            }
            let letter = (b'A' + i as u8) as char;
            // "X:\" as a wide, NUL-terminated string.
            let root: Vec<u16> = format!("{letter}:\\").encode_utf16().chain(std::iter::once(0)).collect();
            let dtype = unsafe { GetDriveTypeW(root.as_ptr()) };
            if dtype != DRIVE_REMOVABLE {
                continue;
            }
            out.push(UsbDevice {
                drive: format!("{letter}:"),
                label: volume_label(&root),
            });
        }
        out
    }

    fn volume_label(root: &[u16]) -> Option<String> {
        let mut name = [0u16; 128];
        let ok = unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                name.as_mut_ptr(),
                name.len() as u32,
                std::ptr::null_mut(), // serial
                std::ptr::null_mut(), // max component len
                std::ptr::null_mut(), // fs flags
                std::ptr::null_mut(), // fs name
                0,
            )
        };
        if ok == 0 {
            return None;
        }
        let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        let label = String::from_utf16_lossy(&name[..end]);
        if label.is_empty() { None } else { Some(label) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(d: &str) -> UsbDevice {
        UsbDevice { drive: d.into(), label: None }
    }

    #[test]
    fn diff_detects_arrival_and_removal() {
        let prev = vec![dev("E:")];
        let cur = vec![dev("E:"), dev("F:")];
        let (arr, rem) = diff(&prev, &cur);
        assert_eq!(arr, vec![dev("F:")]);
        assert!(rem.is_empty());

        let (arr2, rem2) = diff(&cur, &prev);
        assert!(arr2.is_empty());
        assert_eq!(rem2, vec![dev("F:")]);
    }

    #[test]
    fn no_change_no_events() {
        let s = vec![dev("E:")];
        let (a, r) = diff(&s, &s);
        assert!(a.is_empty() && r.is_empty());
    }

    /// Live enumeration smoke test — must not panic. Ignored by default.
    /// Run: `cargo test -p sns-core --lib -- --ignored usb_live`
    #[test]
    #[ignore]
    fn usb_live() {
        let list = list_removable();
        eprintln!("removable drives: {}", list.len());
        for d in &list {
            eprintln!("  {} {:?}", d.drive, d.label);
        }
    }
}
