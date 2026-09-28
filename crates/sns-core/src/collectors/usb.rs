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

/// A USB device of any class, identified from its device-instance id (spec §16).
/// Metadata only — no file contents are ever read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsbDeviceInfo {
    pub instance_id: String,        // e.g. USB\VID_0781&PID_5591\4C531001...
    pub vendor_id: Option<String>,  // "0781"
    pub product_id: Option<String>, // "5591"
    pub serial: Option<String>,     // device serial, if the instance id carries a real one
    pub description: Option<String>,// friendly name / device description
}

/// Parse VID / PID / serial out of a USB device-instance id. Pure + unit-tested.
/// Format: `USB\VID_xxxx&PID_yyyy\<serial-or-bus-generated>`. A trailing segment that
/// contains `&` is a bus-generated id (not a real device serial) → serial = None.
pub fn parse_instance_id(id: &str) -> (Option<String>, Option<String>, Option<String>) {
    let up = id.to_ascii_uppercase();
    let grab = |key: &str| -> Option<String> {
        up.find(key).map(|i| {
            up[i + key.len()..].chars().take(4).collect::<String>()
        }).filter(|s| s.len() == 4 && s.chars().all(|c| c.is_ascii_hexdigit()))
    };
    let vid = grab("VID_");
    let pid = grab("PID_");
    let serial = id.rsplit('\\').next().filter(|s| !s.is_empty() && !s.contains('&')).map(|s| s.to_string());
    (vid, pid, serial)
}

/// Diff USB device sets keyed by instance id → (arrivals, removals).
pub fn diff_devices(prev: &[UsbDeviceInfo], cur: &[UsbDeviceInfo]) -> (Vec<UsbDeviceInfo>, Vec<UsbDeviceInfo>) {
    let has = |set: &[UsbDeviceInfo], id: &str| set.iter().any(|x| x.instance_id == id);
    let arrivals = cur.iter().filter(|c| !has(prev, &c.instance_id)).cloned().collect();
    let removals = prev.iter().filter(|p| !has(cur, &p.instance_id)).cloned().collect();
    (arrivals, removals)
}

/// All USB devices currently present (any class), with identity.
#[cfg(windows)]
pub fn list_usb_devices() -> Vec<UsbDeviceInfo> {
    win_dev::list()
}

#[cfg(not(windows))]
pub fn list_usb_devices() -> Vec<UsbDeviceInfo> {
    Vec::new()
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

#[cfg(windows)]
mod win_dev {
    use super::{parse_instance_id, UsbDeviceInfo};
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
        SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
        SetupDiGetDeviceInstanceIdW, SetupDiGetDeviceRegistryPropertyW, SP_DEVINFO_DATA,
        DIGCF_ALLCLASSES, DIGCF_PRESENT,
    };

    const SPDRP_DEVICEDESC: u32 = 0x0;
    const SPDRP_FRIENDLYNAME: u32 = 0xC;

    fn widestr(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    unsafe fn prop(hdev: isize, data: *const SP_DEVINFO_DATA, id: u32) -> Option<String> {
        let mut buf = [0u8; 1024];
        let mut req = 0u32;
        let mut ty = 0u32;
        let ok = SetupDiGetDeviceRegistryPropertyW(hdev, data, id, &mut ty, buf.as_mut_ptr(), buf.len() as u32, &mut req);
        if ok == 0 || req == 0 {
            return None;
        }
        let n = (req as usize / 2).min(buf.len() / 2);
        let wide = std::slice::from_raw_parts(buf.as_ptr() as *const u16, n);
        let s = widestr(wide);
        if s.is_empty() { None } else { Some(s) }
    }

    pub fn list() -> Vec<UsbDeviceInfo> {
        let mut out = Vec::new();
        unsafe {
            let enumerator: Vec<u16> = "USB\0".encode_utf16().collect();
            // Null ClassGuid + a specific enumerator requires DIGCF_ALLCLASSES.
            let hdev = SetupDiGetClassDevsW(std::ptr::null(), enumerator.as_ptr(), std::ptr::null_mut(), DIGCF_PRESENT | DIGCF_ALLCLASSES);
            // HDEVINFO is an isize handle; INVALID_HANDLE_VALUE == -1.
            if hdev == -1 || hdev == 0 {
                return out;
            }
            let mut idx = 0u32;
            loop {
                let mut data: SP_DEVINFO_DATA = std::mem::zeroed();
                data.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;
                if SetupDiEnumDeviceInfo(hdev, idx, &mut data) == 0 {
                    break;
                }
                idx += 1;

                let mut idbuf = [0u16; 512];
                let mut req = 0u32;
                let instance_id = if SetupDiGetDeviceInstanceIdW(hdev, &data, idbuf.as_mut_ptr(), idbuf.len() as u32, &mut req) != 0 {
                    widestr(&idbuf)
                } else {
                    continue;
                };
                let description = prop(hdev, &data, SPDRP_FRIENDLYNAME).or_else(|| prop(hdev, &data, SPDRP_DEVICEDESC));
                let (vendor_id, product_id, serial) = parse_instance_id(&instance_id);
                out.push(UsbDeviceInfo { instance_id, vendor_id, product_id, serial, description });
            }
            SetupDiDestroyDeviceInfoList(hdev);
        }
        out
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

    #[test]
    fn parse_instance_id_extracts_vid_pid_serial() {
        let (v, p, s) = parse_instance_id(r"USB\VID_0781&PID_5591\4C531001234567");
        assert_eq!(v.as_deref(), Some("0781"));
        assert_eq!(p.as_deref(), Some("5591"));
        assert_eq!(s.as_deref(), Some("4C531001234567"));
    }

    #[test]
    fn parse_instance_id_bus_generated_serial_is_none() {
        // Trailing "&"-containing segment is bus-generated, not a real serial.
        let (v, p, s) = parse_instance_id(r"USB\VID_046D&PID_C534\5&2ab1c3d&0&1");
        assert_eq!(v.as_deref(), Some("046D"));
        assert_eq!(p.as_deref(), Some("C534"));
        assert_eq!(s, None);
    }

    #[test]
    fn parse_instance_id_no_vid() {
        let (v, p, _) = parse_instance_id(r"USB\ROOT_HUB30\4&12ab&0");
        assert_eq!(v, None);
        assert_eq!(p, None);
    }

    fn di(id: &str) -> UsbDeviceInfo {
        UsbDeviceInfo { instance_id: id.into(), vendor_id: None, product_id: None, serial: None, description: None }
    }

    #[test]
    fn device_diff_by_instance_id() {
        let prev = vec![di("USB\\A")];
        let cur = vec![di("USB\\A"), di("USB\\B")];
        let (arr, rem) = diff_devices(&prev, &cur);
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0].instance_id, "USB\\B");
        assert!(rem.is_empty());
    }

    /// Live enumeration smoke — must not panic. Ignored by default.
    /// Run: `cargo test -p sns-core --lib -- --ignored usb_live`
    #[test]
    #[ignore]
    fn usb_live() {
        eprintln!("removable drives: {}", list_removable().len());
        let devs = list_usb_devices();
        eprintln!("usb devices: {}", devs.len());
        for d in devs.iter().take(8) {
            eprintln!("  {} vid={:?} pid={:?} serial={:?} desc={:?}", d.instance_id, d.vendor_id, d.product_id, d.serial, d.description);
        }
    }
}
