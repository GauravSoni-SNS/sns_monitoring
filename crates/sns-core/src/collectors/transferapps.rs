//! Installed data-transfer app detection (exfil). Scans the Windows "installed programs"
//! registry and flags known data-movement tools — remote access, P2P/torrent, cloud sync,
//! messaging with file transfer, and dedicated send tools. These are the apps a user could
//! use to move company data off the device.
//!
//! BOUNDARY: reads only the list of installed program names from the registry. It does not
//! read any app's data, traffic, or transfer contents (those are not accessible without a
//! network/kernel driver — out of scope). This is "what risky tools are present", not "what
//! was transferred".

use serde::Serialize;

/// A detected transfer-capable application.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TransferApp {
    pub name: String,
    pub category: String,
}

/// Known-tool signatures: (lowercase substring in the program name, category).
const SIGNATURES: &[(&str, &str)] = &[
    // Remote access / remote control
    ("anydesk", "remote-access"),
    ("teamviewer", "remote-access"),
    ("rustdesk", "remote-access"),
    ("ultraviewer", "remote-access"),
    ("ammyy", "remote-access"),
    ("remote desktop", "remote-access"),
    ("vnc", "remote-access"),
    ("splashtop", "remote-access"),
    // P2P / torrent
    ("utorrent", "torrent"),
    ("bittorrent", "torrent"),
    ("qbittorrent", "torrent"),
    ("transmission", "torrent"),
    ("vuze", "torrent"),
    ("tixati", "torrent"),
    // Cloud sync / storage
    ("dropbox", "cloud-sync"),
    ("google drive", "cloud-sync"),
    ("backup and sync", "cloud-sync"),
    ("onedrive", "cloud-sync"),
    ("mega", "cloud-sync"),
    ("box sync", "cloud-sync"),
    ("box drive", "cloud-sync"),
    ("icloud", "cloud-sync"),
    ("pcloud", "cloud-sync"),
    ("sync.com", "cloud-sync"),
    // Messaging with file transfer
    ("telegram", "messaging"),
    ("whatsapp", "messaging"),
    ("signal", "messaging"),
    ("skype", "messaging"),
    // Dedicated send / file-transfer tools
    ("shareit", "file-transfer"),
    ("feem", "file-transfer"),
    ("send anywhere", "file-transfer"),
    ("filezilla", "file-transfer"),
    ("winscp", "file-transfer"),
    ("resilio", "file-transfer"),
    ("syncthing", "file-transfer"),
];

/// Classify a program display name → category, if it matches a known transfer tool.
pub fn classify(display_name: &str) -> Option<&'static str> {
    let n = display_name.to_ascii_lowercase();
    SIGNATURES.iter().find(|(sig, _)| n.contains(sig)).map(|(_, cat)| *cat)
}

/// Scan installed programs and return the transfer-capable ones found. Non-Windows: empty.
#[cfg(windows)]
pub fn scan_installed() -> Vec<TransferApp> {
    let mut out: Vec<TransferApp> = Vec::new();
    for name in win::installed_display_names() {
        if let Some(cat) = classify(&name) {
            if !out.iter().any(|a| a.name.eq_ignore_ascii_case(&name)) {
                out.push(TransferApp { name, category: cat.to_string() });
            }
        }
    }
    out.sort_by(|a, b| a.category.cmp(&b.category).then(a.name.cmp(&b.name)));
    out
}

#[cfg(not(windows))]
pub fn scan_installed() -> Vec<TransferApp> {
    let mut out: Vec<TransferApp> = Vec::new();
    for name in crate::collectors::platform_unix::installed_app_names() {
        if let Some(cat) = classify(&name) {
            if !out.iter().any(|a| a.name.eq_ignore_ascii_case(&name)) {
                out.push(TransferApp { name, category: cat.to_string() });
            }
        }
    }
    out.sort_by(|a, b| a.category.cmp(&b.category).then(a.name.cmp(&b.name)));
    out
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
        REG_SAM_FLAGS,
    };

    const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn widestr(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    /// Read every subkey's "DisplayName" under the three standard uninstall locations
    /// (HKLM 64-bit, HKLM 32-bit WOW, HKCU).
    pub fn installed_display_names() -> Vec<String> {
        let mut names = Vec::new();
        let roots: [(HKEY, REG_SAM_FLAGS); 3] = [
            (HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY),
            (HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY),
            (HKEY_CURRENT_USER, 0),
        ];
        for (root, wow) in roots {
            collect_from(root, wow, &mut names);
        }
        names
    }

    fn collect_from(root: HKEY, wow: REG_SAM_FLAGS, out: &mut Vec<String>) {
        unsafe {
            let mut hkey: HKEY = std::ptr::null_mut();
            let path = wide(UNINSTALL);
            if RegOpenKeyExW(root, path.as_ptr(), 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | wow, &mut hkey) != ERROR_SUCCESS {
                return;
            }
            let mut index = 0u32;
            loop {
                let mut name_buf = [0u16; 256];
                let mut name_len = name_buf.len() as u32;
                let r = RegEnumKeyExW(
                    hkey, index, name_buf.as_mut_ptr(), &mut name_len,
                    std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
                );
                if r != ERROR_SUCCESS {
                    break;
                }
                index += 1;
                let subname = widestr(&name_buf[..name_len as usize]);
                if let Some(dn) = read_display_name(hkey, &subname, wow) {
                    out.push(dn);
                }
            }
            RegCloseKey(hkey);
        }
    }

    unsafe fn read_display_name(parent: HKEY, subkey: &str, wow: REG_SAM_FLAGS) -> Option<String> {
        let mut sub: HKEY = std::ptr::null_mut();
        let sk = wide(subkey);
        if RegOpenKeyExW(parent, sk.as_ptr(), 0, KEY_READ | wow, &mut sub) != ERROR_SUCCESS {
            return None;
        }
        let val = wide("DisplayName");
        let mut buf = [0u16; 512];
        let mut len = (buf.len() * 2) as u32; // bytes
        let r = RegQueryValueExW(
            sub, val.as_ptr(), std::ptr::null_mut(), std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut u8, &mut len,
        );
        RegCloseKey(sub);
        if r != ERROR_SUCCESS || len == 0 {
            return None;
        }
        let chars = (len as usize / 2).min(buf.len());
        let s = widestr(&buf[..chars]);
        if s.is_empty() { None } else { Some(s) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_tools() {
        assert_eq!(classify("AnyDesk"), Some("remote-access"));
        assert_eq!(classify("qBittorrent 4.6"), Some("torrent"));
        assert_eq!(classify("Dropbox"), Some("cloud-sync"));
        assert_eq!(classify("Telegram Desktop"), Some("messaging"));
        assert_eq!(classify("SHAREit"), Some("file-transfer"));
    }

    #[test]
    fn ignores_unknown() {
        assert_eq!(classify("Microsoft Visual Studio Code"), None);
        assert_eq!(classify("7-Zip"), None);
    }
}
