//! USB file-copy detection (exfil #3). Periodically snapshots the file listing of removable
//! drives and reports files that newly appear (or grow) — the data-exfil-to-USB case.
//!
//! BOUNDARY: this reads only directory entries — file **name and size** — never file
//! contents (spec §16). It cannot and does not open, read, or copy any file's data. It is a
//! coarse "a file was written to removable media" signal, not content capture.

use std::collections::HashMap;

use sns_shared::events::{ActivityEvent, EventType};
use sns_shared::ids::new_event_id;

use crate::clock::now_utc_iso;

/// A snapshot of one removable drive's files: relative path -> size in bytes.
pub type DriveSnapshot = HashMap<String, u64>;
/// All removable drives: drive letter (e.g. "E:") -> its snapshot.
pub type UsbSnapshot = HashMap<String, DriveSnapshot>;

/// Safety caps so a huge stick can't make a snapshot unbounded.
pub const MAX_FILES_PER_DRIVE: usize = 20_000;
pub const MAX_DEPTH: usize = 8;

/// A file newly written to (or grown on) a removable drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFile {
    pub drive: String,
    pub path: String,
    pub size: u64,
}

/// Diff two USB snapshots: report files in `cur` that are absent from `prev`, or whose size
/// changed (a rewrite / append). Pure + testable. Drives only in `prev` (removed sticks) are
/// ignored — removal is handled by the USB connect/disconnect collector.
pub fn diff_snapshots(prev: &UsbSnapshot, cur: &UsbSnapshot) -> Vec<NewFile> {
    let mut out = Vec::new();
    for (drive, files) in cur {
        let prev_files = prev.get(drive);
        for (path, &size) in files {
            let changed = match prev_files.and_then(|pf| pf.get(path)) {
                None => true,              // new file
                Some(&old) => old != size, // size changed
            };
            if changed {
                out.push(NewFile { drive: drive.clone(), path: path.clone(), size });
            }
        }
    }
    out
}

/// Coarse file-kind classification by extension — "what kind of data moved". Lowercased.
pub fn file_kind(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "doc" | "docx" | "pdf" | "txt" | "rtf" | "odt" | "xls" | "xlsx" | "csv" | "ppt" | "pptx" => "document",
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "tiff" | "heic" | "svg" => "image",
        "mp4" | "mkv" | "avi" | "mov" | "wmv" | "flv" | "webm" => "video",
        "mp3" | "wav" | "flac" | "aac" | "ogg" | "m4a" => "audio",
        "zip" | "rar" | "7z" | "tar" | "gz" | "iso" => "archive",
        "exe" | "msi" | "bat" | "cmd" | "ps1" | "dll" | "scr" => "executable",
        _ => "other",
    }
}

/// Aggregate transfer summary — total volume, file count, and bytes per kind.
#[derive(Debug, Clone, Default, serde::Serialize, PartialEq, Eq)]
pub struct TransferSummary {
    pub total_bytes: u64,
    pub file_count: u64,
    /// kind -> total bytes.
    pub by_kind: std::collections::BTreeMap<String, u64>,
}

/// Summarize copied files (path, size) → total volume + per-kind breakdown. Pure + testable.
pub fn summarize(files: &[(String, u64)]) -> TransferSummary {
    let mut s = TransferSummary::default();
    for (path, size) in files {
        s.total_bytes += *size;
        s.file_count += 1;
        *s.by_kind.entry(file_kind(path).to_string()).or_insert(0) += *size;
    }
    s
}

/// Build a FILE_COPIED_TO_USB event (metadata only: drive, relative path, size).
pub fn build_event(device_id: &str, f: &NewFile) -> ActivityEvent {
    let meta = serde_json::json!({ "drive": f.drive, "path": f.path, "size": f.size }).to_string();
    ActivityEvent {
        event_id: new_event_id(),
        device_id: device_id.to_string(),
        event_type: EventType::FileCopiedToUsb,
        timestamp_utc: now_utc_iso(),
        application_name: None,
        process_name: None,
        window_title: Some(format!("{} ({})", f.path, f.drive)),
        metadata_json: Some(meta),
    }
}

/// Snapshot all removable drives (name + size per file, capped). Non-Windows: empty.
#[cfg(windows)]
pub fn snapshot_removable() -> UsbSnapshot {
    win::snapshot()
}

#[cfg(not(windows))]
pub fn snapshot_removable() -> UsbSnapshot {
    crate::collectors::platform_unix::snapshot_removable_files()
}

#[cfg(windows)]
mod win {
    use super::{DriveSnapshot, UsbSnapshot, MAX_DEPTH, MAX_FILES_PER_DRIVE};
    use std::path::{Path, PathBuf};
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};

    const DRIVE_REMOVABLE: u32 = 2;

    pub fn snapshot() -> UsbSnapshot {
        let mut out = UsbSnapshot::new();
        let mask = unsafe { GetLogicalDrives() };
        for i in 0..26u32 {
            if mask & (1 << i) == 0 {
                continue;
            }
            let letter = (b'A' + i as u8) as char;
            let root_w: Vec<u16> = format!("{letter}:\\").encode_utf16().chain(std::iter::once(0)).collect();
            if unsafe { GetDriveTypeW(root_w.as_ptr()) } != DRIVE_REMOVABLE {
                continue;
            }
            let drive = format!("{letter}:");
            let base = PathBuf::from(format!("{letter}:\\"));
            let mut snap = DriveSnapshot::new();
            walk(&base, &base, 0, &mut snap);
            out.insert(drive, snap);
        }
        out
    }

    fn walk(base: &Path, dir: &Path, depth: usize, snap: &mut DriveSnapshot) {
        if depth > MAX_DEPTH || snap.len() >= MAX_FILES_PER_DRIVE {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for entry in rd.flatten() {
            if snap.len() >= MAX_FILES_PER_DRIVE {
                return;
            }
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                walk(base, &path, depth + 1, snap);
            } else if ft.is_file() {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                let rel = path.strip_prefix(base).unwrap_or(&path).to_string_lossy().replace('\\', "/");
                snap.insert(rel, size);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(drive: &str, files: &[(&str, u64)]) -> UsbSnapshot {
        let mut m = UsbSnapshot::new();
        m.insert(drive.into(), files.iter().map(|(p, s)| (p.to_string(), *s)).collect());
        m
    }

    #[test]
    fn detects_new_and_changed_files() {
        let prev = snap("E:", &[("a.txt", 10), ("b.txt", 20)]);
        let cur = snap("E:", &[("a.txt", 10), ("b.txt", 30), ("c.txt", 5)]);
        let mut d = diff_snapshots(&prev, &cur);
        d.sort_by(|x, y| x.path.cmp(&y.path));
        assert_eq!(d.len(), 2); // b grew, c new
        assert_eq!(d[0].path, "b.txt");
        assert_eq!(d[1].path, "c.txt");
    }

    #[test]
    fn no_events_when_unchanged() {
        let s = snap("E:", &[("a.txt", 10)]);
        assert!(diff_snapshots(&s, &s).is_empty());
    }

    #[test]
    fn summarize_totals_and_kinds() {
        let files = vec![
            ("report.pdf".to_string(), 1000u64),
            ("photo.jpg".to_string(), 2000u64),
            ("movie.mp4".to_string(), 5000u64),
            ("notes.txt".to_string(), 500u64),
            ("tool.exe".to_string(), 300u64),
        ];
        let s = summarize(&files);
        assert_eq!(s.total_bytes, 8800);
        assert_eq!(s.file_count, 5);
        assert_eq!(s.by_kind["document"], 1500); // pdf + txt
        assert_eq!(s.by_kind["image"], 2000);
        assert_eq!(s.by_kind["video"], 5000);
        assert_eq!(s.by_kind["executable"], 300);
    }

    #[test]
    fn file_kind_classifies() {
        assert_eq!(file_kind("a/b/c.DOCX"), "document");
        assert_eq!(file_kind("x.ISO"), "archive");
        assert_eq!(file_kind("noext"), "other");
    }

    #[test]
    fn new_drive_reports_all_its_files() {
        let prev = UsbSnapshot::new();
        let cur = snap("F:", &[("x", 1), ("y", 2)]);
        assert_eq!(diff_snapshots(&prev, &cur).len(), 2);
    }
}
