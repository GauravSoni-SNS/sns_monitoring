//! Screenshot file layout + directory usage (spec §12, §19, §20).

use std::path::{Path, PathBuf};

use crate::clock::ymd_utc;
use crate::error::Result;

/// `data\<YYYY>\<MM>\<DD>\screenshots\screenshot_<ulid>.enc` under the data root.
/// Opaque ULID filename, never a timestamp (spec §20).
pub fn screenshot_path(data_root: &Path, screenshot_id: &str) -> PathBuf {
    let (y, m, d) = ymd_utc();
    data_root
        .join("data")
        .join(format!("{y:04}"))
        .join(format!("{m:02}"))
        .join(format!("{d:02}"))
        .join("screenshots")
        .join(format!("{screenshot_id}.enc"))
}

/// Ensure the day bucket exists before writing.
pub fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Recursive byte usage of the data root, for quota checks (spec §25, §26).
pub fn dir_size_bytes(root: &Path) -> u64 {
    fn walk(p: &Path) -> u64 {
        let mut total = 0;
        let Ok(entries) = std::fs::read_dir(p) else { return 0 };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                total += walk(&entry.path());
            } else if let Ok(md) = entry.metadata() {
                total += md.len();
            }
        }
        total
    }
    walk(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screenshot_filename_is_opaque_enc() {
        let p = screenshot_path(Path::new("/root"), "scr_01KABC");
        let name = p.file_name().unwrap().to_string_lossy();
        assert_eq!(name, "scr_01KABC.enc");
        // No time-encoded plaintext name (spec §20).
        assert!(!name.contains(':'));
    }
}
