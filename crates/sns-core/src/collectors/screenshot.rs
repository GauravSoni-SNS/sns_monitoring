//! Screenshot collector (spec §19, §20, SCREENSHOT.md).
//!
//! Pipeline: capture authorized display → compress (PNG) → AES-256-GCM encrypt →
//! SHA-256(ciphertext) → write `screenshot_<ulid>.enc` (fsync) → return metadata for the
//! storage writer to insert (sync_status=LOCAL_ONLY). No video, no webcam, no mic.
//!
//! The display grab is the platform step (DXGI Desktop Duplication / GDI). The
//! encrypt→hash→persist pipeline below is final and unit-tested against real crypto.

use std::path::Path;

use sha2::{Digest, Sha256};
use sns_shared::ids::new_screenshot_id;
use sns_shared::models::ScreenshotMeta;
use sns_shared::sync::SyncStatus;

use crate::clock::now_utc_iso;
use crate::error::{CoreError, Result};
use crate::security::crypto::{self, DataKey, ENCRYPTION_VERSION};
use crate::storage::filesystem;

/// Encrypt + hash + persist one captured frame. `png_bytes` is the compressed image from
/// the platform grab. Returns the metadata row to insert.
pub fn persist_capture(
    data_root: &Path,
    key: &DataKey,
    device_id: &str,
    monitor_id: Option<u32>,
    png_bytes: &[u8],
) -> Result<ScreenshotMeta> {
    let screenshot_id = new_screenshot_id();
    let path = filesystem::screenshot_path(data_root, &screenshot_id);
    filesystem::ensure_parent(&path)?;

    let ciphertext = crypto::encrypt(key, png_bytes)?;
    let sha = hex::encode(Sha256::digest(&ciphertext)); // hash of ciphertext (spec §19)

    // Write then fsync so a committed DB row always has a readable file (STORAGE.md).
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&path)?;
        f.write_all(&ciphertext)?;
        f.sync_all()?;
    }

    Ok(ScreenshotMeta {
        screenshot_id,
        device_id: device_id.to_string(),
        timestamp_utc: now_utc_iso(),
        file_path: path.to_string_lossy().into_owned(),
        file_size: ciphertext.len() as u64,
        sha256: sha,
        encryption_version: ENCRYPTION_VERSION,
        monitor_id,
        created_at: now_utc_iso(),
        sync_status: SyncStatus::LocalOnly,
    })
}

/// Downscale a decrypted PNG to a small thumbnail (preview cards). Aspect-preserving,
/// fits within `max_dim` x `max_dim`. Re-encoded as PNG.
pub fn thumbnail(png: &[u8], max_dim: u32) -> Result<Vec<u8>> {
    use image::ImageFormat;
    let img = image::load_from_memory(png).map_err(|_| CoreError::Storage("thumb decode failed".into()))?;
    let t = img.thumbnail(max_dim, max_dim);
    let mut out = Vec::new();
    t.write_to(&mut std::io::Cursor::new(&mut out), ImageFormat::Png)
        .map_err(|_| CoreError::Storage("thumb encode failed".into()))?;
    Ok(out)
}

/// Content fingerprint of a decoded screenshot, used by the heuristic cleanup (feature #5).
#[derive(Debug, Clone, Copy)]
pub struct Fingerprint {
    /// 8×8 average-hash (perceptual) — small Hamming distance ⇒ visually near-identical.
    pub ahash: u64,
    /// Std-dev of luma over the 8×8 grid. Very low ⇒ near-uniform (blank / lock screen).
    pub luma_stddev: f64,
}

/// Compute a perceptual fingerprint from PNG bytes: downscale to 8×8 grayscale, take the
/// average-hash and the luma std-dev. Cheap and decode-only; no capture.
pub fn fingerprint(png: &[u8]) -> Result<Fingerprint> {
    let img = image::load_from_memory(png).map_err(|_| CoreError::Storage("fp decode failed".into()))?;
    let small = img.resize_exact(8, 8, image::imageops::FilterType::Triangle).to_luma8();
    let px: Vec<f64> = small.pixels().map(|p| p.0[0] as f64).collect();
    let mean = px.iter().sum::<f64>() / px.len() as f64;
    let var = px.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / px.len() as f64;
    let mut ahash = 0u64;
    for (i, v) in px.iter().enumerate() {
        if *v >= mean {
            ahash |= 1 << i;
        }
    }
    Ok(Fingerprint { ahash, luma_stddev: var.sqrt() })
}

/// Hamming distance between two average-hashes (0 = identical frame).
pub fn ahash_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// Heuristic "junk" test for a single frame: near-uniform screens (blank desktop, lock/login
/// screen, screensaver) have very low luma variation. Threshold chosen to flag flat frames
/// while keeping any screen with real window content.
pub fn is_blank_or_lock(fp: &Fingerprint) -> bool {
    fp.luma_stddev < 8.0
}

/// Default Hamming threshold below which two consecutive frames count as near-duplicates.
pub const NEAR_DUPLICATE_DISTANCE: u32 = 5;

/// Decide which screenshots to drop by content. `frames` is ordered oldest→newest as
/// `(id, fingerprint)`; a `None` fingerprint (decrypt/decode failed) is always KEPT (never
/// delete what we could not inspect). With `heuristic` on: blank/lock frames are dropped, and
/// a frame within `NEAR_DUPLICATE_DISTANCE` of the last kept frame is dropped as a duplicate.
/// Returns the ids to delete. Pure + testable.
pub fn plan_cleanup(frames: &[(String, Option<Fingerprint>)], heuristic: bool) -> Vec<String> {
    let mut drop = Vec::new();
    if !heuristic {
        return drop;
    }
    let mut last_kept: Option<u64> = None;
    for (id, fp) in frames {
        let Some(fp) = fp else {
            continue; // uninspectable → keep
        };
        if is_blank_or_lock(fp) {
            drop.push(id.clone());
            continue;
        }
        if let Some(prev) = last_kept {
            if ahash_distance(prev, fp.ahash) <= NEAR_DUPLICATE_DISTANCE {
                drop.push(id.clone());
                continue;
            }
        }
        last_kept = Some(fp.ahash);
    }
    drop
}

/// Platform display grab → downscaled PNG bytes for a monitor.
///
/// IMPORTANT (session-0 limitation): a LocalSystem service runs in session 0 and cannot
/// see the interactive desktop — capturing there yields a black frame. So on Windows this
/// returns an empty vec when called from session 0; the service must run the capture inside
/// the active user session via a session-bridge helper (WTSQueryUserToken +
/// CreateProcessAsUser). See docs/SCREENSHOT.md. Empty result ⇒ caller stores nothing.
#[cfg(windows)]
pub fn capture_monitor(monitor_id: u32, max_dimension: u32) -> Result<Vec<u8>> {
    if win_capture::in_session_0() {
        // Never store black session-0 frames. Helper runs the real capture in-session.
        return Ok(vec![]);
    }
    let (w, h, bgra) = win_capture::grab_primary()?;
    encode_png(w, h, bgra, max_dimension, monitor_id)
}

#[cfg(not(windows))]
pub fn capture_monitor(_monitor_id: u32, max_dimension: u32) -> Result<Vec<u8>> {
    // Linux/macOS: capture via the platform layer (grim/scrot/import or screencapture).
    // Downscale to `max_dimension` through the same PNG re-encode path used on Windows.
    let raw = crate::collectors::platform_unix::capture_screen_png(max_dimension);
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    match image::load_from_memory(&raw) {
        Ok(img) => {
            let (w, h) = (img.width(), img.height());
            let img = if w.max(h) > max_dimension && max_dimension > 0 {
                let scale = max_dimension as f32 / w.max(h) as f32;
                img.thumbnail((w as f32 * scale) as u32, (h as f32 * scale) as u32)
            } else {
                img
            };
            let mut out = Vec::new();
            img.write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
                .map_err(|_| CoreError::Storage("png encode failed".into()))?;
            Ok(out)
        }
        Err(_) => Ok(raw), // store as-is if we can't re-encode
    }
}

/// Convert a top-down BGRA framebuffer to RGBA, optionally downscale so the longest edge
/// is `max_dimension`, and PNG-encode. Portable (used by any capture backend).
#[allow(dead_code)]
fn encode_png(w: u32, h: u32, mut bgra: Vec<u8>, max_dimension: u32, _monitor_id: u32) -> Result<Vec<u8>> {
    use image::{codecs::png::PngEncoder, imageops, ExtendedColorType, ImageEncoder, RgbaImage};

    if w == 0 || h == 0 || bgra.len() < (w as usize * h as usize * 4) {
        return Err(CoreError::Storage("invalid frame dimensions".into()));
    }
    // BGRA → RGBA in place (swap B/R, force opaque alpha).
    for px in bgra.chunks_exact_mut(4) {
        px.swap(0, 2);
        px[3] = 0xFF;
    }
    let mut img = RgbaImage::from_raw(w, h, bgra)
        .ok_or_else(|| CoreError::Storage("frame buffer size mismatch".into()))?;

    let longest = w.max(h);
    if max_dimension > 0 && longest > max_dimension {
        let scale = max_dimension as f32 / longest as f32;
        let nw = ((w as f32 * scale).round() as u32).max(1);
        let nh = ((h as f32 * scale).round() as u32).max(1);
        img = imageops::resize(&img, nw, nh, imageops::FilterType::Triangle);
    }

    let mut out = Vec::new();
    PngEncoder::new(&mut out)
        .write_image(img.as_raw(), img.width(), img.height(), ExtendedColorType::Rgba8)
        .map_err(|_| CoreError::Storage("png encode failed".into()))?;
    Ok(out)
}

#[cfg(windows)]
mod win_capture {
    use super::{CoreError, Result};
    use windows_sys::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC,
        GetDIBits, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
        SRCCOPY,
    };
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

    /// True if this process is in session 0 (the non-interactive service session).
    pub fn in_session_0() -> bool {
        unsafe {
            let mut sid: u32 = 0;
            if ProcessIdToSessionId(GetCurrentProcessId(), &mut sid) != 0 {
                sid == 0
            } else {
                // If we cannot tell, assume session 0 and skip rather than risk a black grab.
                true
            }
        }
    }

    /// Capture the primary display as a top-down BGRA buffer. Returns (width, height, bytes).
    /// SAFETY: every GDI handle acquired is released on all paths before returning.
    pub fn grab_primary() -> Result<(u32, u32, Vec<u8>)> {
        unsafe {
            let w = GetSystemMetrics(SM_CXSCREEN);
            let h = GetSystemMetrics(SM_CYSCREEN);
            if w <= 0 || h <= 0 {
                return Err(CoreError::Storage("screen metrics unavailable".into()));
            }
            let (w, h) = (w as u32, h as u32);
            let null = std::ptr::null_mut();

            let screen_dc = GetDC(null);
            if screen_dc.is_null() {
                return Err(CoreError::Storage("GetDC failed".into()));
            }
            let mem_dc = CreateCompatibleDC(screen_dc);
            let bitmap = CreateCompatibleBitmap(screen_dc, w as i32, h as i32);
            if mem_dc.is_null() || bitmap.is_null() {
                if !bitmap.is_null() { DeleteObject(bitmap); }
                if !mem_dc.is_null() { DeleteDC(mem_dc); }
                ReleaseDC(null, screen_dc);
                return Err(CoreError::Storage("GDI object creation failed".into()));
            }
            let old = SelectObject(mem_dc, bitmap);
            let blt_ok = BitBlt(mem_dc, 0, 0, w as i32, h as i32, screen_dc, 0, 0, SRCCOPY) != 0;

            let mut result = Err(CoreError::Storage("BitBlt failed".into()));
            if blt_ok {
                let mut bmi: BITMAPINFO = std::mem::zeroed();
                bmi.bmiHeader = BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: w as i32,
                    biHeight: -(h as i32), // negative ⇒ top-down rows
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB,
                    biSizeImage: 0,
                    biXPelsPerMeter: 0,
                    biYPelsPerMeter: 0,
                    biClrUsed: 0,
                    biClrImportant: 0,
                };
                let mut buf = vec![0u8; w as usize * h as usize * 4];
                let scanned = GetDIBits(
                    mem_dc,
                    bitmap,
                    0,
                    h,
                    buf.as_mut_ptr() as *mut _,
                    &mut bmi,
                    DIB_RGB_COLORS,
                );
                if scanned != 0 {
                    result = Ok((w, h, buf));
                }
            }

            SelectObject(mem_dc, old);
            DeleteObject(bitmap);
            DeleteDC(mem_dc);
            ReleaseDC(null, screen_dc);
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_encode_downscales_and_is_valid_png() {
        // Synthetic 100x40 BGRA frame → PNG, downscaled to max edge 50.
        let (w, h) = (100u32, 40u32);
        let bgra = vec![0x10u8; (w * h * 4) as usize];
        let png = encode_png(w, h, bgra, 50, 0).unwrap();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n"); // PNG magic
        // Decode back and confirm downscale applied (longest edge == 50).
        let img = image::load_from_memory(&png).unwrap();
        assert_eq!(img.width().max(img.height()), 50);
    }

    #[test]
    fn png_encode_rejects_bad_dimensions() {
        assert!(encode_png(10, 10, vec![0u8; 8], 0, 0).is_err());
    }

    // Build a PNG from an 8-bit grayscale pattern for fingerprint tests.
    fn gray_png(f: impl Fn(u32, u32) -> u8) -> Vec<u8> {
        use image::{ImageFormat, Luma};
        let mut img = image::GrayImage::new(64, 64);
        for (x, y, p) in img.enumerate_pixels_mut() {
            *p = Luma([f(x, y)]);
        }
        let mut out = Vec::new();
        image::DynamicImage::ImageLuma8(img)
            .write_to(&mut std::io::Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn blank_frame_flagged_content_frame_kept() {
        let blank = gray_png(|_, _| 30); // uniform → lock/blank
        let content = gray_png(|x, y| (((x * 13) ^ (y * 7)) & 0xFF) as u8); // busy pattern
        assert!(is_blank_or_lock(&fingerprint(&blank).unwrap()));
        assert!(!is_blank_or_lock(&fingerprint(&content).unwrap()));
    }

    #[test]
    fn plan_cleanup_drops_blank_and_dupes_keeps_content() {
        let busy = fingerprint(&gray_png(|x, y| (((x * 13) ^ (y * 7)) & 0xFF) as u8)).unwrap();
        let busy_dup = fingerprint(&gray_png(|x, y| (((x * 13) ^ (y * 7)) & 0xFF) as u8)).unwrap();
        let other = fingerprint(&gray_png(|x, y| (((x * 5) ^ (y * 11)) & 0xFF) as u8)).unwrap();
        let blank = fingerprint(&gray_png(|_, _| 30)).unwrap();
        let frames = vec![
            ("keep1".to_string(), Some(busy)),
            ("dup".to_string(), Some(busy_dup)),   // near-dup of keep1 → drop
            ("blank".to_string(), Some(blank)),    // blank → drop
            ("keep2".to_string(), Some(other)),    // different content → keep
            ("unreadable".to_string(), None),      // never drop
        ];
        let drop = plan_cleanup(&frames, true);
        assert!(drop.contains(&"dup".to_string()));
        assert!(drop.contains(&"blank".to_string()));
        assert!(!drop.contains(&"keep1".to_string()));
        assert!(!drop.contains(&"keep2".to_string()));
        assert!(!drop.contains(&"unreadable".to_string()));
        // heuristic off → nothing dropped
        assert!(plan_cleanup(&frames, false).is_empty());
    }

    #[test]
    fn near_duplicate_detected() {
        let a = gray_png(|x, y| (((x * 13) ^ (y * 7)) & 0xFF) as u8);
        let a2 = gray_png(|x, y| (((x * 13) ^ (y * 7)) & 0xFF) as u8); // identical
        let b = gray_png(|x, y| (((x * 5) ^ (y * 11)) & 0xFF) as u8); // different
        let (fa, fa2, fb) = (fingerprint(&a).unwrap(), fingerprint(&a2).unwrap(), fingerprint(&b).unwrap());
        assert!(ahash_distance(fa.ahash, fa2.ahash) <= NEAR_DUPLICATE_DISTANCE);
        assert!(ahash_distance(fa.ahash, fb.ahash) > NEAR_DUPLICATE_DISTANCE);
    }

    /// Live capture against the real display. Ignored by default (needs a session with a
    /// desktop). Run: `cargo test -p sns-core --lib -- --ignored live_capture_smoke`.
    #[test]
    #[ignore]
    fn live_capture_smoke() {
        let bytes = capture_monitor(0, 800).unwrap();
        if bytes.is_empty() {
            eprintln!("capture returned empty (session 0 or no display) — expected for a service");
        } else {
            assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
            eprintln!("captured PNG: {} bytes", bytes.len());
        }
    }

    #[test]
    fn capture_is_encrypted_hashed_and_readable_back() {
        let dir = tempfile::tempdir().unwrap();
        let key = DataKey::generate();
        let fake_png = b"\x89PNG fake image bytes";

        let meta = persist_capture(dir.path(), &key, "dev_T", Some(0), fake_png).unwrap();

        // File exists, is the ciphertext (not the plaintext PNG), and hash matches.
        let on_disk = std::fs::read(&meta.file_path).unwrap();
        assert_ne!(on_disk, fake_png);
        assert_eq!(hex::encode(Sha256::digest(&on_disk)), meta.sha256);
        assert_eq!(meta.encryption_version, ENCRYPTION_VERSION);
        assert!(meta.file_path.ends_with(".enc"));

        // Authorized viewer path: decrypt round-trips to the original frame.
        assert_eq!(crypto::decrypt(&key, &on_disk).unwrap(), fake_png);
    }
}
