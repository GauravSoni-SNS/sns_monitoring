//! Print-job monitoring (exfil #3). Polls the Windows print spooler and reports each document
//! sent to a printer.
//!
//! BOUNDARY: reads only the spooler's job **metadata** — document name, printer, page count,
//! spool byte size (spec §16). It never reads the document's rendered content or data.

use std::collections::HashSet;

use sns_shared::events::{ActivityEvent, EventType};
use sns_shared::ids::new_event_id;

use crate::clock::now_utc_iso;

/// One spooled print job (metadata only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrintJob {
    pub printer: String,
    pub document: String,
    pub pages: u32,
    pub size_bytes: u32,
    /// Stable per-(printer,job) key used to emit each job exactly once.
    pub key: String,
}

/// Tracks which jobs have already been reported, so each prints one event.
#[derive(Debug, Default)]
pub struct PrintTracker {
    seen: HashSet<String>,
}

impl PrintTracker {
    pub fn new() -> Self {
        Self { seen: HashSet::new() }
    }

    /// Given the currently-spooled jobs, return the ones not seen before (and remember them).
    /// Also forgets keys no longer present so a later job with a reused id still reports.
    pub fn newly_seen(&mut self, jobs: &[PrintJob]) -> Vec<PrintJob> {
        let current: HashSet<String> = jobs.iter().map(|j| j.key.clone()).collect();
        let fresh: Vec<PrintJob> = jobs.iter().filter(|j| !self.seen.contains(&j.key)).cloned().collect();
        for j in &fresh {
            self.seen.insert(j.key.clone());
        }
        // Drop keys that left the queue so the id can fire again if reused.
        self.seen.retain(|k| current.contains(k));
        fresh
    }
}

/// Build a DOCUMENT_PRINTED event (metadata only).
pub fn build_event(device_id: &str, j: &PrintJob) -> ActivityEvent {
    let meta = serde_json::json!({
        "printer": j.printer, "document": j.document, "pages": j.pages, "size_bytes": j.size_bytes
    })
    .to_string();
    ActivityEvent {
        event_id: new_event_id(),
        device_id: device_id.to_string(),
        event_type: EventType::DocumentPrinted,
        timestamp_utc: now_utc_iso(),
        application_name: None,
        process_name: None,
        window_title: Some(format!("{} → {}", j.document, j.printer)),
        metadata_json: Some(meta),
    }
}

/// Current spooled jobs across all local printers. Non-Windows: empty.
#[cfg(windows)]
pub fn current_jobs() -> Vec<PrintJob> {
    win::current_jobs()
}

#[cfg(not(windows))]
pub fn current_jobs() -> Vec<PrintJob> {
    crate::collectors::platform_unix::current_print_jobs()
}

#[cfg(windows)]
mod win {
    use super::PrintJob;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Graphics::Printing::{
        ClosePrinter, EnumJobsW, EnumPrintersW, OpenPrinterW, JOB_INFO_1W, PRINTER_ENUM_LOCAL,
        PRINTER_INFO_1W,
    };

    fn widestr(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        unsafe {
            let mut len = 0usize;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
        }
    }

    pub fn current_jobs() -> Vec<PrintJob> {
        let mut out = Vec::new();
        for printer in printers() {
            out.extend(jobs_for(&printer));
        }
        out
    }

    fn printers() -> Vec<String> {
        unsafe {
            let flags = PRINTER_ENUM_LOCAL;
            let mut needed = 0u32;
            let mut count = 0u32;
            // First call sizes the buffer.
            EnumPrintersW(flags, std::ptr::null(), 1, std::ptr::null_mut(), 0, &mut needed, &mut count);
            if needed == 0 {
                return Vec::new();
            }
            let mut buf = vec![0u8; needed as usize];
            if EnumPrintersW(flags, std::ptr::null(), 1, buf.as_mut_ptr(), needed, &mut needed, &mut count) == 0 {
                return Vec::new();
            }
            let infos = std::slice::from_raw_parts(buf.as_ptr() as *const PRINTER_INFO_1W, count as usize);
            infos.iter().map(|i| widestr(i.pName as *const u16)).filter(|s| !s.is_empty()).collect()
        }
    }

    fn jobs_for(printer: &str) -> Vec<PrintJob> {
        unsafe {
            let name: Vec<u16> = printer.encode_utf16().chain(std::iter::once(0)).collect();
            let mut h: HANDLE = std::ptr::null_mut();
            if OpenPrinterW(name.as_ptr(), &mut h, std::ptr::null()) == 0 || h.is_null() {
                return Vec::new();
            }
            let mut needed = 0u32;
            let mut count = 0u32;
            // Size the job buffer (up to 256 jobs).
            EnumJobsW(h, 0, 256, 1, std::ptr::null_mut(), 0, &mut needed, &mut count);
            let mut out = Vec::new();
            if needed > 0 {
                let mut buf = vec![0u8; needed as usize];
                if EnumJobsW(h, 0, 256, 1, buf.as_mut_ptr(), needed, &mut needed, &mut count) != 0 {
                    let jobs = std::slice::from_raw_parts(buf.as_ptr() as *const JOB_INFO_1W, count as usize);
                    for j in jobs {
                        out.push(PrintJob {
                            printer: printer.to_string(),
                            document: widestr(j.pDocument as *const u16),
                            pages: j.TotalPages,
                            // JOB_INFO_1W exposes no spool byte size; left 0 (metadata only).
                            size_bytes: 0,
                            key: format!("{printer}#{}", j.JobId),
                        });
                    }
                }
            }
            ClosePrinter(h);
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(key: &str) -> PrintJob {
        PrintJob { printer: "HP".into(), document: "doc".into(), pages: 1, size_bytes: 100, key: key.into() }
    }

    #[test]
    fn reports_each_job_once() {
        let mut t = PrintTracker::new();
        let jobs = vec![job("HP#1"), job("HP#2")];
        assert_eq!(t.newly_seen(&jobs).len(), 2);
        // Same queue again → nothing new.
        assert_eq!(t.newly_seen(&jobs).len(), 0);
        // One leaves, a new one arrives.
        let jobs2 = vec![job("HP#2"), job("HP#3")];
        let fresh = t.newly_seen(&jobs2);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].key, "HP#3");
    }

    #[test]
    fn reused_id_fires_again_after_leaving_queue() {
        let mut t = PrintTracker::new();
        assert_eq!(t.newly_seen(&[job("HP#1")]).len(), 1);
        assert_eq!(t.newly_seen(&[]).len(), 0); // queue empties, key forgotten
        assert_eq!(t.newly_seen(&[job("HP#1")]).len(), 1); // same id reused → fires
    }
}
