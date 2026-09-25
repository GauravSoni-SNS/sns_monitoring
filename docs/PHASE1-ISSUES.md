# PHASE1-ISSUES.md

Issues found and their resolution during Phase-1 completion. Severity: Critical / High /
Medium / Low. Do not start Phase 2 while any **Critical** remains open. (None are open.)

---

## ISSUE-1 — Session-0 isolation: interactive collectors can't see the desktop
- **Severity:** Critical (architecture)
- **Description:** A `LocalSystem` service runs in session 0, which has no interactive
  desktop. Screenshots, foreground-window/active-app, window titles, and browser activity
  captured from session 0 return nothing real. The original design ran all collectors in the
  service, which would silently capture black frames / no app data on a real deployment.
- **Repro:** Run capture from a session-0 process → empty/black frame.
- **Expected:** Real user-desktop capture.
- **Root cause:** Windows Session 0 Isolation (since Vista); not bypassable and not to be
  bypassed.
- **Fix:** Split topology. Added **`sns-useragent`** (runs in the user session via a logon
  scheduled task) for interactive capture; it writes encrypted files + JSON manifests to a
  drop box (`runtime/incoming/`). The session-0 **service** ingests manifests into SQLite
  (single writer) and **detects session 0, skipping capture** so it never stores black frames.
- **Verification:** End-to-end on a real interactive session — useragent captured the live
  screen, service ingested it, integrity PASS. Documented in SCREENSHOT.md.
- **Status:** Resolved.

## ISSUE-2 — Drop-box ingest deleted manifests even on insert failure
- **Severity:** High (data loss)
- **Description:** The first `ingest_dropbox` removed each manifest unconditionally after
  processing, so a failed DB insert would silently drop the captured record. Re-ingest after
  a crash could also duplicate a chained event.
- **Repro:** Inject an insert failure during ingest → manifest deleted, data lost.
- **Root cause:** Unconditional `remove_file`; no idempotency on re-ingest.
- **Fix:** `insert_screenshot` is now `INSERT OR IGNORE` returning whether a new row landed;
  `SCREENSHOT_CREATED` is emitted only on a genuinely new row; activity ingest checks
  `activity_exists` first; the manifest is deleted **only** when its data is safely committed
  (or provably already present). Unparseable manifests are quarantined to
  `runtime/incoming/bad/` instead of looping forever.
- **Verification:** Full pipeline run — manifest consumed only after row committed; re-run
  does not duplicate; integrity PASS.
- **Status:** Resolved.

## ISSUE-3 — FK constraint surfaced by a test that skipped device creation
- **Severity:** Medium (test correctness)
- **Description:** `head_persists_across_reopen` inserted activity events without first
  creating the `devices` row; with `foreign_keys=ON` this failed (extended code 787).
- **Root cause:** Test didn't mirror production boot (which always upserts the device first).
  The FK is correct and desirable.
- **Fix:** Test now creates the device row first. Kept the FK.
- **Status:** Resolved.

## ISSUE-4 — windows-sys 0.59 handles are raw pointers, not integers
- **Severity:** Medium (compile)
- **Description:** GDI handle code compared handles to `0` and passed `0` as `HWND`; in
  windows-sys 0.59 these are `*mut c_void`.
- **Fix:** Use `std::ptr::null_mut()` and `.is_null()`.
- **Status:** Resolved (build clean).

## ISSUE-5 — Missing crate deps surfaced only at real compile
- **Severity:** Low
- **Description:** `sns-agentctl` used `serde` without depending on it; `sns-admin` needed
  `sha2`. Caught by the first real `cargo build` (the prior environment had no toolchain).
- **Fix:** Added the dependencies.
- **Status:** Resolved.

---

## Known limitations / remaining work (not defects — tracked for the test PC / follow-up)

- **L-1 (High for full acceptance):** Real **Windows Service install + lifecycle** (auto-start,
  terminal-closure, logout independence) not exercised here — the session was non-elevated.
  `service_win.rs` compiles; run `installer\install.ps1` elevated on `SNS-TEST-001`.
- **L-2a (done):** **Session logon/logoff** events are now implemented — the SCM control
  handler accepts `SESSION_CHANGE` and pushes signals through a bounded inbox to the agent
  loop, which chains `USER_SESSION_STARTED/ENDED`. The drain logic is verified by
  `tests/lifecycle.rs::session_signals_become_chained_session_events`. The FFI handler
  mapping compiles; its live delivery needs the service running elevated on the test PC.
- **L-2b (Medium, remaining):** **USB attach/detach** events not yet emitted. Design:
  `RegisterDeviceNotification` with the service status handle (`DEVICE_NOTIFY_SERVICE_HANDLE`)
  → `WM_DEVICECHANGE` → push into the same inbox pattern → `USB_DEVICE_CONNECTED/DISCONNECTED`
  (device description only; no file copy or content inspection).
- **L-3 (Low):** `health.json` `last_screenshot_utc` can lag one maintenance cycle (published
  before the first ingest); it self-corrects within the maintenance interval.
- **L-4 (Low):** Admin UI is a **functional vanilla-JS SPA** served by `sns-admin`, not the
  React/Vite stack named in the spec. All 11 sections work (login, dashboard, timeline,
  browser, screenshots with decrypt-view, system events, storage, health, config, audit,
  integrity). React can replace it without backend changes.
- **L-5 (Low):** Browser URL is captured at **window-title granularity** (page title), not the
  address-bar URL; reading the real URL needs UI Automation and is deferred. No history/cookie/
  credential access (by policy).
- **L-6 (Low):** Installer is PowerShell scripts + a **WiX skeleton**; a signed MSI with a full
  file harvest and Authenticode signing is follow-up packaging work.
- **L-7 (Low):** Multi-monitor capture grabs the **primary** display; DXGI multi-display
  enumeration is a refinement.

## ISSUE-6 — ACLs locked out the user-session capture agent
- **Severity:** High (functional) — found during first real install.
- **Description:** Install ACLs granted `Users` no access to the data root, but
  `sns-useragent` runs as a **standard user** (logon scheduled task, limited token). It
  could not read `config`/`keys` and exited instantly → 0 screenshots, no app/browser events.
- **Fix:** Installer now grants `Users` read on the tree + read on `keys`, `Modify` on
  `data`/`runtime`/`logs`/`queue`, and keeps `database` SYSTEM+Admins-only. Immediate-repair
  `icacls` commands provided for already-installed machines.
- **Status:** Resolved (installer updated + rebundled).

## L-8 (design tradeoff, documented) — monitored user can reach the DEK / their own files
Because interactive capture must run in the user's session, that user's token can read
`keys\keyring.json` and unwrap the **LocalMachine-DPAPI** DEK, and can write/delete files
under `data\`. So the *monitored user* can, in principle, decrypt or delete **their own**
screenshots. Deletion/modification of stored `.enc` files is **tamper-evident** (SHA-256 +
GCM → 409 + `INTEGRITY_FAILURE` on view). Full confidentiality against the monitored user
would need the DEK held only by the SYSTEM service with screenshots handed off via IPC — a
Phase-1.x hardening. Acceptable for the authorized-audit use case; noted here for honesty.

No Critical issues open.
