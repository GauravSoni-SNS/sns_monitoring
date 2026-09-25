# PHASE1-TEST-REPORT.md

Honest record of what was **actually built and run** in this session, and what was not.
Nothing here is claimed "tested" unless a command was executed and its output observed.

## Environment (real)

| Item | Value |
|---|---|
| Test PC | Developer workstation (Windows) — **not** yet a dedicated `SNS-TEST-001` PC |
| Windows | Windows 11 Pro 10.0.22621 |
| Rust | 1.97.1 (stable, `x86_64-pc-windows-msvc`) — installed this session via rustup |
| MSVC | Visual Studio 2022 Build Tools 14.44 + Windows SDK 10.0.22621 / 10.0.26100 |
| Agent version | 1.0.0 |
| Dates | Session of 2026-08-11 |
| Elevation | Shell was **non-elevated** → real SCM service install could not be exercised here |

## Build & unit/integration tests (executed, observed)

| Command | Result |
|---|---|
| `cargo fetch` | OK — 140 packages, manifests valid |
| `cargo build --workspace` | **exit 0, 0 warnings** |
| `cargo build --release --workspace` | **exit 0, 0 warnings** (4 binaries: service, useragent, agentctl, admin) |
| `cargo test --workspace` | **43 passed, 0 failed, 1 ignored** (crypto, hash-chain, config, retention, dropbox, screenshot PNG, storage, sync-status, ids, lifecycle, session events) |
| `cargo clippy --workspace` | **exit 0, 0 warnings** |
| `cargo test -p sns-service --test lifecycle` | **3/3 pass** (graceful shutdown, crash recovery, session events) |

## Scenario tests actually run in-session (real, observed)

1. **Screenshot capture pipeline (real display).** `sns-useragent` captured this machine's
   live screen (143 KB PNG grabbed via GDI in a smoke test; 625 KB encrypted file in the
   full run), encrypted (AES-256-GCM), SHA-256'd, wrote `screenshot_<ulid>.enc`, dropped a
   manifest. Verified: **stored file is not a valid image** (header `91 8d f8 45…`, not PNG
   magic) → encrypted at rest (spec §12).
2. **Session-bridge ingest.** `sns-service` (`--console`) ingested the manifest into SQLite:
   `Screenshots: 1`, `SCREENSHOT_CREATED` chained, manifest consumed, `verify-integrity` PASS.
3. **Foreground application capture (real).** `sns-useragent` recorded
   `ACTIVE_APPLICATION_CHANGED app=explorer.exe title="Home - File Explorer"`, correctly
   **deduplicated** (one event for stable foreground). Browser path wired for browser foreground.
4. **Admin backend (live HTTP).** Login (Argon2id) → 200 + session cookie + CSRF;
   `/api/device`, `/api/screenshots` → 200; **`/api/screenshots/:id/image` decrypted in memory
   and served a valid PNG** (`89 50 4e 47`); unauthenticated request → **401**.
5. **Screenshot tamper rejection (spec §12).** Flipped one byte of the `.enc` file →
   viewer returned **HTTP 409**, `audit_log` recorded `SCREENSHOT_TAMPER_DETECTED`, and an
   `INTEGRITY_FAILURE` manifest was dropped for the service to chain.
6. **Graceful shutdown (spec §6–8, §28).** Integration test: boot → `shutdown(WINDOWS_SHUTDOWN)`
   → reopened DB shows exactly one `AGENT_STARTUP` + one `AGENT_SHUTDOWN`, `integrity_check` ok,
   chain PASS.
7. **Crash recovery (spec §9, §37).** Integration test: boot then drop **without** shutdown →
   reboot (boot again) → WAL recovers, ≥2 `AGENT_STARTUP`, **0** `AGENT_SHUTDOWN` in between,
   `integrity_check` ok, chain PASS, no duplicate explosion.
8. **Integrity matrix (unit).** clean → PASS; content edit → FAIL (exact row); deleted row →
   FAIL (linkage); retention never touches the chain → PASS.
9. **Retention safety (unit).** Un-synced `LOCAL_ONLY` data is **not** deleted by default;
   deleted only when `delete_unsynced=true`; activity hash-chain never pruned.
10. **Device identity (unit).** rename keeps `device_id`; `device_id` immutable.

## NOT run here (requires elevation and/or a dedicated PC + real time)

These are **not** claimed as passed. Procedures are in this report + INSTALLATION.md.

- Real **Windows Service install** (`sc create`, auto-delayed start), auto-start on boot,
  service-recovery actions — needs an **elevated** shell on the test PC. (`service_win.rs`
  compiles; its SCM runtime path is unverified here.)
- **Terminal-closure / logout / login** independence as an installed service.
- **USB attach/detach** events (collector not yet implemented — see PHASE1-ISSUES L-2b).
- **Live SCM delivery** of session logon/logoff events (the drain logic is verified; the
  control-handler mapping compiles but its live SCM delivery needs the elevated test PC).
- **Multi-day stability, CPU/RAM/disk growth** (§40) — inherently a days-long operator task.
- **Signed binaries / real MSI** (WiX skeleton only).

## Acceptance criteria (§45) — honest status

| Criterion | Status |
|---|---|
| Workspace builds on Windows | ✅ verified (exit 0, 0 warnings) |
| `cargo test --workspace` passes | ✅ verified |
| Release build succeeds | ✅ verified (see final run) |
| Service installs / auto-starts | ⏳ not run here (needs elevation on test PC) |
| Terminal closure doesn't stop service | ⏳ not run here (service model designed for it) |
| User logout doesn't stop service | ⏳ not run here |
| Windows restart works / data persists | 🟡 crash-recovery logic verified; full reboot on test PC |
| Windows shutdown clean + AGENT_SHUTDOWN | ✅ shutdown logic verified (integration) |
| Power/crash recovery | ✅ verified (integration) |
| SQLite consistent | ✅ verified (WAL + integrity_check + chain) |
| Application activity works | ✅ verified (real foreground capture) |
| Browser activity works | 🟡 wired + unit-tested; needs a browser-foreground live check |
| Screenshot capture works | ✅ verified (real display) |
| Screenshot encryption works | ✅ verified (not an image at rest) |
| Authorized screenshot viewing works | ✅ verified (decrypt in memory → PNG) |
| Key protection works | ✅ DPAPI wrap/unwrap verified (unit + live keyring) |
| Integrity verification works | ✅ verified (CLI + admin + unit matrix) |
| Tampering is detected | ✅ verified (409 + audit + INTEGRITY_FAILURE) |
| Offline mode works | ✅ by construction (no network on collection path); no blocking calls exist |
| Storage limits work | 🟡 thresholds + events implemented + unit-tested; live-fill not run |
| Retention works | ✅ verified (unit; un-synced protected) |
| Local admin interface works | ✅ verified (live login + all read endpoints + UI served) |
| Authentication works | ✅ verified (Argon2id, 401 on no session, rate-limited) |
| Device ID stable / rename / IP change | ✅ verified (unit) |
| No prohibited data collection | ✅ by design (no keylog/password/cookie/mic/cam) — see SECURITY.md |
| No secrets in logs | ✅ by design; grep review recommended on test PC |
| CPU/RAM/disk acceptable | ⏳ multi-day measurement on test PC |
| Multi-day stability | ⏳ operator task |
| PHASE1-TEST-REPORT.md | ✅ this file |
| Critical issues resolved | ✅ (see PHASE1-ISSUES.md) |

## Recommended procedure on the dedicated test PC (`SNS-TEST-001`)

1. Copy `target\release\*.exe` into the installer's `bin\`, run **elevated**:
   `installer\install.ps1 -SystemName SNS-TEST-001 -AdminPassword (Read-Host -AsSecureString)`.
2. `sc query SNSSecurityAgent` → RUNNING, START_TYPE auto-delayed.
3. Reboot → confirm service auto-starts with no terminal; log back in → confirm
   `SNSSecurityCapture` task runs `sns-useragent` in your session.
4. Open the admin panel at `http://127.0.0.1:7731`, sign in, watch the timeline/screenshots fill.
5. Exercise: browse, switch apps, disconnect network (collection continues), open+close a
   terminal (`sns-agentctl status`; service keeps running), log out/in, restart, shut down.
6. After several days: `sns-agentctl verify-integrity` (PASS), review storage growth, CPU/RAM,
   and fill the measurement rows above. Record any issues in PHASE1-ISSUES.md.
