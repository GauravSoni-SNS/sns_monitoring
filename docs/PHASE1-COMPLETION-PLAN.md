# PHASE1-COMPLETION-PLAN.md

Plan to finish Phase 1 and make it production-testable on Windows. No Phase-2 work (no
central DB, remote API, cloud storage, sync). Reuses the existing architecture, schema,
IDs, sync-status model, and Phase-2 interfaces unchanged.

## Toolchain blocker (must resolve first — spec §28)

This dev box has **no Rust toolchain and no MSVC C++ compiler**:

```
rustc / cargo / rustup : NOT INSTALLED
cl.exe (MSVC)          : NOT INSTALLED   (the link.exe on PATH is Git's, not MSVC)
winget                 : present (1.29)
node / npm             : present (22.17 / 10.9)  → fine for the React UI
network                : up
```

Consequence: `cargo build` / `cargo test` / release build / service install / the multi-day
test **cannot run until a toolchain exists**. Per spec §28/§46 nothing below is marked
"tested" until it is actually built and run. Required install:

- `rustup` + stable `x86_64-pc-windows-msvc` toolchain, **or** `-gnu` if MSVC tools are
  unavailable.
- **MSVC Build Tools + Windows SDK** (needed for `windows-sys`, `windows-service`, DXGI,
  and MSVC linking). Large (~several GB), needs elevation.
- Optional: WiX toolset for the MSI (scripts already cover install without it).

## Already implemented (from prior session; unit-tested logic, unbuilt)

- Workspace + 5 crates; schema `migrations/0001_init.sql`.
- `sns-shared`: event enum, ULID IDs, hash-chain seal/verify, sync-status + Phase-2 traits.
- `sns-core`: config/policy validation, identity, AES-256-GCM crypto, DPAPI keymgr,
  integrity verify, SQLite storage (insert+chain+checkpoint), retention **predicates**,
  health model, collector **interfaces**.
- `sns-service`: SCM host + agent supervisor + dev console; graceful shutdown lifecycle.
- `sns-agentctl`: `init` / `status` / `health` / `verify-integrity` / `diagnostics`.
- `sns-admin`: auth (Argon2id) + route table.

## Still incomplete (this phase completes these — spec §3, §10–20)

| Area | Work | Files |
|---|---|---|
| Foreground app capture | Win32 GetForegroundWindow → process image + title | `sns-core/collectors/application.rs` |
| Browser activity | Foreground browser detect + tab title/domain via UI Automation | `sns-core/collectors/browser.rs` |
| Screenshot grab | DXGI Desktop Duplication (+ GDI fallback) → PNG | `sns-core/collectors/screenshot.rs` |
| Screenshot scheduler | Interval timer, policy-gated, test-short interval | `sns-service/agent.rs` |
| Session events | SESSIONCHANGE → USER_SESSION_STARTED/ENDED | `sns-service/service_win.rs` |
| USB events | Device arrival/removal (WM_DEVICECHANGE / notification) | `sns-core/collectors/system.rs` + service |
| Retention delete | Transactional file+row prune; DATA_RETENTION_DELETE audit | `sns-core/storage/retention.rs` + storage task |
| Storage limits | Usage scan → STORAGE_WARNING/CRITICAL events | `sns-core/health.rs` + storage task |
| Health publisher | Write `runtime/health.json` for CLI/admin | `sns-service/agent.rs` |
| Admin HTTP server | axum on 127.0.0.1: login/session/CSRF/routes | `sns-admin/*` |
| Screenshot view | On-demand decrypt in memory, zeroize, audit each view | `sns-admin` + `sns-core` |
| React UI | 11 functional pages | `admin-ui/` |
| Installer | MSI custom actions wired to scripts | `installer/` |

## Implementation order (conservative, additive; schema unchanged)

1. Make it build: add missing `windows-sys` features, resolve `service_win.rs` /
   `keymgr.rs` against the real compiler. `cargo test --workspace` green.
2. Storage task: single-writer loop consuming a channel; retention delete + storage-limit
   events + health snapshot publisher.
3. Screenshot scheduler + DXGI capture; end-to-end capture→encrypt→hash→row.
4. Application + browser Win32 capture.
5. Session + USB events from the service control handler / device notifications.
6. Admin HTTP server (axum) + on-demand screenshot decrypt endpoint.
7. React UI (Vite, bundled, no CDN).
8. Installer MSI custom actions + signing.
9. Release build; Windows service install; run acceptance scenario (§45).

After each module: build → test → security-review → fix → document.

## Testing requirements (spec §24, §28, §37, §45)

- `cargo test --workspace` green on Windows (unit: crypto, chain, config, retention,
  domain, keyring, storage).
- Integrity matrix: valid PASS; content edit FAIL; deleted row FAIL; broken previous-hash
  FAIL; valid append PASS.
- Crash/recovery: kill mid-write → reopen → integrity_check ok, committed events present,
  chain valid, no duplicate explosion.
- Screenshot: encrypted file not openable as image; SHA-256 matches; tamper → viewer
  rejects + integrity/security event.

## Windows verification requirements (spec §4–9, §31–41)

- Service installs, auto-start (delayed), runs as LocalSystem.
- Terminal-closure: `sns-agentctl status`, close CMD, service still RUNNING (not a child).
- Logout/login: service continues.
- Restart: clean stop → auto-start → prior data intact → integrity PASS.
- Shutdown: silent, AGENT_SHUTDOWN written, no popups/monitoring UI, no corruption.
- Offline: disconnect NIC → collection continues, nothing blocks.
- One dedicated test PC (`SNS-TEST-001`), multi-day run, then `PHASE1-TEST-REPORT.md`.

## Explicitly NOT in this phase (spec §44)

PostgreSQL, remote API, cloud/object storage, central server/auth, remote admin, sync
scheduler, remote upload. Phase-2 traits/docs kept for compatibility only.
