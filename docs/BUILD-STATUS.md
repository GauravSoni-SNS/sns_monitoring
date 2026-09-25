# BUILD-STATUS.md

Phase-1 progress against the spec §45 development order. **Verified** = built + run this
session with observed output (see PHASE1-TEST-REPORT.md). **Implemented** = built (compiles
in release), unit/logic covered. **Partial/Remaining** = see PHASE1-ISSUES.md.

Toolchain now present: Rust 1.97.1 msvc + VS Build Tools 14.44. `cargo build/test` run for real.

| # | Module (spec §45) | Status | Where |
|---|---|---|---|
| 1 | Architecture | Doc ✅ | `docs/ARCHITECTURE.md` + companions |
| 2 | Device identity | Verified ✅ | `sns-shared/ids.rs`, `sns-core/identity.rs` |
| 3 | Windows Service host | Implemented; shutdown/crash **verified**; SCM install not run (non-elevated) | `sns-service/service_win.rs`, `agent.rs`, `lib.rs`, `tests/lifecycle.rs` |
| 4 | SQLite storage + migrations | Verified ✅ | `migrations/0001_init.sql`, `sns-core/storage/db.rs` |
| 5 | Event model | Verified ✅ | `sns-shared/events.rs` |
| 6 | Application collector | **Verified** (real foreground capture) | `sns-core/collectors/application.rs`, `sns-useragent` |
| 7 | Browser collector | Implemented (wired; title-granularity) | `sns-core/collectors/browser.rs`, `sns-useragent` |
| 8 | Screenshot collector | **Verified** (real GDI capture → encrypt → store → ingest) | `sns-core/collectors/screenshot.rs`, `sns-useragent`, `storage/dropbox.rs` |
| 9 | Encryption + key mgmt | Verified ✅ (DPAPI wrap/unwrap live) | `sns-core/security/crypto.rs`, `keymgr.rs` |
| 10 | Integrity chain | Verified ✅ (matrix + live tamper 409) | `sns-shared/events.rs`, `sns-core/security/integrity.rs` |
| 11 | Offline queue | Implemented (status model) / Phase-2 traits | `sns-shared/sync.rs` |
| 12 | Retention | Verified ✅ (delete + un-synced protection + audit) | `sns-core/storage/{retention,db}.rs`, `sns-service/agent.rs` |
| 13 | Health | Verified ✅ (published `runtime/health.json`) | `sns-core/health.rs`, `sns-service/agent.rs` |
| 14 | Local admin panel | **Verified** (live login/read/decrypt/tamper) | `sns-admin/*` (axum + `index.html`) |
| 15 | Installer | Scripts + useragent task; WiX skeleton | `installer/install.ps1`, `uninstall.ps1`, `Product.wxs` |
| 16 | Service recovery | Implemented (SCM failure actions + backoff) | `installer/install.ps1`, `sns-service/agent.rs` |
| 17 | Testing | Unit + integration **verified**; live scenario partial | `#[cfg(test)]`, `tests/lifecycle.rs`, `docs/PHASE1-TEST-REPORT.md` |
| 18 | Security review | Doc ✅ / clippy + external review on test PC | `docs/SECURITY.md` |

### New in this session

- **`sns-useragent`** crate — user-session collector (session-0 bridge) for screenshots +
  app/browser, writing to `runtime/incoming/` (see SCREENSHOT.md, PHASE1-ISSUES ISSUE-1).
- **`storage/dropbox.rs`** — crash-safe, idempotent manifest ingest (single-writer preserved).
- **`sns-admin`** — full axum backend + functional served UI + on-demand screenshot decrypt.
- **`sns-service/tests/lifecycle.rs`** — graceful-shutdown + crash-recovery integration tests.

### Remaining for full acceptance (see PHASE1-ISSUES L-1..L-7)

Real SCM install/lifecycle on an elevated test PC; session/USB event emission; signed MSI;
UI-Automation browser URL; multi-monitor DXGI; React UI (optional, current UI is functional).

## What runs today (any OS, once a Rust toolchain is present)

```bash
cargo test --workspace     # unit tests: crypto round-trip/tamper, hash chain verify,
                           # config validation, retention predicates, domain extraction,
                           # keyring wrap/unwrap, storage insert+verify, focus-change logic
```

`sns-agentctl init` / `verify-integrity` / `status` / `diagnostics` work against a data
root on any OS (DPAPI is Windows-only; non-Windows uses the marked DEV key fallback).

## Remaining for a shippable Phase-1 on Windows (next steps, in order)

1. Win32 capture bodies: foreground window (step 6), browser tab via UI Automation (step 7),
   DXGI Desktop Duplication + PNG encode (step 8).
2. Screenshot interval timer + session/USB event wiring from the service control handler.
3. Retention delete execution (transactional file+row) on the storage task.
4. Health snapshot publisher → `runtime/health.json`.
5. `sns-admin` HTTP server (axum) + React UI build; on-demand screenshot decrypt endpoint.
6. WiX packaging (heat harvest, component GUIDs), Authenticode signing.
7. Windows service + §48 scenario test automation.
8. CI: fmt/clippy/audit/deny/gitleaks + Windows job.

No item above changes the schema, IDs, or interfaces already fixed — they are additive.
