# PHASE-2-PLAN.md

Phase 2 adds central sync. **Not implemented in Phase 1** — only prepared for (spec §47).

---

## Phase 2 scope (planned features)

All features operate **only on managed devices under a written, disclosed monitoring
policy**. Phase 2 keeps the Phase-1 boundary: no browser injection, no reading of a
browser's private-mode memory/stores, no cookie/token/password/history-store extraction,
no covert/hidden behavior. Everything below is **live OS-level observation** or
aggregation of already-collected local data.

### A. Better admin UI (React) — ✅ DONE
React + Vite + TS SPA in `admin-ui/`, built and **embedded** into `sns-admin` (rust-embed,
no CDN, single exe), served at `/` with `/api/*` behind it. Views: Dashboard (KPI cards),
Usage Time (bar charts), Timeline, Browser, Screenshots (grid → on-demand decrypt view),
System Events, Storage, Audit, Integrity (run + result), Configuration. Same auth model
(Argon2id, loopback, session cookie, CSRF, rate-limit). Verified end-to-end in a browser:
login → dashboard with live data → all views render.

### B. Application + browser usage-time tracking — ✅ DONE
`Storage::usage_by()` aggregates **focus duration** from the ordered event stream
(`ACTIVE_APPLICATION_CHANGED` for apps, `BROWSER_ACTIVITY` for domains): each segment = gap
to the next focus change, **capped at 15 min** so an idle-but-focused window doesn't inflate
totals. `/api/usage?kind=app|browser&days=N` → top-N per-name seconds + session count,
rendered as bar charts. Pure aggregation over already-collected data; no new capture surface.
Unit-tested (idle cap + per-name sum + sort).

### C. Browser activity — live URL/domain (mode-agnostic)
Enhance the browser collector to read the **foreground** browser tab's URL/domain from the
visible window via **UI Automation** (address-bar value) + window title. This is live
foreground observation — the same thing a screenshot shows — so it naturally covers any
mode (normal, guest, private) that is currently on screen. It is **not** history recovery
and **not** reading the browser's private store; if no browser window is in the foreground,
nothing is captured. Per-domain visit duration is derived like app usage-time (B).
Granularity (domain vs full URL) stays policy-controlled; default = domain.

> Explicitly NOT in scope: defeating private-mode isolation, browser process injection,
> extension-based capture of another profile's data, or reconstructing history the browser
> chose not to keep. Those are refused.

### D. Central sync + server (the original Phase-2 core)
Agent → encrypted local store → secure API → PostgreSQL + object storage, per the
architecture below. Idempotent upload keyed on the existing ULIDs; `sync_status` drives the
queue. Multi-device central dashboard, TLS + per-device auth, server-side authz.

### E. USB events — ✅ DONE
USB **mass-storage** connect/disconnect (the data-exfil case): the session-0 service polls
removable drives each tick (`GetLogicalDrives`/`GetDriveTypeW`/`GetVolumeInformationW`),
diffs the set, and chains `USB_DEVICE_CONNECTED`/`USB_DEVICE_DISCONNECTED` with **drive
letter + volume label only** — never file contents (spec §16). Baselined at boot so an
already-inserted stick is not re-reported. Diff logic unit-tested; live enumeration verified.
Shown in the admin **System Events** view. (Broader device-class enumeration via
`RegisterDeviceNotification` remains a later refinement.)

### Development order
1. React UI + usage-time charts (no new capture surface — safest, highest visible value).
2. Live browser URL via UI Automation + per-domain duration.
3. USB events.
4. Central API + PostgreSQL + object storage + multi-device dashboard.

Each feature: build → test → security review → confirm disclosure/consent posture → ship.

---

## Target architecture

```
Windows Agent → Encrypted Local Storage → Phase-2 Secure API
                                             ├→ PostgreSQL (events/metadata)
                                             └→ Object Storage (screenshot blobs)
```

## What Phase 1 already guarantees

- Stable `device_id` (immutable) and ULID `event_id`/`screenshot_id` on every syncable row ⇒
  **idempotent** upload (server upsert on unique id, safe to retry/dedup).
- `sync_status` column + index on every syncable table.
- `queue\pending\` spool directory.
- Encryption + integrity already applied at rest, so sync moves already-protected data.

## Interfaces defined now (traits, no network impl)

```
SyncService         orchestrates a sync cycle
EventUploader       push activity/browser/system events (batched, idempotent)
ScreenshotUploader  push encrypted blobs + metadata
DeviceRegistration  register/authenticate this device with server
SyncQueue           enqueue/dequeue LOCAL_ONLY→QUEUED refs
SyncRetry           backoff + SYNC_FAILED handling
ServerHealth        reachability/health probe
```

These live in `sns-shared` as traits with `todo!()`/no-op Phase-1 stubs so Phase-1 code compiles and
Phase-2 drops in implementations without schema changes.

## Sync flow (Phase 2)

```
scan LOCAL_ONLY rows → mark QUEUED → batch → SYNCING → POST /ingest (auth, TLS)
  → 2xx: mark SYNCED
  → error: SYNC_FAILED → SyncRetry backoff → QUEUED
Screenshots: upload ciphertext to object storage, then metadata row.
```

Never delete un-synced data (spec §25). Retention in Phase 2 keys off `SYNCED` + age.

## Security additions (Phase 2)

Mutual TLS or signed device tokens; server-side authz; per-device keys; transport separate from
at-rest DEK. Out of scope here; noted for design continuity.
