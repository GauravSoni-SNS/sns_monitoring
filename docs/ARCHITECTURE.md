# ARCHITECTURE — SNS Endpoint Security Agent (Phase 1)

This document is the architecture gate required before implementation (spec §49). It covers all 14
required items. Companion docs go deeper per subsystem (see cross-references).

---

## 1. Complete architecture

```
                         Windows OS
                             │
                   Service Control Manager (SCM)
                             │  start / stop / shutdown / power events
                             ▼
        ┌────────────────────────────────────────────────┐
        │        sns-service  (production entrypoint)      │
        │        runs as LocalSystem, no interactive UI    │
        │                                                  │
        │   ServiceMain ── control handler ── event loop   │
        └───────────────┬──────────────────────────────────┘
                        │ owns
                        ▼
        ┌────────────────────────────────────────────────┐
        │                 Agent (supervisor)               │
        │  boot: config → key mgr → db → integrity check   │
        │  supervises independent collectors w/ backoff    │
        └───┬───────┬───────┬────────┬───────┬────────┬────┘
            │       │       │        │       │        │
       Application Browser System  Screenshot Health Retention
        Collector Collector Collector Scheduler Manager Manager
            │       │       │        │
            └───────┴───────┴────────┘  emit Events
                        │
                        ▼
        ┌────────────────────────────────────────────────┐
        │                 EventBus (bounded MPSC)          │
        └───────────────┬──────────────────────────────────┘
                        ▼
        ┌────────────────────────────────────────────────┐
        │        Storage layer (single writer task)        │
        │  ┌──────────┐  ┌──────────────┐  ┌────────────┐  │
        │  │ Integrity│→ │ SQLite (WAL) │  │ Filesystem │  │
        │  │  chain   │  │ activity.db  │  │ screenshots│  │
        │  └──────────┘  └──────────────┘  └────────────┘  │
        └────────────────────────────────────────────────┘
                        ▲                         ▲
                        │ read-only               │ encrypt/decrypt
        ┌───────────────┴──────────┐    ┌─────────┴──────────┐
        │  sns-admin (localhost)   │    │  Security services  │
        │  + React UI (auth)       │    │  KeyManager (DPAPI) │
        │  sns-agentctl (IPC)      │    │  Crypto (AES-GCM)   │
        └──────────────────────────┘    └────────────────────┘
```

**Key design rules**

- **One writer.** All DB + integrity-chain writes go through a single storage task fed by a bounded
  channel. Removes lock contention and makes the hash chain strictly ordered. Readers (admin/CLI)
  use separate read-only connections (WAL allows concurrent reads).
- **Collector isolation.** Each collector is an independent async task. A panic/error in one is
  caught by the supervisor and restarted with backoff; it never takes down the others or the service
  (spec §42).
- **No terminal, no UI.** Production runs headless under SCM. Admin panel + CLI are *clients* of the
  service, not the collector host (spec §29).

---

## 2. Windows Service lifecycle

See [`SERVICE-LIFECYCLE.md`](SERVICE-LIFECYCLE.md) for full detail. Summary:

```
BOOT → SCM starts SNSSecurityAgent (auto-start, delayed)
  → ServiceMain registers control handler, reports START_PENDING
  → Agent.boot():
       load config + policy
       init KeyManager (unwrap data key via DPAPI-Machine)
       open SQLite, PRAGMA journal_mode=WAL, integrity_check
       run event-chain verification (fast tail check)
       write AGENT_STARTUP + (if applicable) SYSTEM_STARTUP
       start collectors
  → report RUNNING
RUN loop: service pumps SCM control requests; agent supervises collectors
STOP / SHUTDOWN / PRESHUTDOWN control received:
  → report STOP_PENDING (with wait hints)
  → signal collectors to stop accepting new events
  → drain EventBus, finish in-flight screenshot if safe
  → commit open transaction, write AGENT_SHUTDOWN{reason}
  → checkpoint WAL, close DB, zeroize keys
  → report STOPPED
```

Accepted controls: `STOP`, `SHUTDOWN`, `PRESHUTDOWN` (extra time before shutdown),
`SESSIONCHANGE` (logon/logoff/lock/unlock/fast-user-switch), `POWEREVENT`.

---

## 3. Folder structure

Repo layout is in [`README.md`](../README.md). Runtime data layout on target machine:

```
C:\ProgramData\SNS\SecurityAgent\
  config\      agent.json  policy.json          (ACL: SYSTEM+Admins full, Users none)
  database\    activity.db  activity.db-wal  activity.db-shm
  keys\        keyring.json                      (wrapped keys only, never plaintext)
  data\<YYYY>\<MM>\<DD>\screenshots\  manifests\
  queue\pending\                                 (Phase-2 sync spool)
  logs\        agent.log (rotating)
  cache\  runtime\  (pid, health snapshot, ipc socket)
```

NTFS ACLs applied by installer (spec §12, §40). No hidden/system-disguised paths.

---

## 4. SQLite schema

Full DDL in [`../migrations/0001_init.sql`](../migrations/0001_init.sql); design notes in
[`DATABASE.md`](DATABASE.md). Tables: `devices`, `users`, `activity_events`, `browser_events`,
`screenshots`, `system_events`, `configuration_history`, `audit_log`, plus `schema_migrations`.
Every synchronizable row carries `event_id` (ULID) + `sync_status`. Activity events carry
`event_hash` + `previous_event_hash` for the integrity chain.

---

## 5. Device identity design

See [`DATABASE.md`](DATABASE.md#identity). On first install a stable `device_id` = `dev_` + ULID is
generated and persisted in `config/agent.json` **and** the `devices` table. It never changes —
not on IP change, hostname change, or system-name change (spec §9–11). `system_name` is admin-set
(e.g. `SNS-PC-001`), mutable, and changing it writes a `CONFIGURATION_CHANGED` event but keeps the
same `device_id`. IP/hostname are refreshed as supplementary `last_seen` metadata only.

---

## 6. Encryption / key-management design

See [`SECURITY.md`](SECURITY.md). Summary:

- **Algorithm:** AES-256-GCM (via `aes-gcm`), 96-bit random nonce per message, no nonce reuse.
- **Key hierarchy:** a machine root secret protected by **Windows DPAPI** (`CryptProtectData`,
  `LocalMachine` scope) wraps a randomly generated 256-bit **Data Encryption Key (DEK)**. Only the
  wrapped DEK is stored (`keys/keyring.json`). Plaintext DEK lives in a `Zeroizing` buffer in memory.
- **Coverage:** screenshot blobs, sensitive local fields, admin credential hash salt/secret.
- **Rotation:** `key_version` on every ciphertext; new DEK generated on rotation, old kept for
  decrypt-only until re-encrypt or retention expiry.
- **Never logged, never in DB plaintext.** Keys zeroized on shutdown.

---

## 7. Screenshot lifecycle

See [`SCREENSHOT.md`](SCREENSHOT.md).

```
Timer(interval from policy, default 15m)
  → policy check (enabled? within allowed schedule?)
  → capture authorized display(s) via Windows GDI/DXGI
  → downscale + encode PNG → compress
  → AES-256-GCM encrypt → screenshot_<ulid>.enc
  → SHA-256 of ciphertext
  → write file (fsync) under data\Y\M\D\screenshots\
  → INSERT screenshots row (sync_status=LOCAL_ONLY) in one txn
  → emit SCREENSHOT_CREATED activity event
```

No continuous video, no webcam/mic. Filenames are opaque ULIDs, never timestamps (spec §20).

---

## 8. Offline-storage lifecycle

See [`OFFLINE-MODE.md`](OFFLINE-MODE.md). No network call is ever on the collection path. Every
record is written locally and marked `LOCAL_ONLY`. Phase 2 will flip records `LOCAL_ONLY → QUEUED →
SYNCING → SYNCED`. Storage manager enforces quota; retention never deletes un-synced data unless the
explicit storage/retention policy permits (spec §25).

---

## 9. Shutdown lifecycle

See §2 above and [`SERVICE-LIFECYCLE.md`](SERVICE-LIFECYCLE.md). On `STOP`/`SHUTDOWN`/`PRESHUTDOWN`:
stop intake → drain → finish safe screenshot → commit txn → `AGENT_SHUTDOWN{reason}` → WAL
checkpoint → close DB → zeroize keys → report STOPPED. Silent; no shutdown-screen UI (spec §34).
`reason` ∈ {`SERVICE_STOP`, `WINDOWS_SHUTDOWN`, `PRESHUTDOWN`, `UNINSTALL`}.

---

## 10. Crash-recovery design

See [`SERVICE-LIFECYCLE.md`](SERVICE-LIFECYCLE.md#crash-recovery). WAL + per-event transactions mean
a committed event is durable. On next boot: `PRAGMA integrity_check` → WAL auto-recovers →
tail-verify hash chain → detect that no `AGENT_SHUTDOWN` preceded this `AGENT_STARTUP` and record an
inferred ungraceful-stop marker in `system_events`. Partial/temporary screenshot files (no committed
DB row) are cleaned up. Windows Service recovery restarts the process with backoff (no rapid restart
loop, spec §27).

---

## 11. Threat model

See [`SECURITY.md`](SECURITY.md#threat-model). Assets: collected activity data, screenshots, DEK,
admin credentials, integrity chain. Adversaries considered:

| Adversary | Concern | Mitigation |
|---|---|---|
| Non-admin local user | Read/exfil collected data | NTFS ACLs (SYSTEM+Admins only), AES-GCM at rest |
| Local admin (insider) | Silent tamper of records | Hash chain → `INTEGRITY_FAILURE`; append-only audit_log; DPAPI-Machine key binds data to host |
| Malware on host | Steal DEK | DEK wrapped by DPAPI-Machine, zeroized in RAM, never on disk plaintext |
| Network attacker | Reach admin panel | Loopback bind only, auth required, no default remote exposure |
| Prompt-injection via captured content | N/A Phase 1 | Captured data is never executed/interpreted |

Out of scope for Phase 1: a full-admin/kernel attacker with physical DMA (documented, not defended).

---

## 12. Security model

Least privilege at every layer; strong FS ACLs; DPAPI-wrapped keys; AES-256-GCM at rest;
authenticated loopback admin (Argon2id password hash, session tokens); tamper-evident hash chain +
append-only audit log; secure config validation on load; signed MSI + binaries; dependency/secret
scanning in CI. No anti-AV / anti-EDR behavior. Full detail in [`SECURITY.md`](SECURITY.md).

---

## 13. Phase-2 migration strategy

See [`PHASE-2-PLAN.md`](PHASE-2-PLAN.md). Phase 1 ships stable global IDs (`device_id`, ULID
`event_id`s) and `sync_status` on every syncable row so Phase 2 sync is idempotent. Interfaces
`SyncService`, `EventUploader`, `ScreenshotUploader`, `DeviceRegistration`, `SyncQueue`,
`SyncRetry`, `ServerHealth` are defined as traits now (no network implementation). Target:
Agent → local encrypted store → Phase-2 secure API → PostgreSQL + object storage.

---

## 14. Development milestones

Spec §45 order, tracked in [`BUILD-STATUS.md`](BUILD-STATUS.md):

1. Architecture ✅ (this doc set)
2. Device identity
3. Windows Service host
4. SQLite storage + migrations
5. Event model
6. Application collector
7. Browser collector
8. Screenshot collector
9. Encryption + key mgmt
10. Integrity chain
11. Offline queue
12. Retention
13. Health
14. Local admin panel
15. Installer (MSI)
16. Service recovery
17. Testing (unit + scenario §48)
18. Security review

Each module: build → test → security-review → fix → document.
