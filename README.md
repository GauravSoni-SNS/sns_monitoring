# SNS Endpoint Security & Activity Audit — Phase 1

Enterprise endpoint activity/security agent for **authorized company-managed Windows devices**.
Runs as a background Windows Service. Terminal-independent. Offline-first. Encrypted local storage.
Integrity-protected. Crash-safe. Graceful shutdown. Phase-2-ready (no sync yet).

> **Authorized-use boundary.** This software must run only on company-owned/managed devices under a
> written monitoring policy that has been disclosed to device users as required by applicable law.
> It deliberately **does not** implement keylogging, password/credential/cookie capture, webcam/mic
> recording, rootkits, AV evasion, or covert persistence. See [`docs/SECURITY.md`](docs/SECURITY.md).

## What Phase 1 does

- Installs as a proper, identifiable Windows Service (`SNSSecurityAgent`) — auto-start on boot.
- Collects application/window-focus activity, browser domain activity, periodic screenshots,
  USB attach/detach, and session/system/agent lifecycle events.
- Stores everything locally in encrypted files + a SQLite database (WAL, transactional).
- Chains events with hashes for tamper-evidence.
- Enforces storage quota + retention policy.
- Exposes an authenticated **localhost-only** admin panel and a `sns-agentctl` diagnostic CLI
  that talk *to* the service (they never run the collectors themselves).

## What Phase 1 does NOT do

- No network sync / no central server (Phase 2). Records carry a `sync_status` so Phase 2 is a drop-in.

## Layout

```
sns-endpoint-security/
├── Cargo.toml                 # Rust workspace
├── crates/
│   ├── sns-shared/            # models, event types, IDs, schemas
│   ├── sns-core/              # config, identity, storage, security, health, collectors
│   ├── sns-service/           # Windows Service host (production entrypoint)
│   ├── sns-agentctl/          # diagnostic CLI (talks to service over local IPC)
│   └── sns-admin/             # localhost admin HTTP backend
├── admin-ui/                  # React admin frontend (served by sns-admin)
├── installer/                 # WiX / MSI + PowerShell install scripts
├── migrations/                # SQLite schema migrations
├── docs/                      # architecture + security + lifecycle docs
└── tests/                     # integration + scenario tests
```

## Build (dev)

```bash
cargo build --workspace
```

Production is installed via the MSI in `installer/` — never `cargo run` in production. See
[`docs/INSTALLATION.md`](docs/INSTALLATION.md).

## Status of this tree

Phase-1 foundation. See [`docs/BUILD-STATUS.md`](docs/BUILD-STATUS.md) for what is implemented vs
scaffolded, mapped to the spec's 18-step development order.
