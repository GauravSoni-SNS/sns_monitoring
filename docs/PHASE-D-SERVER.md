# PHASE-D-SERVER.md — Central org-wide server

Multi-tenant central server: every business (org) is isolated; its boss (org admin) signs in
and sees **all their org's devices**. Agents sync their already-encrypted, integrity-chained
events to the server over HTTPS (internet + LAN), authenticated per-device.

## Decisions (locked)
- **Storage:** PostgreSQL (scales to many devices/orgs). Screenshot blobs: object storage
  (S3-compatible) — Phase-D.2; metadata lands in Postgres first.
- **Reach:** internet + LAN, over TLS (terminate at a reverse proxy, e.g. Caddy/Nginx, or
  natively). Agents hold a **per-device bearer token** (random, stored server-side as SHA-256).
- **Tenancy:** `org_id` on every row; every query is scoped to the authenticated principal's
  org. A device token only ever reads/writes its own org; an admin session only sees its org.

## Components
- `sns-server` (new crate): axum HTTP API + Postgres (`sqlx`).
- Agent sync engine (in `sns-core`, Phase-D.2): drains `queue/pending` → HTTPS upload,
  idempotent on the existing ULIDs, retry/backoff, `sync_status` transitions.
- Central dashboard (Phase-D.3): multi-device admin UI (org login, device list, cross-device
  timeline/usage/alerts/transfers/screenshots).

## Data model (migrations/0001_init.sql)
- `orgs(id, name, enroll_token_hash, created_at)` — one per business; enroll token lets new
  devices self-register into the org.
- `admin_users(id, org_id, email, password_hash, role, created_at)` — the boss + any viewers.
- `devices(id, org_id, device_id, system_name, hostname, os_version, agent_version,
  last_seen_at, created_at)` — `device_id` is the agent's stable id, unique per org.
- `device_tokens(id, org_id, device_pk, token_hash, created_at, revoked_at)`.
- `events(id, org_id, device_pk, event_id, event_type, timestamp_utc, application_name,
  window_title, metadata_json, event_hash, previous_event_hash, created_at)` — `event_id`
  (ULID) unique per org ⇒ idempotent upload.
- `screenshots(id, org_id, device_pk, screenshot_id, timestamp_utc, sha256, file_size,
  monitor_id, blob_url, created_at)` — `blob_url` points at object storage (Phase-D.2).

## API (v1)
- `POST /api/v1/devices/register` — body: enroll token + system/host/os ⇒ `{device_id, token}`.
  The token is shown once; the server keeps only its hash.
- `POST /api/v1/ingest/events` — Bearer device token; batch of events; upsert on `event_id`.
- `POST /api/v1/ingest/screenshots` — Bearer device token; metadata now, blob upload Phase-D.2.
- `POST /api/v1/admin/login` — org admin ⇒ session cookie + CSRF.
- `GET  /api/v1/admin/devices` — org's devices.
- `GET  /api/v1/admin/events?device=&from=&to=&type=` — org-scoped query.
- `GET  /api/v1/healthz` — liveness.

## Security
- Device tokens: 256-bit random, transmitted once, stored as SHA-256; revocable.
- Admin auth: Argon2id password, session cookie + CSRF (same model as the local panel).
- Strict org scoping on every handler (principal carries `org_id`; no cross-org reads).
- TLS required in production (reverse proxy or native rustls).
- The chain hashes travel with the events, so the server can re-verify per device.

## Build/deploy
- `DATABASE_URL=postgres://…` + `sqlx migrate run` then run `sns-server` (binds `0.0.0.0:8443`
  behind TLS, or `127.0.0.1:8080` behind a proxy).
- Runtime-checked `sqlx::query` (no compile-time DB needed); migrations create the schema.

## Quickstart (local test)
1. Run Postgres (Docker):
   ```
   docker run -d --name sns-pg -e POSTGRES_PASSWORD=snspass -e POSTGRES_DB=sns -p 5432:5432 postgres:16
   ```
2. Set the URL and provision a business + its boss:
   ```
   set DATABASE_URL=postgres://postgres:snspass@localhost:5432/sns
   sns-server provision-org --name "Acme" --admin-email boss@acme.com --admin-password "StrongPass1"
   ```
   It prints a **device enroll token** (shown once).
3. Start the server:
   ```
   sns-server serve            # listens 0.0.0.0:8080 (put TLS in front for internet)
   ```
4. Health check: `GET http://localhost:8080/api/v1/healthz` → `{"ok":true}`.
5. (D.2) Point an agent at the server with the enroll token; it registers and starts syncing.

## Staging
- **D.1 — ✅ DONE (verified live on Neon Postgres):** server crate, schema, device register +
  token auth, idempotent event ingest, admin login + org-scoped device/event queries. Tested
  end-to-end: register → ingest (dup→accepted:0) → admin login → org-scoped query → 401 w/o auth.
- **D.2 — ✅ DONE (events sync):** agent sync engine (`sns-service::sync`): registers once with
  the enroll token, persists the returned device token to policy.json, then uploads un-synced
  events in batches over HTTPS (`ureq`+rustls), marking them SYNCED only on server acceptance.
  Throttled to ~60s in the service maintenance loop. `sns-agentctl enroll --server <url>
  --token <enroll>` turns it on. Storage queue (`unsynced_events`/`mark_events_synced`) + batch
  logic unit-tested. (This is the agent's only outbound path; off unless configured.)
- **D.3 — ✅ DONE (verified live on Neon):** central dashboard served by `sns-server` at `/`
  (single embedded page, no build step). Boss signs in (org-scoped) → KPIs (devices online/
  offline) → device list → click a device → its events with type + IST date filters. Verified
  end-to-end in a browser against the live Neon DB.
- **D.2b — next:** central screenshots — agent re-encrypts each frame under an **org public key**
  (boss holds the private key), uploads the blob to object storage; dashboard decrypts for the
  boss. (Server never sees plaintext or the device's local key.)
- **Capability adds (no driver needed):** MTP phone file-list (WPD COM), network transfer
  volume per app (ETW), Bluetooth device identity (SetupDi).
- **Later / optional:** desktop-app wrapper (Tauri) for the dashboard; WFP kernel driver to
  *block* transfers (not just observe).
