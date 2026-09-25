# SCREENSHOT.md

## Policy (spec §19)

`policy.json → screenshot`:

```json
{ "enabled": true, "interval_seconds": 900, "monitors": "all", "max_dimension": 1920, "jpeg_quality": null }
```

Interval presets: Disabled · 15 min (default) · 30 min · custom. Configurable by authorized admin.

## Capture lifecycle

```
Timer fires (interval)
  → policy.enabled? in allowed schedule? else skip
  → enumerate authorized displays (DXGI Desktop Duplication; GDI BitBlt fallback)
  → for each monitor:
       grab frame → downscale to max_dimension → encode PNG → compress
       AES-256-GCM encrypt (fresh nonce) → bytes
       sha256(ciphertext)
       write screenshot_<ulid>.enc + fsync
       INSERT screenshots{screenshot_id, monitor_id, file_path, file_size, sha256,
                          encryption_version, timestamp_utc, sync_status=LOCAL_ONLY}  (txn)
       emit SCREENSHOT_CREATED activity event
```

- No continuous/video capture, no webcam, no microphone (spec §19).
- Capture failure is isolated: log + optional `metadata`, retry next tick; never crashes the agent
  (spec §42).
- During shutdown, an in-flight capture finishes only if safe; otherwise its temp file is discarded.

## Viewing (admin panel, spec §33)

Screenshots decrypt **on demand** only, server-side in `sns-admin`, streamed to the authenticated
localhost UI. Decrypted bytes are never written back to disk. Each view is written to `audit_log`.

## Naming (spec §20)

Opaque `screenshot_<ulid>.enc`. No time-encoded plaintext names. All metadata in SQLite.

## Session-0 isolation (IMPORTANT — architecture)

A `LocalSystem` service runs in **session 0**, which has no interactive desktop. A screen
grab from session 0 returns a black/empty frame, not the user's screen. The same applies to
foreground-window, window-title, and browser capture. This is a Windows security feature
(Session 0 Isolation, since Vista), not a limitation to be bypassed — and we do not bypass it.

**Topology (two components):**

- **`sns-service`** (session 0): owns SQLite, retention, health, admin panel, integrity,
  and session/USB lifecycle events (all reachable from session 0). It **detects session 0
  and never captures** (no black frames).
- **`sns-useragent`** (user session, started at logon by a visible scheduled task): performs
  interactive capture — screenshots (and, Task #4, app/browser) — where the desktop actually
  is. It encrypts with the machine-DPAPI DEK (LocalMachine scope is readable from the user
  session) and writes records to the drop box `runtime/incoming/`.
- **Drop box → ingest:** the service ingests manifests on its tick into SQLite (single writer
  = service), idempotently (unique ids; `INSERT OR IGNORE`), deleting a manifest only after
  its row is committed. Unparseable manifests are quarantined to `runtime/incoming/bad/`.

**Verified end-to-end** on a real interactive session: `sns-useragent` captured the live
screen, encrypted it, dropped a manifest; `sns-service` ingested it; the stored `.enc` file
is not a valid image; SQLite recorded the row and `SCREENSHOT_CREATED`; integrity PASS.

In dev `--console` mode the service itself runs in the user session, so its in-process
capture path also works (used for quick local testing).
