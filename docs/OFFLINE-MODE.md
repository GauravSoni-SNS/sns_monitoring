# OFFLINE-MODE.md

## Principle (spec §23)

Phase 1 needs **no internet**. No network call is ever on the collection path. Collection, encryption,
hashing, and local storage are fully local and never block on connectivity.

```
Internet OFF
  10:00 APPLICATION_STARTED   → stored
  10:15 SCREENSHOT_CREATED    → stored
  10:30 BROWSER_ACTIVITY      → stored
  10:45 ACTIVE_APP_CHANGED    → stored
  11:00 SCREENSHOT_CREATED    → stored
All present locally, encrypted, chained.
```

## sync_status (spec §24)

Every syncable record is written `LOCAL_ONLY`. The state machine (Phase-2-ready, inert in Phase 1):

```
LOCAL_ONLY → QUEUED → SYNCING → SYNCED
                        └────→ SYNC_FAILED → (retry) QUEUED
```

## Phase-2-ready spool

`queue\pending\` exists now but is unused in Phase 1. Phase-2 `SyncQueue` will enqueue references to
`LOCAL_ONLY` rows; uploads are idempotent via ULID `event_id`. No data is deleted for being un-synced
(spec §25).

## Failure independence

If any future network dependency is added, it must degrade to offline: a failed/absent server can
never stop or slow local collection. This is enforced by keeping collectors and storage free of any
network handle in Phase 1.
