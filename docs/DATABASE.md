# DATABASE.md

SQLite, single file `database\activity.db`. WAL mode, `synchronous=NORMAL`, `foreign_keys=ON`,
`busy_timeout=5000`. One writer task; readers use separate read-only connections.

DDL of record: [`../migrations/0001_init.sql`](../migrations/0001_init.sql). This doc explains intent.

## Durability settings

- `journal_mode=WAL` — concurrent reads during writes; crash-safe rollback (spec §13).
- `synchronous=NORMAL` — safe with WAL; good throughput. (`FULL` optional via policy for max
  durability at cost of speed.)
- One transaction per committed event; batch only within a single write task tick.
- `wal_checkpoint(TRUNCATE)` on graceful shutdown and periodically by the storage task.

## Identity {#identity}

`device_id` (`dev_`+ULID) is generated once at install, stored in both `config/agent.json` and the
`devices` row, and is **immutable** (spec §9–11). `system_name` is admin-set and mutable; changing
it updates the `devices` row, appends `configuration_history`, and emits `CONFIGURATION_CHANGED` —
but never mints a new `device_id`. `hostname`/`current_ip` are supplementary, refreshed on
`last_seen`. IP is never an identifier.

## Tables (spec §14)

- **devices** — one row (this host): `device_id`, `system_name`, `hostname`, `os_version`,
  `agent_version`, `created_at`, `updated_at`, `last_seen_at`.
- **users** — observed local sessions: `device_id`, `user_identifier`, `session_identifier`,
  `created_at`, `last_seen_at`. No auth secrets.
- **activity_events** — `event_id` (ULID, unique), `device_id`, `user_id`, `event_type`,
  `timestamp_utc`, `application_name`, `process_name`, `window_title`, `metadata_json`,
  `event_hash`, `previous_event_hash`, `created_at`, `sync_status`. Hash chain lives here.
- **browser_events** — `event_id`, `device_id`, `browser`, `url_or_domain`, `timestamp_utc`,
  `duration_seconds`, `created_at`, `sync_status`.
- **screenshots** — `screenshot_id`, `device_id`, `timestamp_utc`, `file_path`, `file_size`,
  `sha256`, `encryption_version`, `monitor_id`, `created_at`, `sync_status`.
- **system_events** — `event_id`, `device_id`, `event_type`, `timestamp_utc`, `metadata_json`,
  `created_at`.
- **configuration_history** — `version`, `configuration_json`, `changed_at`, `changed_by`.
- **audit_log** — append-only: `action`, `timestamp_utc`, `actor`, `metadata_json`.
- **schema_migrations** — applied migration versions.

## IDs (spec §15)

Every syncable event has a unique `event_id` = ULID (`evt_`/`scr_` prefixed at the app layer).
ULIDs are lexicographically time-sortable and collision-safe, enabling Phase-2 idempotent
dedup/upsert. Integer PKs exist only as local rowids and are never used for identity/sync.

## sync_status (spec §24)

Enum on every syncable row: `LOCAL_ONLY` (default in Phase 1) → `QUEUED` → `SYNCING` → `SYNCED` /
`SYNC_FAILED`. Phase 1 writes only `LOCAL_ONLY`. Indexed for the Phase-2 uploader to scan cheaply.

## Indexes

`activity_events(timestamp_utc)`, `activity_events(sync_status)`, `activity_events(event_type)`,
`browser_events(timestamp_utc)`, `screenshots(timestamp_utc)`, `screenshots(sync_status)`,
unique on each `event_id`/`screenshot_id`.

## Retention interaction

Retention deletes are transactional and respect the "never delete un-synced data unless policy
permits" rule (spec §25). In Phase 1 nothing is synced, so default retention only prunes rows/files
older than the configured window **and** flagged deletable by policy.
