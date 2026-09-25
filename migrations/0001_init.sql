-- SNS Endpoint Security — Phase 1 schema (spec §14)
-- Applied at install. WAL/pragmas are set by the app at open time, not here.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL          -- ISO-8601 UTC
);

-- One row: this host.
CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     TEXT NOT NULL UNIQUE,          -- dev_<ULID>, immutable
    system_name   TEXT NOT NULL,                 -- admin-set, mutable
    hostname      TEXT,
    os_version    TEXT,
    agent_version TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    last_seen_at  TEXT
);

-- Observed local sessions. No auth secrets ever stored.
CREATE TABLE IF NOT EXISTS users (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id          TEXT NOT NULL,
    user_identifier    TEXT NOT NULL,            -- e.g. DOMAIN\user or SID (no passwords)
    session_identifier TEXT,
    created_at         TEXT NOT NULL,
    last_seen_at       TEXT,
    UNIQUE (device_id, user_identifier, session_identifier),
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

-- Activity + lifecycle events. Hash chain lives here (spec §22).
CREATE TABLE IF NOT EXISTS activity_events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id            TEXT NOT NULL UNIQUE,     -- evt_<ULID>
    device_id           TEXT NOT NULL,
    user_id             INTEGER,
    event_type          TEXT NOT NULL,           -- controlled enum (spec §16)
    timestamp_utc       TEXT NOT NULL,
    application_name    TEXT,
    process_name        TEXT,
    window_title        TEXT,
    metadata_json       TEXT,
    event_hash          TEXT NOT NULL,           -- SHA-256(canonical || previous_event_hash)
    previous_event_hash TEXT NOT NULL,           -- genesis = 64 zero hex chars
    created_at          TEXT NOT NULL,
    sync_status         TEXT NOT NULL DEFAULT 'LOCAL_ONLY',
    FOREIGN KEY (device_id) REFERENCES devices(device_id),
    FOREIGN KEY (user_id)   REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS browser_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id         TEXT NOT NULL UNIQUE,       -- evt_<ULID>
    device_id        TEXT NOT NULL,
    browser          TEXT NOT NULL,              -- chrome | edge | firefox
    url_or_domain    TEXT,
    timestamp_utc    TEXT NOT NULL,
    duration_seconds INTEGER,
    created_at       TEXT NOT NULL,
    sync_status      TEXT NOT NULL DEFAULT 'LOCAL_ONLY',
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

CREATE TABLE IF NOT EXISTS screenshots (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    screenshot_id      TEXT NOT NULL UNIQUE,     -- scr_<ULID>
    device_id          TEXT NOT NULL,
    timestamp_utc      TEXT NOT NULL,
    file_path          TEXT NOT NULL,
    file_size          INTEGER,
    sha256             TEXT NOT NULL,            -- of ciphertext
    encryption_version INTEGER NOT NULL,
    monitor_id         INTEGER,
    created_at         TEXT NOT NULL,
    sync_status        TEXT NOT NULL DEFAULT 'LOCAL_ONLY',
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

CREATE TABLE IF NOT EXISTS system_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      TEXT NOT NULL UNIQUE,          -- evt_<ULID>
    device_id     TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    metadata_json TEXT,
    created_at    TEXT NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

CREATE TABLE IF NOT EXISTS configuration_history (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    version            INTEGER NOT NULL,
    configuration_json TEXT NOT NULL,
    changed_at         TEXT NOT NULL,
    changed_by         TEXT
);

-- Append-only audit trail.
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    action        TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    actor         TEXT,
    metadata_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_activity_ts     ON activity_events(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_activity_sync   ON activity_events(sync_status);
CREATE INDEX IF NOT EXISTS idx_activity_type   ON activity_events(event_type);
CREATE INDEX IF NOT EXISTS idx_browser_ts      ON browser_events(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_browser_sync    ON browser_events(sync_status);
CREATE INDEX IF NOT EXISTS idx_screenshot_ts   ON screenshots(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_screenshot_sync ON screenshots(sync_status);
CREATE INDEX IF NOT EXISTS idx_system_ts       ON system_events(timestamp_utc);
