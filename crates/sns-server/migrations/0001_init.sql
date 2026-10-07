-- SNS central server schema. Multi-tenant: every row carries org_id and all access is
-- org-scoped. ULIDs from the agent make event/screenshot upload idempotent.

CREATE TABLE IF NOT EXISTS orgs (
    id                BIGSERIAL PRIMARY KEY,
    name              TEXT NOT NULL,
    enroll_token_hash TEXT NOT NULL,           -- SHA-256 of the device enrollment token
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_users (
    id            BIGSERIAL PRIMARY KEY,
    org_id        BIGINT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    email         TEXT NOT NULL,
    password_hash TEXT NOT NULL,               -- Argon2id
    role          TEXT NOT NULL DEFAULT 'admin', -- 'admin' | 'viewer'
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (email)
);

CREATE TABLE IF NOT EXISTS devices (
    id            BIGSERIAL PRIMARY KEY,
    org_id        BIGINT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    device_id     TEXT NOT NULL,               -- agent's stable id (dev_…)
    system_name   TEXT,
    hostname      TEXT,
    os_version    TEXT,
    agent_version TEXT,
    last_seen_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, device_id)
);

CREATE TABLE IF NOT EXISTS device_tokens (
    id         BIGSERIAL PRIMARY KEY,
    org_id     BIGINT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    device_pk  BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,                  -- SHA-256 of the bearer token
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    UNIQUE (token_hash)
);

CREATE TABLE IF NOT EXISTS events (
    id                  BIGSERIAL PRIMARY KEY,
    org_id              BIGINT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    device_pk           BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    event_id            TEXT NOT NULL,          -- ULID from the agent
    event_type          TEXT NOT NULL,
    timestamp_utc       TEXT NOT NULL,          -- RFC-3339 (+05:30), as stored on the agent
    application_name    TEXT,
    window_title        TEXT,
    metadata_json       TEXT,
    event_hash          TEXT,
    previous_event_hash TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, event_id)                  -- idempotent upload
);
CREATE INDEX IF NOT EXISTS events_org_device_ts ON events (org_id, device_pk, timestamp_utc);
CREATE INDEX IF NOT EXISTS events_org_type ON events (org_id, event_type);

CREATE TABLE IF NOT EXISTS screenshots (
    id            BIGSERIAL PRIMARY KEY,
    org_id        BIGINT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    device_pk     BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    screenshot_id TEXT NOT NULL,               -- ULID from the agent
    timestamp_utc TEXT NOT NULL,
    sha256        TEXT,
    file_size     BIGINT,
    monitor_id    INT,
    blob_url      TEXT,                         -- object-storage pointer (Phase-D.2)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, screenshot_id)
);
CREATE INDEX IF NOT EXISTS screenshots_org_device_ts ON screenshots (org_id, device_pk, timestamp_utc);
