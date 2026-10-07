-- Per-org symmetric key (hex, 32 bytes) used to encrypt screenshot blobs at rest on the
-- server. The agent receives it at registration (over TLS), re-encrypts each screenshot under
-- it before upload; the dashboard decrypts it for the org's boss. Nullable for orgs created
-- before this column — backfilled lazily on the next device registration.
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS screenshot_key TEXT;
