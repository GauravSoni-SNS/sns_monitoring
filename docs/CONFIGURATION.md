# CONFIGURATION.md

Two files under `config\`, both ACL-restricted to SYSTEM + Administrators. Loaded and
schema-validated at boot; invalid config → refuse to start collectors, log, stay in safe mode
(spec §40, §42).

## agent.json (identity + runtime)

```json
{
  "schema_version": 1,
  "device_id": "dev_01KABCDEF...",         // immutable, generated at install
  "system_name": "SNS-PC-001",             // admin-set, mutable
  "agent_version": "1.0.0",
  "admin": {
    "bind": "127.0.0.1",
    "port": 7731,
    "password_hash": "$argon2id$...",      // Argon2id, never plaintext
    "session_ttl_seconds": 1800
  },
  "logging": { "level": "info", "max_file_mb": 20, "max_files": 10 }
}
```

## policy.json (collection policy)

```json
{
  "schema_version": 1,
  "screenshot":   { "enabled": true, "interval_seconds": 900, "monitors": "all", "max_dimension": 1920 },
  "application":  { "enabled": true, "capture_window_title": true },
  "browser":      { "enabled": true, "granularity": "domain" },
  "usb":          { "enabled": true },
  "storage":      { "max_bytes": 10737418240, "warn_pct": 80, "critical_pct": 90 },
  "retention":    { "screenshot_days": 7, "event_days": 30, "delete_unsynced": false },
  "durability":   { "sqlite_synchronous": "NORMAL" }
}
```

## Change management (spec §14, §16)

Any authorized change (via admin panel):

1. Validate against schema.
2. Append to `configuration_history` (`version`, `configuration_json`, `changed_at`, `changed_by`).
3. Emit `CONFIGURATION_CHANGED`.
4. Write `audit_log` entry.
5. Hot-apply where safe (interval, thresholds); require restart only for bind/port changes.

`system_name` changes follow this path and never alter `device_id` (spec §10).

## Validation rules (examples)

- `interval_seconds >= 60` when screenshots enabled.
- `warn_pct < critical_pct <= 100`.
- `max_bytes > 0`; `admin.bind` must be a loopback address by default.
- Unknown keys rejected; `schema_version` must match a known migration.
