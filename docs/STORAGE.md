# STORAGE.md

## Root

`C:\ProgramData\SNS\SecurityAgent\` — see [`ARCHITECTURE.md`](ARCHITECTURE.md#3-folder-structure)
for the tree. ACLs: SYSTEM + Administrators full, Users none (spec §12, §40). Not disguised, not
hidden-as-system.

## Screenshot files

- Path: `data\<YYYY>\<MM>\<DD>\screenshots\screenshot_<ulid>.enc`
- Body: PNG (downscaled/compressed) → AES-256-GCM ciphertext. Opaque ULID filename (spec §20).
- Sidecar manifest under `...\manifests\` records SHA-256 + key_version for offline audit; DB row is
  source of truth.

## Quota & retention (spec §25)

Defaults (all configurable in `policy.json`):

| Setting | Default |
|---|---|
| Max local storage | 10 GB |
| Screenshot retention | 7 days |
| Event retention | 30 days |
| Warning threshold | 80% |
| Critical threshold | 90% |

- At 80% → `STORAGE_WARNING` event + admin-panel flag.
- At 90% → `STORAGE_CRITICAL`; retention manager runs an eager prune of policy-deletable data.
- **Never** delete un-synced data purely because the network is down, unless the retention/storage
  policy explicitly permits it. In Phase 1 the "deletable" predicate = `age > window`.

## Retention algorithm

```
loop (every retention_interval):
  compute usage(root)
  if usage >= critical: emit STORAGE_CRITICAL; prune_aggressively()
  elif usage >= warning: emit STORAGE_WARNING
  prune():
    delete screenshots where age > screenshot_retention AND policy_deletable  (file + row, txn)
    delete activity/browser/system events where age > event_retention AND policy_deletable
    wal_checkpoint(TRUNCATE)
```

Deletes are transactional; the file is unlinked only after the row delete commits (or the row is
tombstoned first, then file removed) to avoid dangling references.

## Durability

DB durability in [`DATABASE.md`](DATABASE.md). Screenshot files are `fsync`'d before the DB row is
committed, so a committed row always has a readable file; a crash between file-write and commit
leaves an orphan file cleaned up on next boot.
