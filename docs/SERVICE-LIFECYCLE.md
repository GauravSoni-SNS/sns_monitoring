# SERVICE-LIFECYCLE.md

## Service identity

- Service name: `SNSSecurityAgent`
- Display name: `SNS Endpoint Security Agent`
- Account: `LocalSystem`
- Start type: `Automatic (Delayed Start)` — lets Windows finish critical boot first.
- Accepted controls: `STOP`, `SHUTDOWN`, `PRESHUTDOWN`, `SESSIONCHANGE`, `POWEREVENT`.

## Startup (spec §3, §35)

```
Power on → Windows boot → SCM launches SNSSecurityAgent (auto-delayed)
  ServiceMain:
    register control handler
    report START_PENDING (checkpoint++, wait_hint)
    Agent.boot():
      1. load + validate config\agent.json, policy\policy.json
      2. KeyManager.init(): DPAPI-unwrap DEK into Zeroizing buffer
      3. open activity.db; PRAGMA journal_mode=WAL; synchronous=NORMAL; foreign_keys=ON
      4. PRAGMA integrity_check  (fail → INTEGRITY_FAILURE, enter degraded read-safe mode)
      5. tail-verify hash chain (last N events)
      6. upsert devices row; refresh hostname/ip/last_seen
      7. write AGENT_STARTUP; if boot-since-last-shutdown looks fresh, write SYSTEM_STARTUP
      8. start collectors (each in its own task)
    report RUNNING
```

No terminal, no click-to-start (spec §29, §35).

## Run loop

SCM control requests are pumped on the service thread and forwarded to the agent via a control
channel. Collectors run as independent async tasks under a Tokio runtime owned by the agent.

## Session changes (spec §5, §37)

`SESSIONCHANGE` notifications map to events (no secrets captured):

| WM notification | Event |
|---|---|
| `WTS_SESSION_LOGON` | `USER_SESSION_STARTED` |
| `WTS_SESSION_LOGOFF` | `USER_SESSION_ENDED` |
| `WTS_SESSION_LOCK` / `UNLOCK` | recorded as session metadata |
| fast-user-switch (`CONSOLE_CONNECT/DISCONNECT`) | session start/end for that session id |

Logoff/login **must not** stop the service — it runs at machine scope, independent of any user
session or terminal.

## Shutdown (spec §6, §7, §28, §34)

```
STOP | SHUTDOWN | PRESHUTDOWN received
  report STOP_PENDING (generous wait_hint; PRESHUTDOWN gives more time)
  reason = classify(control)   // SERVICE_STOP | WINDOWS_SHUTDOWN | PRESHUTDOWN
  1. signal collectors: stop accepting new events
  2. drain EventBus into storage
  3. if a screenshot capture is mid-flight and can finish safely, finish it; else drop temp file
  4. commit any open transaction
  5. write AGENT_SHUTDOWN { timestamp_utc, device_id, agent_version, reason }
  6. PRAGMA wal_checkpoint(TRUNCATE)
  7. close DB; KeyManager.zeroize()
  report STOPPED
```

Never force-kill, never delete data, never leave a txn open, never show a shutdown dialog. Silent.

## Crash recovery (spec §8, §27, §42)

- **Durability:** WAL + one transaction per committed event ⇒ committed events survive crash/power
  loss. Uncommitted work is lost by design (never assume shutdown code runs).
- **On next boot:** `integrity_check` + WAL auto-recovery; if the previous run left no
  `AGENT_SHUTDOWN` before this `AGENT_STARTUP`, record an inferred ungraceful-stop marker.
- **Orphan cleanup:** temp screenshot files with no committed DB row are deleted.
- **Collector fault isolation:** supervisor catches a collector error/panic, logs it, and restarts
  that collector with exponential backoff (cap). Other collectors keep running (spec §42).
- **Windows Service recovery:** SCM failure actions = restart after 60s / 60s / then every 5 min;
  reset count daily. Prevents rapid restart loops (spec §27). Agent also self-guards against
  crash-storms by widening its own backoff.

## Uninstall (spec §39)

Stop service → flush/commit → close DB → zeroize keys → write `AGENT_SHUTDOWN{reason=UNINSTALL}` →
per-policy preserve or securely wipe data → remove service → remove binaries. Always uninstallable.
