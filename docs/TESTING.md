# TESTING.md

## Levels

- **Unit** — pure logic: ULID gen, event canonicalization + hash chain, config validation, crypto
  round-trip, retention predicate, sync-status transitions. Run on any OS (`cargo test`).
- **Integration** — storage layer against a temp SQLite DB: WAL recovery, transactional retention,
  concurrent read during write, integrity verify pass/fail.
- **Service/Windows** — require a Windows host or CI VM: service install/start/stop, session-change
  events, screenshot capture, DPAPI wrap/unwrap.
- **Scenario** — the full §48 acceptance flow.

## Crypto & integrity tests

- AES-GCM encrypt→decrypt round-trip; tamper a byte ⇒ decrypt fails (auth tag).
- Nonce uniqueness across N encryptions.
- Hash chain: build M events, verify PASS; mutate one row ⇒ verify reports exact break +
  `INTEGRITY_FAILURE` emitted.

## Crash/recovery tests (spec §8, §42)

- Kill process mid-write ⇒ reopen ⇒ `integrity_check` OK, committed events present, partial lost.
- Orphan screenshot file (no row) ⇒ cleaned on boot.
- Inject collector panic ⇒ supervisor restarts it, other collectors unaffected.
- Simulated power loss (WAL truncation) ⇒ recover committed events.

## §48 acceptance scenario (must pass)

```
install → configure SNS-PC-001 → service installed
 → reboot → service auto-starts (no terminal)
 → app activity collected → browser activity collected → screenshot @15m
 → disconnect internet → collection continues
 → open terminal → close terminal → collection continues
 → user logout → service continues → user login → collection resumes
 → reboot → previous data present → auto-start → verify-integrity PASS
 → storage limits enforced
 → Windows shutdown → agent flushes, AGENT_SHUTDOWN written, no UI shown → clean shutdown
```

Automated where possible (service control, DB assertions); manual checklist for reboot/logout/
shutdown-screen visual confirmation.

## CI gates

`cargo fmt --check` · `cargo clippy -D warnings` · `cargo test --workspace` · `cargo audit` ·
`cargo deny check` · gitleaks. Windows job additionally runs service + scenario suites.
