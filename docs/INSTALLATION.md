# INSTALLATION.md

Production install is via a signed **MSI** (WiX). Never `cargo run` in production (spec §2).

## Installer steps (spec §38)

1. Install binaries → `C:\Program Files\SNS\SecurityAgent\` (`sns-service.exe`, `sns-agentctl.exe`,
   `sns-admin.exe`, admin UI assets).
2. Create ProgramData tree `C:\ProgramData\SNS\SecurityAgent\...`.
3. Apply NTFS ACLs (SYSTEM+Admins full, Users none; `keys\` extra-restricted).
4. Create SQLite DB + run migrations (`0001_init.sql`).
5. Generate immutable `device_id`; write `agent.json`.
6. Initialize key protection: generate DEK, DPAPI-wrap (LocalMachine), write `keys/keyring.json`.
7. Register Windows Service `SNSSecurityAgent` (LocalSystem, auto-delayed).
8. Configure failure/recovery actions (restart 60s/60s/5min; reset daily).
9. Write default `policy.json`.
10. Run health check (`sns-agentctl health`).
11. Prompt admin for `System Name` + admin panel password (Argon2id-hashed).

CLI-driven install (silent/MDM):

```powershell
msiexec /i SNSSecurityAgent.msi /qn SYSTEM_NAME=SNS-PC-001 ADMIN_PASSWORD_FILE=C:\secure\pw.txt
```

## Uninstall (spec §39)

```powershell
msiexec /x SNSSecurityAgent.msi /qn PRESERVE_DATA=1
```

Stops service, flushes/commits DB, zeroizes keys, writes `AGENT_SHUTDOWN{reason=UNINSTALL}`,
preserves or securely wipes data per `PRESERVE_DATA`, removes service + binaries. Always
uninstallable (no covert persistence).

## Post-install verification (maps to §48 scenario)

```powershell
sc.exe query SNSSecurityAgent           # RUNNING, START_TYPE auto-delayed
sns-agentctl status
sns-agentctl health
sns-agentctl verify-integrity
```

Then reboot and confirm the service starts with no terminal and no user interaction.

## Dev vs prod

Terminal / `cargo build` / `cargo run` are for development, debugging, diagnostics, and admin
maintenance only. The production collector always runs under SCM (spec §2, §29).
