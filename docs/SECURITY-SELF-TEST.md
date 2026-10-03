# SECURITY-SELF-TEST.md

Self-contained safety audit of the SNS agent, focused on **blast radius**: the agent must
affect **only the machine it runs on** and never reach, scan, or disturb other systems.

Run date: 2026-10-01. Method: static review (grep over all Rust) + live inspection of the
running processes. Re-run the live checks after any networking change.

## Findings — blast radius is the local machine only

| Area | Control | Evidence |
|------|---------|----------|
| Outbound network | No HTTP/SMTP/socket client anywhere | grep: no `reqwest`/`hyper client`/`ureq`/`Command`/`connect()` in `*.rs`; no such deps in `Cargo.toml`. Offline-first (spec §23). |
| Admin server exposure | Binds loopback only; non-loopback refused at startup | `config.rs::validate` rejects a non-loopback `admin.bind` (`agent_config_rejects_non_loopback_bind` test). `sns-admin/main.rs` binds `cfg.admin.bind:port` after `AgentConfig::load` (which validates). |
| Live listeners | None beyond loopback | `Get-NetTCPConnection -State Listen` filtered to SNS PIDs → none non-loopback. Admin serves `127.0.0.1:7731` only when running. |
| Live outbound | None | `Get-NetTCPConnection` for SNS PIDs with remote ∉ loopback → empty. |
| Process execution | No child processes / remote exec | grep: no `Command::new`, `CreateProcess`, `ShellExecute`, `WinExec`. |
| USB / devices | Read-only enumeration | `collectors/usb.rs` uses `SetupDiGetClassDevsW` + `GetLogicalDrives` (reads only); never opens device contents or writes. |
| Filesystem | Writes confined to the data root | All writes go through `root.join(...)` under `%ProgramData%\SNS\SecurityAgent`; DB ACL = SYSTEM + Administrators (installer). |
| Registry | One standard key | Only the Add/Remove-Programs (ARP) uninstall key in `install.ps1` (HKLM); removed on uninstall. No Rust registry writes. |
| Runaway processes | Single-instance guard | `singleton::acquire("Local\\SNSSecurityCaptureAgent")` — a duplicate exits immediately. |
| Fault isolation | Supervised collectors | A panicking collector is restarted in isolation (spec §42); no crash cascade. |

## Boundaries reaffirmed (unchanged from Phase 1)

No keystrokes, clipboard, passwords, cookies, tokens, or browser private-store extraction.
Browser URL capture (feature C) reads only the **on-screen** address bar via UI Automation.
Idle tracking (feature #2) reads only the **time** of last input, never the input itself.

## Live re-check commands (PowerShell)

```powershell
$pids = Get-CimInstance Win32_Process -Filter "Name LIKE 'sns-%'" | Select -Expand ProcessId
# Listeners owned by SNS (expect only 127.0.0.1:7731 when the panel runs):
Get-NetTCPConnection -State Listen | ? { $pids -contains $_.OwningProcess } |
  Select LocalAddress,LocalPort,OwningProcess
# Any non-loopback connection by SNS (expect none):
Get-NetTCPConnection | ? { $pids -contains $_.OwningProcess -and
  $_.RemoteAddress -notin '127.0.0.1','::1','0.0.0.0','::' }
```

## Verdict

The agent cannot disturb other systems: it opens no outbound connections, exposes only a
loopback admin port, spawns no processes, and writes only within its own data root. Safe to
run on the local machine without affecting the network or other hosts.
