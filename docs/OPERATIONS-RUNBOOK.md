# OPERATIONS RUNBOOK — SNS Endpoint Security Agent

Every command for install, run, view, uninstall — plus every error hit during the first real
setup and the exact fix. Run PowerShell **as Administrator** unless noted "normal user".

Authorized company-managed devices only, under a disclosed monitoring policy.

---

## 0. Locations

| What | Path |
|---|---|
| Binaries | `C:\Program Files\SNS\SecurityAgent\` |
| Data (encrypted screenshots + SQLite) | `C:\ProgramData\SNS\SecurityAgent\` |
| Config | `...\config\agent.json`, `...\config\policy.json` |
| Logs | `...\logs\agent.log`, `...\logs\useragent.log` |
| Service | `SNSSecurityAgent` (LocalSystem, auto-start) |
| Capture task | `SNSSecurityCapture` (runs `sns-useragent` at logon) |
| Admin panel | http://127.0.0.1:7731 (loopback only) |

Two components (Windows session-0 isolation):
- **`sns-service`** — session 0, owns DB / retention / health / ingest. Auto-starts at boot.
- **`sns-useragent`** — your logon session, captures screen + app + browser. Auto-starts at logon.
- **`sns-admin`** / **`sns-agentctl`** — on-demand tools you run to view data (need admin).

---

## 1. Install

**Simple (one machine):** unzip the bundle, double-click **`Install.cmd`**, click Yes on UAC,
enter a System Name + admin password.

**Silent / mass deploy (GPO/Intune), elevated:**
```powershell
powershell -ExecutionPolicy Bypass -File install.ps1 -SystemName SNS-PC-001 -AdminPassword (ConvertTo-SecureString 'YourPass' -AsPlainText -Force)
```

**Rebuild the bundle after code changes:**
```powershell
& "$env:USERPROFILE\.cargo\bin\cargo.exe" build --release --workspace
powershell -ExecutionPolicy Bypass -File installer\package.ps1
```

---

## 2. Start / stop / status

```powershell
Start-Service SNSSecurityAgent          # start service now (no reboot)
Stop-Service  SNSSecurityAgent          # graceful stop (writes AGENT_SHUTDOWN)
Get-Service   SNSSecurityAgent          # Running / Stopped
Start-ScheduledTask -TaskName "SNSSecurityCapture"   # start capture now
Get-Process sns-service, sns-useragent | Select Name, Id   # what's running
```

At real boot + logon both start automatically — no commands needed day to day.

---

## 3. View collected data (trial results)

Inspection tools read the protected DB, so run them **elevated**.

```powershell
# quick summary: event + screenshot counts, last screenshot, DB integrity
& "$env:ProgramFiles\SNS\SecurityAgent\sns-agentctl.exe" status

# tamper-evidence check over the whole chain
& "$env:ProgramFiles\SNS\SecurityAgent\sns-agentctl.exe" verify-integrity

# health snapshot
& "$env:ProgramFiles\SNS\SecurityAgent\sns-agentctl.exe" health

# full UI: run this, leave the window open, then browse the panel
& "$env:ProgramFiles\SNS\SecurityAgent\sns-admin.exe"
#   -> open http://127.0.0.1:7731  (sign in with the admin password)
#   -> Dashboard / Timeline / Browser / Screenshots (click to decrypt-view) /
#      System Events / Storage / Health / Configuration / Audit / Integrity
```

Ctrl-C the `sns-admin` window when done — the service + capture keep running.

---

## 4. Change screenshot interval / policy

Edit `C:\ProgramData\SNS\SecurityAgent\config\policy.json`, then restart the service.
```powershell
$p="C:\ProgramData\SNS\SecurityAgent\config\policy.json"
(Get-Content $p) -replace '"interval_seconds": 900','"interval_seconds": 30' | Set-Content $p   # test: 30s
Restart-Service SNSSecurityAgent
```
Set back to `900` (15 min) for normal use.

---

## 5. Uninstall

Double-click **`Uninstall.cmd`**, or Windows "Add or remove programs" → SNS Endpoint Security
Agent, or elevated:
```powershell
powershell -ExecutionPolicy Bypass -File uninstall.ps1            # removes service, task, data
powershell -ExecutionPolicy Bypass -File uninstall.ps1 -PreserveData   # keep the data
```

---

## 6. Issues hit during first real setup — and the fixes

All of these are **already fixed in the current installer/bundle**; this section is the record
+ the manual repair commands, in case an older install shows the same symptom.

### 6.1 `sc.exe create` failed silently → service not created
- **Symptom:** install finished, but `Start-Service SNSSecurityAgent` → "Cannot find any
  service with service name". `no health snapshot ... (is the service running?)`.
- **Cause:** `sc.exe create binPath=` mangles the quoted `C:\Program Files\...` path (space).
- **Fix (installer now uses `New-Service`). Manual repair:**
```powershell
New-Service -Name SNSSecurityAgent -BinaryPathName '"C:\Program Files\SNS\SecurityAgent\sns-service.exe"' -DisplayName "SNS Endpoint Security Agent" -StartupType Automatic
sc.exe config SNSSecurityAgent start= delayed-auto
sc.exe failure SNSSecurityAgent reset= 86400 actions= restart/60000/restart/60000/restart/300000
Start-Service SNSSecurityAgent
```

### 6.2 Capture agent exits instantly — `io error: Access is denied (os error 5)`
- **Symptom:** `sns-useragent` never stays running under the logon task; run by a normal user
  it prints `Access is denied`.
- **Cause:** data-folder ACLs granted `Users` nothing, and `keys\` had inheritance broken —
  the standard-user capture agent couldn't read config / the encryption key.
- **Fix (installer now sets these). Manual repair, elevated:**
```powershell
$r="C:\ProgramData\SNS\SecurityAgent"
icacls $r          /grant "*S-1-5-32-545:(OI)(CI)RX"
icacls "$r\data"   /grant "*S-1-5-32-545:(OI)(CI)M"
icacls "$r\runtime" /grant "*S-1-5-32-545:(OI)(CI)M"
icacls "$r\logs"   /grant "*S-1-5-32-545:(OI)(CI)M"
icacls "$r\keys"   /grant "*S-1-5-32-545:(OI)(CI)RX"
icacls "$r\database" /inheritance:r /grant "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
```
(`database` stays SYSTEM+Admins only — standard users cannot read the DB by design.)

### 6.3 Scheduled task returns `-2147024894` (0x80070002 file not found)
- **Symptom:** `schtasks /Run /TN SNSSecurityCapture` succeeds but no `sns-useragent` process;
  `LastTaskResult` = `-2147024894`.
- **Cause:** `schtasks /TR "..."` quoting broke on the spaced path.
- **Fix (installer now uses `Register-ScheduledTask`). Manual repair, elevated:**
```powershell
Unregister-ScheduledTask -TaskName "SNSSecurityCapture" -Confirm:$false -ErrorAction SilentlyContinue
$a = New-ScheduledTaskAction -Execute "$env:ProgramFiles\SNS\SecurityAgent\sns-useragent.exe"
$t = New-ScheduledTaskTrigger -AtLogOn
$p = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited
$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName "SNSSecurityCapture" -Action $a -Trigger $t -Principal $p -Settings $s -Force
```

### 6.4 `sns-agentctl` / `sns-admin` → `unable to open database file`
- **Symptom:** run from a normal (non-elevated) window.
- **Cause:** the DB is SYSTEM+Admins only (by design, §40).
- **Fix:** run inspection tools from an **elevated** PowerShell. Not a bug.

### 6.5 Two `sns-useragent` processes / double screenshots
- **Cause:** task + manual overlap, or double task fire; no single-instance guard.
- **Fix:** build adds a per-session single-instance lock (`Local\` mutex). Replace the exe:
```powershell
Get-Process sns-useragent -ErrorAction SilentlyContinue | Stop-Process -Force
Copy-Item "<release>\sns-useragent.exe" "$env:ProgramFiles\SNS\SecurityAgent\" -Force
Start-ScheduledTask -TaskName "SNSSecurityCapture"
```

### 6.6 Blank terminal window opens at logon
- **Cause:** `sns-useragent` was a console app; the task showed its (empty) console.
- **Fix:** release build is now windowless (`windows_subsystem = "windows"`). Replace the exe
  as in 6.5. Debug builds keep the console for developer diagnostics.

### 6.7 `Start-ScheduledTask` doesn't launch it, but real logon does
- **Cause:** the task's principal is the **Users group** + AtLogon trigger; on-demand start
  may not bind a user. It runs correctly at an actual logon.
- **Workaround to start now without logoff:**
```powershell
Start-Process "$env:ProgramFiles\SNS\SecurityAgent\sns-useragent.exe"
```

---

## 7. Health check one-liner
```powershell
Get-Service SNSSecurityAgent; Get-Process sns-service, sns-useragent -ErrorAction SilentlyContinue | Select Name, Id
& "$env:ProgramFiles\SNS\SecurityAgent\sns-agentctl.exe" status
```
