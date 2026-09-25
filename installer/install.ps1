# SNS Endpoint Security — install script (spec §38).
# Run elevated. Performs OS-level install steps; config/key init is done by the
# installer helper (sns-agentctl init, or the MSI custom action in production).
#
# This is the scriptable reference used by the WiX MSI custom actions. It is NOT a
# covert installer: the service is named, discoverable, and uninstallable (spec §39).

[CmdletBinding()]
param(
    [string]$SystemName,                    # e.g. SNS-PC-001 (spec §10); prompts if omitted
    [securestring]$AdminPassword,           # admin-panel password; prompts if omitted
    [string]$InstallDir = "$Env:ProgramFiles\SNS\SecurityAgent",
    [string]$DataRoot   = "$Env:ProgramData\SNS\SecurityAgent",
    [string]$ServiceName = "SNSSecurityAgent",
    # Where the built binaries live. In the install bundle this is the script's own folder;
    # from the repo it falls back to the cargo release output.
    [string]$BinSource
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Must run elevated (Administrator)."
}

# Resolve binary source: bundle folder (exes next to this script) or repo release output.
if (-not $BinSource) {
    if (Test-Path (Join-Path $PSScriptRoot "sns-service.exe")) { $BinSource = $PSScriptRoot }
    else { $BinSource = (Join-Path $PSScriptRoot "..\target\release") }
}

# Interactive fallbacks so a double-click install just works.
if (-not $SystemName)   { $SystemName = Read-Host "System Name (e.g. SNS-PC-001)" }
if (-not $SystemName)   { $SystemName = $Env:COMPUTERNAME }
if (-not $AdminPassword){ $AdminPassword = Read-Host "Admin panel password" -AsSecureString }

Write-Host "[1/11] Install binaries from $BinSource -> $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach ($exe in "sns-service.exe","sns-useragent.exe","sns-agentctl.exe","sns-admin.exe") {
    $src = Join-Path $BinSource $exe
    if (-not (Test-Path $src)) { throw "Missing binary: $src (run: cargo build --release --workspace)" }
    Copy-Item $src $InstallDir -Force
}

Write-Host "[2/11] Create data directories -> $DataRoot"
$dirs = @("config","database","keys","data","queue\pending","logs","cache","runtime")
foreach ($d in $dirs) { New-Item -ItemType Directory -Force -Path (Join-Path $DataRoot $d) | Out-Null }

Write-Host "[3/11] Apply NTFS ACLs"   # spec §12, §40
# SYSTEM + Admins full over the whole tree. The user-session capture agent runs as a
# STANDARD user, so grant Users read-only by default and Modify only where it must write.
icacls $DataRoot /inheritance:r | Out-Null
icacls $DataRoot /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null
foreach ($sub in "data","runtime","logs","queue") {
    icacls (Join-Path $DataRoot $sub) /grant:r "*S-1-5-32-545:(OI)(CI)M" | Out-Null   # capture writes here
}
# Database is service-owned (single writer): SYSTEM + Admins only, no standard users.
icacls (Join-Path $DataRoot "database") /inheritance:r `
    /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
# keys\: users need READ to unwrap the machine-DPAPI key for encryption in their own session.
icacls (Join-Path $DataRoot "keys") /inheritance:r `
    /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null

Write-Host "[4/11] Initialize DB, [5/11] device_id, [6/11] key protection, [9/11] default policy"
# Production: MSI custom action runs `sns-agentctl init --system-name $SystemName`, which
# generates the immutable device_id, DPAPI-wraps a fresh DEK, writes agent.json/policy.json,
# and creates + migrates activity.db.
# Pass the password via env (not the command line) so it is not visible in the process list.
$plainPw = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword))
$Env:SNS_ADMIN_PASSWORD = $plainPw
try {
    & (Join-Path $InstallDir "sns-agentctl.exe") init --system-name $SystemName --data-root $DataRoot
} finally {
    Remove-Item Env:\SNS_ADMIN_PASSWORD -ErrorAction SilentlyContinue
    $plainPw = $null
}

Write-Host "[7/11] Install Windows Service + [8/11] recovery config"
# Use New-Service (not sc.exe) so the quoted binary path with spaces is passed correctly.
$svcExe = Join-Path $InstallDir "sns-service.exe"
if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}
New-Service -Name $ServiceName `
    -BinaryPathName ('"{0}"' -f $svcExe) `
    -DisplayName "SNS Endpoint Security Agent" `
    -Description "Authorized enterprise endpoint activity/security agent (SNS)." `
    -StartupType Automatic | Out-Null
# Delayed auto-start + recovery (restart 60s/60s/then 5min; reset daily, spec §27).
sc.exe config $ServiceName start= delayed-auto | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null
sc.exe failureflag $ServiceName 1 | Out-Null
if (-not (Get-Service $ServiceName -ErrorAction SilentlyContinue)) {
    throw "Service '$ServiceName' was not created."
}

Write-Host "[9b] Register user-session capture agent (session-0 bridge)"
# Interactive collection (screenshots, app/browser focus) cannot run from the session-0
# service; it runs as sns-useragent in each user's session, launched at logon. This is a
# visible, named scheduled task — not covert persistence.
# Use Register-ScheduledTask (not schtasks /TR) so the "Program Files" space is quoted
# correctly — the raw schtasks form yields a 0x80070002 "file not found" at run time.
$uaPath = Join-Path $InstallDir "sns-useragent.exe"
Unregister-ScheduledTask -TaskName "SNSSecurityCapture" -Confirm:$false -ErrorAction SilentlyContinue
$ua_action    = New-ScheduledTaskAction -Execute $uaPath
$ua_trigger   = New-ScheduledTaskTrigger -AtLogOn
$ua_principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited  # BUILTIN\Users
$ua_settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName "SNSSecurityCapture" -Action $ua_action -Trigger $ua_trigger `
    -Principal $ua_principal -Settings $ua_settings -Force | Out-Null

Write-Host "[9d] Register admin panel as a SYSTEM startup task"
# Run sns-admin as LocalSystem at boot so the loopback panel is always up and always has
# access to the SYSTEM+Admins-only database — no manual elevation needed to view data.
# Runs in session 0 (no visible window). Reachable at http://127.0.0.1:7731.
$adminPath = Join-Path $InstallDir "sns-admin.exe"
Unregister-ScheduledTask -TaskName "SNSSecurityAdmin" -Confirm:$false -ErrorAction SilentlyContinue
$ad_action    = New-ScheduledTaskAction -Execute $adminPath
$ad_trigger   = New-ScheduledTaskTrigger -AtStartup
$ad_principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -RunLevel Highest  # LocalSystem
$ad_settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName "SNSSecurityAdmin" -Action $ad_action -Trigger $ad_trigger `
    -Principal $ad_principal -Settings $ad_settings -Force | Out-Null
Start-ScheduledTask -TaskName "SNSSecurityAdmin"

Write-Host "[9c] Register in Add/Remove Programs"
# Copy the uninstaller alongside the binaries so Programs & Features can call it.
Copy-Item (Join-Path $PSScriptRoot "uninstall.ps1") $InstallDir -Force -ErrorAction SilentlyContinue
$arp = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SNSSecurityAgent"
New-Item -Path $arp -Force | Out-Null
Set-ItemProperty $arp DisplayName    "SNS Endpoint Security Agent"
Set-ItemProperty $arp DisplayVersion "1.0.0"
Set-ItemProperty $arp Publisher      "SNS"
Set-ItemProperty $arp InstallLocation $InstallDir
Set-ItemProperty $arp NoModify 1; Set-ItemProperty $arp NoRepair 1
Set-ItemProperty $arp UninstallString ("powershell -NoProfile -ExecutionPolicy Bypass -File `"{0}\uninstall.ps1`"" -f $InstallDir)

Write-Host "[10/11] Start service + [11/11] health check"
Start-Service $ServiceName
for ($i = 0; $i -lt 10; $i++) {
    if ((Get-Service $ServiceName).Status -eq 'Running') { break }
    Start-Sleep -Seconds 1
}
Write-Host ("Service status: {0}" -f (Get-Service $ServiceName).Status)
Start-Sleep -Seconds 2   # let the agent publish its first health snapshot
& (Join-Path $InstallDir "sns-agentctl.exe") status

Write-Host ""
Write-Host "Install complete. Service '$ServiceName' auto-starts on boot."
Write-Host "Admin panel: http://127.0.0.1:7731  (System Name: $SystemName)"
Write-Host "Log back in (or run the SNSSecurityCapture task) to start screenshot capture."
