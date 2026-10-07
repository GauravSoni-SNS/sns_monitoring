# Hot-swap the installed SNS binaries with freshly built ones — no reinstall, no data touched.
# Use after building a new dist to make the changes LIVE. Run elevated.
#   powershell -ExecutionPolicy Bypass -File installer\update-binaries.ps1
#
# Stops the service + capture/admin tasks, replaces the 4 exes in the install dir, restarts.
# Config, keys, and the database (in %ProgramData%\SNS\SecurityAgent) are never modified.

[CmdletBinding()]
param(
    [string]$InstallDir  = "$Env:ProgramFiles\SNS\SecurityAgent",
    [string]$ServiceName = "SNSSecurityAgent",
    # Source of new binaries: the dist bundle folder, or the repo release output.
    [string]$BinSource
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Must run elevated (Administrator)."
}

$repo = Split-Path $PSScriptRoot -Parent
if (-not $BinSource) {
    $cand = Join-Path $repo "dist\SNSSecurityAgent"
    if (Test-Path (Join-Path $cand "sns-service.exe")) { $BinSource = $cand }
    else { $BinSource = Join-Path $repo "target\release" }
}

$exes = "sns-service.exe","sns-useragent.exe","sns-agentctl.exe","sns-admin.exe"
foreach ($e in $exes) {
    if (-not (Test-Path (Join-Path $BinSource $e))) { throw "Missing $e in $BinSource" }
}

Write-Host "[1/4] Stopping service + tasks"
# Disable the tasks first so Task Scheduler can't relaunch the capture/admin exes the instant
# we kill them (that race is why a plain stop+kill fails to free the file). Use the cmdlets
# (not schtasks.exe) and swallow "not running" — they must never abort the update.
foreach ($t in "SNSSecurityCapture","SNSSecurityAdmin") {
    try { Disable-ScheduledTask -TaskName $t -ErrorAction Stop | Out-Null } catch {}
    try { Stop-ScheduledTask    -TaskName $t -ErrorAction Stop | Out-Null } catch {}
}
Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
# Wait for the service to reach Stopped (so it can't respawn its helper).
for ($i = 0; $i -lt 20; $i++) {
    $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -eq 'Stopped') { break }
    Start-Sleep -Milliseconds 300
}
# Now kill any remaining agent processes; with tasks disabled they won't come back.
$procNames = "sns-useragent","sns-admin","sns-service","sns-agentctl"
for ($i = 0; $i -lt 10; $i++) {
    $alive = Get-Process $procNames -ErrorAction SilentlyContinue
    if (-not $alive) { break }
    $alive | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 400
}

Write-Host "[2/4] Copying new binaries -> $InstallDir"
foreach ($e in $exes) {
    $src = Join-Path $BinSource $e
    $dst = Join-Path $InstallDir $e
    # Retry the copy in case a handle is still being released.
    $copied = $false
    for ($i = 0; $i -lt 10 -and -not $copied; $i++) {
        try { Copy-Item $src $dst -Force -ErrorAction Stop; $copied = $true }
        catch {
            Get-Process $procNames -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $copied) { throw "Could not replace $e - a process is still using it. Close any running SNS window and retry." }
}

Write-Host "[3/4] Restarting service"
Start-Service $ServiceName

Write-Host "[4/4] Re-enabling + starting tasks"
foreach ($t in "SNSSecurityCapture","SNSSecurityAdmin") {
    try { Enable-ScheduledTask -TaskName $t -ErrorAction Stop | Out-Null } catch {}
}
Start-ScheduledTask -TaskName "SNSSecurityAdmin"    -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName "SNSSecurityCapture"  -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done. New binaries live. Version stamps:"
foreach ($e in $exes) {
    $f = Join-Path $InstallDir $e
    "{0,-22} {1}" -f $e, (Get-Item $f).LastWriteTime
}
