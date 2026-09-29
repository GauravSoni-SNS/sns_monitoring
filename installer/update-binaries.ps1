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
Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
foreach ($t in "SNSSecurityCapture","SNSSecurityAdmin") {
    Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
}
# Give the processes a moment, then hard-stop any that still hold the exes.
Start-Sleep -Milliseconds 500
foreach ($p in "sns-useragent","sns-admin","sns-service") {
    Get-Process $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 500

Write-Host "[2/4] Copying new binaries -> $InstallDir"
foreach ($e in $exes) { Copy-Item (Join-Path $BinSource $e) $InstallDir -Force }

Write-Host "[3/4] Restarting service"
Start-Service $ServiceName

Write-Host "[4/4] Restarting tasks"
Start-ScheduledTask -TaskName "SNSSecurityAdmin"    -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName "SNSSecurityCapture"  -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done. New binaries live. Version stamps:"
foreach ($e in $exes) {
    $f = Join-Path $InstallDir $e
    "{0,-22} {1}" -f $e, (Get-Item $f).LastWriteTime
}
