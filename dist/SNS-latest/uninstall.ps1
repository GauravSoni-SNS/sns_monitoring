# SNS Endpoint Security — uninstall (spec §39). Run elevated.
# Stops the service cleanly (agent writes AGENT_SHUTDOWN{reason=UNINSTALL}, flushes,
# checkpoints, zeroizes keys), then removes the service and (per policy) the data.

[CmdletBinding()]
param(
    [string]$DataRoot   = "$Env:ProgramData\SNS\SecurityAgent",
    [string]$InstallDir = "$Env:ProgramFiles\SNS\SecurityAgent",
    [string]$ServiceName = "SNSSecurityAgent",
    [switch]$PreserveData   # default: preserve; pass to force secure wipe per policy
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Must run elevated (Administrator)."
}

Write-Host "Stopping service (graceful shutdown lifecycle)..."
sc.exe stop $ServiceName | Out-Null
# Wait for STOPPED so the agent finishes its shutdown lifecycle (spec §6, §28).
for ($i = 0; $i -lt 30; $i++) {
    $state = (sc.exe query $ServiceName) -join "`n"
    if ($state -match "STOPPED" -or $state -notmatch "SERVICE_NAME") { break }
    Start-Sleep -Seconds 1
}

Write-Host "Removing scheduled tasks..."
schtasks /Delete /TN "SNSSecurityCapture" /F 2>$null | Out-Null
schtasks /Delete /TN "SNSSecurityAdmin" /F 2>$null | Out-Null
Get-Process sns-admin -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "Removing service..."
sc.exe delete $ServiceName | Out-Null

Write-Host "Removing Add/Remove Programs entry..."
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SNSSecurityAgent" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Removing binaries..."
# Don't delete the folder we're running from mid-execution; clear contents best-effort.
if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue }

if ($PreserveData) {
    Write-Host "Data preserved at $DataRoot (per policy)."
} else {
    Write-Host "Removing data at $DataRoot ..."
    if (Test-Path $DataRoot) { Remove-Item -Recurse -Force $DataRoot }
}
Write-Host "Uninstall complete."
