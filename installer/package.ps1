# Assemble a copy-anywhere install bundle (folder + zip) from the release binaries.
# Run after: cargo build --release --workspace
#   powershell -ExecutionPolicy Bypass -File installer\package.ps1
#
# The zip is always built from a fresh staging copy (never a file that a running panel
# might have locked). Refreshing the run/share folder dist\SNSSecurityAgent is best-effort:
# if a panel launched from that folder holds sns-admin.exe, the zip still succeeds and a
# warning tells you to stop that panel (or run this elevated, which force-stops it).

$ErrorActionPreference = "Stop"
$repo  = Split-Path $PSScriptRoot -Parent
$rel   = Join-Path $repo "target\release"
$dist  = Join-Path $repo "dist\SNSSecurityAgent"
$stage = Join-Path $repo "dist\_stage"
$zip   = Join-Path $repo "dist\SNSSecurityAgent-1.0.0.zip"

$exes = "sns-service.exe","sns-useragent.exe","sns-agentctl.exe","sns-admin.exe"
foreach ($e in $exes) {
    if (-not (Test-Path (Join-Path $rel $e))) {
        throw "Missing $e in $rel. Run: cargo build --release --workspace"
    }
}

function Fill-Bundle($dir) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    foreach ($e in $exes) { Copy-Item (Join-Path $rel $e) $dir -Force }
    foreach ($f in "install.ps1","uninstall.ps1","Install.cmd","Uninstall.cmd") {
        Copy-Item (Join-Path $PSScriptRoot $f) $dir -Force
    }
    @"
SNS Endpoint Security Agent 1.0.0 - install bundle
==================================================

Authorized company-managed devices only, under a disclosed monitoring policy.

TO INSTALL (one machine):
  1. Copy this whole folder to the target PC (any location).
  2. Double-click  Install.cmd
  3. Click "Yes" on the Windows security (UAC) prompt.
  4. Enter a System Name (e.g. SNS-PC-001) and an admin-panel password.
  Done. Service auto-starts on boot. Admin panel: http://127.0.0.1:7731

SILENT / MASS DEPLOYMENT (GPO / Intune), elevated:
  powershell -ExecutionPolicy Bypass -File install.ps1 -SystemName SNS-PC-001 -AdminPassword (ConvertTo-SecureString 'YourPass' -AsPlainText -Force)

TO UNINSTALL:
  Double-click Uninstall.cmd  (or Windows "Add or remove programs").

Data lives in C:\ProgramData\SNS\SecurityAgent (encrypted screenshots + SQLite).
"@ | Set-Content (Join-Path $dir "README-INSTALL.txt") -Encoding UTF8
}

# 1) Fresh staging copy (from target\release — never locked) and the zip (the deliverable).
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
Fill-Bundle $stage
if (Test-Path $zip) { Remove-Item -Force $zip -ErrorAction SilentlyContinue }
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue

# 2) Best-effort refresh of the run/share folder (may be locked by a running dist panel).
$folderOk = $true
try {
    Get-CimInstance Win32_Process -Filter "Name='sns-admin.exe' OR Name='sns-useragent.exe' OR Name='sns-service.exe'" -ErrorAction SilentlyContinue |
      Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($dist) } |
      ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 300
    if (Test-Path $dist) { Remove-Item -Recurse -Force $dist -ErrorAction Stop }
    Fill-Bundle $dist
} catch {
    $folderOk = $false
}

Write-Host "Zip    : $zip   (OK)"
if ($folderOk) { Write-Host "Folder : $dist   (OK)" }
else { Write-Host "Folder : $dist   (SKIPPED - locked by a running panel; zip is current. Run elevated or stop that panel to refresh the folder.)" }
