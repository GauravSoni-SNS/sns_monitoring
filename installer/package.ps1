# Assemble a copy-anywhere install bundle (folder + zip) from the release binaries.
# Run after: cargo build --release --workspace
#   powershell -ExecutionPolicy Bypass -File installer\package.ps1

$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
$rel  = Join-Path $repo "target\release"
$dist = Join-Path $repo "dist\SNSSecurityAgent"
$zip  = Join-Path $repo "dist\SNSSecurityAgent-1.0.0.zip"

$exes = "sns-service.exe","sns-useragent.exe","sns-agentctl.exe","sns-admin.exe"
foreach ($e in $exes) {
    if (-not (Test-Path (Join-Path $rel $e))) {
        throw "Missing $e in $rel. Run: cargo build --release --workspace"
    }
}

# Stop any bundle exe running FROM the dist folder (it would lock the files we replace).
Get-CimInstance Win32_Process -Filter "Name='sns-admin.exe' OR Name='sns-useragent.exe' OR Name='sns-service.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($dist) } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 400

if (Test-Path $dist) {
  try { Remove-Item -Recurse -Force $dist -ErrorAction Stop }
  catch { throw "Cannot rebuild dist: a file is locked ($($_.Exception.Message)). Stop any sns-admin.exe running from '$dist' (elevated) and retry." }
}
New-Item -ItemType Directory -Force -Path $dist | Out-Null

foreach ($e in $exes) { Copy-Item (Join-Path $rel $e) $dist }
Copy-Item (Join-Path $PSScriptRoot "install.ps1")   $dist
Copy-Item (Join-Path $PSScriptRoot "uninstall.ps1") $dist
Copy-Item (Join-Path $PSScriptRoot "Install.cmd")   $dist
Copy-Item (Join-Path $PSScriptRoot "Uninstall.cmd") $dist

@"
SNS Endpoint Security Agent 1.0.0 - install bundle
==================================================

Authorized company-managed devices only, under a disclosed monitoring policy.

TO INSTALL (one machine):
  1. Copy this whole folder to the target PC (any location).
  2. Double-click  Install.cmd
  3. Click "Yes" on the Windows security (UAC) prompt.
  4. Enter a System Name (e.g. SNS-PC-001) and an admin-panel password.
  Done. The service auto-starts on every boot. Admin panel: http://127.0.0.1:7731
  (Screenshot capture starts after the next logon.)

SILENT / MASS DEPLOYMENT (GPO / Intune / script), run elevated:
  powershell -ExecutionPolicy Bypass -File install.ps1 -SystemName SNS-PC-001 -AdminPassword (ConvertTo-SecureString 'YourPass' -AsPlainText -Force)

TO UNINSTALL:
  Double-click Uninstall.cmd  (or use Windows "Add or remove programs" -> SNS Endpoint Security Agent)

Data lives in C:\ProgramData\SNS\SecurityAgent (encrypted screenshots + SQLite).
"@ | Set-Content (Join-Path $dist "README-INSTALL.txt") -Encoding UTF8

if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path (Join-Path $dist "*") -DestinationPath $zip

Write-Host "Bundle : $dist"
Write-Host "Zip    : $zip"
Get-ChildItem $dist | Select-Object Name, Length | Format-Table -AutoSize
