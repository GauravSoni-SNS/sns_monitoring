# SNS central server backup: Postgres dump + screenshot blobs. Schedule daily (Task Scheduler
# or cron). Keeps the last 14 days. Set DATABASE_URL and SNS_BLOB_DIR to match the server.
param(
    [string]$OutDir     = "C:\sns-backups",
    [string]$BlobDir    = $(if ($env:SNS_BLOB_DIR) { $env:SNS_BLOB_DIR } else { "C:\sns-blobs" }),
    [int]$KeepDays      = 14
)
$ErrorActionPreference = "Stop"
if (-not $env:DATABASE_URL) { throw "DATABASE_URL not set" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"

# 1) Database (needs pg_dump on PATH).
pg_dump $env:DATABASE_URL -Fc -f (Join-Path $OutDir "sns-db-$stamp.dump")

# 2) Screenshot blobs.
if (Test-Path $BlobDir) {
    Compress-Archive -Path (Join-Path $BlobDir "*") -DestinationPath (Join-Path $OutDir "sns-blobs-$stamp.zip") -Force
}

# 3) Prune old backups.
Get-ChildItem $OutDir -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepDays) } | Remove-Item -Force
Write-Host "Backup complete: $OutDir (db + blobs, kept $KeepDays days)"
