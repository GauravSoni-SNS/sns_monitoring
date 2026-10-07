# DEPLOYMENT-GUIDE.md — SNS Endpoint Security

End-to-end guide: stand up the central server, onboard a business, deploy agents to Windows PCs.

## 1. Central server (one time)

### Prerequisites
- A Linux/Windows host with a public domain (for internet reach) or a LAN host.
- PostgreSQL (managed, e.g. Neon/RDS, or self-hosted).
- A directory for screenshot blobs (`SNS_BLOB_DIR`), backed up.

### Run
```
set DATABASE_URL=postgres://user:pass@host/db?sslmode=require
set SNS_BLOB_DIR=C:\sns-blobs          # or /var/lib/sns/blobs
set SNS_SERVER_BIND=127.0.0.1:8080     # bind local; TLS terminates at the proxy
sns-server serve
```
Migrations run automatically on start.

### TLS (internet)
Put Caddy (or Nginx) in front — see `deploy/Caddyfile`. Caddy auto-manages Let's Encrypt certs.
Only the proxy is exposed; `sns-server` stays on loopback.

### Backups
Schedule `deploy/backup.ps1` daily (DB dump + blob archive, 14-day retention).

## 2. Onboard a business (org)

**Self-serve:** open `https://your-server/signup` → fill business name + admin email + password →
you get a **device enroll token** (shown once) + a 14-day / 5-seat trial.

**Or CLI (internal):**
```
sns-server provision-org --name "Acme" --admin-email boss@acme.com --admin-password "..."
```

The boss signs in at `https://your-server/` to see the fleet.

## 3. Deploy the agent to a Windows PC

1. Copy the agent bundle (`dist\SNSSecurityAgent\`) to the PC.
2. Elevated: `Install.cmd` (or `install.ps1`) — enter a System Name + admin-panel password.
   Service auto-starts, local panel at `http://127.0.0.1:7731`.
3. Point it at the central server (elevated):
   ```
   sns-agentctl enroll --server https://your-server --token <enroll-token>
   ```
   The agent registers and begins syncing events + screenshots within ~1 minute.

### Mass deployment (GPO / Intune)
Silent install, then enroll:
```
powershell -ExecutionPolicy Bypass -File install.ps1 -SystemName %COMPUTERNAME% -AdminPassword (ConvertTo-SecureString 'Pass' -AsPlainText -Force)
sns-agentctl.exe enroll --server https://your-server --token <enroll-token>
```
(MSI package: see `installer/wix/` once built + signed.)

## 4. Verify
- Local: `sns-agentctl status` / panel at `127.0.0.1:7731`.
- Central: boss dashboard `https://your-server/` → device appears → events + Screenshots load.

## Updating agents
`installer\update-binaries.ps1` (elevated) hot-swaps binaries. The service self-heals its
integrity chain at boot. (Auto-update: agent polls `/api/v1/agent/version`.)

## Security notes
- Screenshots: encrypted on the PC, re-encrypted under the org key before upload; server stores
  org-encrypted blobs; only the org's boss can view (decrypted server-side for that org).
- USB/print: metadata only, never file contents.
- Device tokens stored hashed; TLS in transit; every query org-scoped.
- Monitoring must be disclosed to users — see `docs/legal/`.
