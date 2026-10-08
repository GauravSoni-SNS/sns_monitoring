# SNS Endpoint Security — How to use (internal)

A quick, practical guide. Two things to run: the **agent** on each Windows PC you want to
monitor, and (optional) the **central server** so one dashboard shows all PCs.

Authorized company-managed devices only, under a disclosed monitoring policy.

---

## A. Monitor a single Windows PC (no server)

1. Copy the folder `SNSSecurityAgent\` (from the zip) to the PC.
2. Right-click **Install.cmd** → nothing special; just double-click it, click **Yes** on the
   Windows (UAC) prompt.
3. Enter a **System Name** (e.g. `SNS-PC-001`) and an **admin-panel password**.
4. Done. The service auto-starts on boot and keeps running after you close any window.

**See the data:** open a browser on that PC → `http://127.0.0.1:7731` → log in with the password.
- Dashboard, Timeline, Browser, Screenshots, USB Devices, Transfers, Alerts, Storage, Integrity.

**Useful commands** (PowerShell as Administrator):
```
& "C:\Program Files\SNS\SecurityAgent\sns-agentctl.exe" status        # summary
& "C:\Program Files\SNS\SecurityAgent\sns-agentctl.exe" apps          # risky apps installed
& "C:\Program Files\SNS\SecurityAgent\sns-agentctl.exe" usb-list      # connected USB devices
```

**Uninstall:** double-click **Uninstall.cmd** (or Windows "Add or remove programs").

---

## B. See ALL PCs in one place (central server + dashboard)

Run the server once on any machine (it can be a Windows PC, a Linux box, or a cloud host). The
**boss can then watch from any browser — Windows, Mac, Linux, or phone.**

### 1. Start the server
Needs a PostgreSQL database URL (e.g. a free Neon database) and a folder for screenshots.
```
set DATABASE_URL=postgres://user:pass@host/db?sslmode=require
set SNS_BLOB_DIR=C:\sns-blobs
set SNS_SERVER_BIND=0.0.0.0:8080
sns-server.exe serve
```
(For internet access with HTTPS, put Caddy in front — see `deploy/Caddyfile`. On a LAN you can
use `http://<server-ip>:8080` directly.)

### 2. Create your organization
Open `http://<server>:8080/signup` → business name + admin email + password → you get a
**device enroll token** (copy it, shown once).

### 3. Point each PC's agent at the server
On each monitored PC (PowerShell as Administrator):
```
& "C:\Program Files\SNS\SecurityAgent\sns-agentctl.exe" enroll --server http://<server>:8080 --token <enroll-token>
```
Within ~1 minute the PC starts uploading events + screenshots.

### 4. Watch the fleet
Open `http://<server>:8080/` in **any browser (Mac/Linux/Windows/phone)** → log in with the
admin email/password → see every PC (online/offline) → click one for its timeline, events, and
**Screenshots**.

---

## C. Updating the agent later
Replace the installed binaries with a new build (PowerShell as Administrator):
```
powershell -ExecutionPolicy Bypass -File "C:\...\installer\update-binaries.ps1"
```
Data and settings are kept; the service self-repairs its integrity chain on restart.

---

## What it watches (metadata-first — no keystrokes, passwords, or file contents)
Active app + window title, browser domains/URLs, periodic screenshots, USB devices + files
copied to USB (names/sizes only), documents printed, installed data-transfer apps, idle/active
time, tamper/integrity events. Retention + cleanup are configurable in the Storage view.
