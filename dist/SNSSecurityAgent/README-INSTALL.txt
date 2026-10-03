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

OPTIONAL - LOCAL ALERTS:
  Copy alerts.example.json to
    C:\ProgramData\SNS\SecurityAgent\config\alerts.json
  and edit it (blocked apps/domains, working hours). No restart needed; the
  Alerts panel view re-reads it on each load. If the file is absent, defaults
  apply (USB connect + integrity failure).
