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
