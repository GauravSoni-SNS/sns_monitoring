@echo off
REM SNS Endpoint Security Agent - double-click installer.
REM Self-elevates (UAC prompt), then runs install.ps1 which asks for the System Name
REM and admin-panel password. For silent/mass deployment, call install.ps1 directly
REM with -SystemName and -AdminPassword (see README-INSTALL.txt).
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File \"%~dp0install.ps1\"'"
