@echo off
REM SNS Endpoint Security Agent - double-click uninstaller (self-elevates).
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File \"%~dp0uninstall.ps1\"'"
