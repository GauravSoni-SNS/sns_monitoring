# SNS Browser Reporter extension

Reliable active-tab-URL capture for the SNS agent, cross-browser and cross-OS (the robust
path on Linux, where no OS API exposes the address bar). It sends **only the focused tab's
URL** to the agent on **loopback (127.0.0.1:7738)** — no page content, history, or cookies.

## Install (per browser, company-managed devices)
**Chrome / Edge / Brave (Chromium):**
1. Go to `chrome://extensions` (or `edge://extensions`), enable **Developer mode**.
2. **Load unpacked** → select this `extension/` folder.
   (For fleet deployment, pack + push it via the browser's enterprise policy
   `ExtensionInstallForcelist`.)

**Firefox:**
1. `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on** → pick `manifest.json`.
   (For permanent/fleet, sign it via AMO or use an enterprise policy.)

## How it connects
The SNS agent (`sns-useragent`) listens on `127.0.0.1:7738`. When the agent is running and the
extension is installed, the agent records `BROWSER_ACTIVITY` from the reported URLs. If the
extension isn't installed, the agent falls back to the OS-native reader (UI Automation on
Windows, AppleScript on macOS); on Linux the extension is the reliable source.

Disclosed monitoring on authorized company-managed devices only.
