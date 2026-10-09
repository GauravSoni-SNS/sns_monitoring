// SNS browser reporter. Sends the active tab's URL to the local SNS agent (loopback only).
// Reports only the URL of the tab in focus — no page content, no history, no cookies. This is
// the reliable cross-browser path for address-bar capture (esp. Linux, where no OS-level API
// exposes it); on Windows/macOS it supplements the native reader.

const AGENT = "http://127.0.0.1:7738/url";
const BROWSER = (navigator.userAgent.match(/Edg|Chrome|Firefox|Brave/) || ["chrome"])[0].toLowerCase();

let lastSent = "";
async function report(url) {
  if (!url || url === lastSent || url.startsWith("chrome://") || url.startsWith("about:") || url.startsWith("edge://")) return;
  lastSent = url;
  try {
    await fetch(AGENT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, browser: BROWSER }),
    });
  } catch (_) { /* agent not running / offline — ignore */ }
}

async function reportActive() {
  try {
    const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (tabs && tabs[0] && tabs[0].url) report(tabs[0].url);
  } catch (_) {}
}

chrome.tabs.onActivated.addListener(reportActive);
chrome.tabs.onUpdated.addListener((id, info, tab) => { if (info.url && tab.active) report(info.url); });
chrome.windows.onFocusChanged.addListener(reportActive);
reportActive();
