// Typed client for the sns-admin API. Session cookie is sent automatically (same-origin);
// the CSRF token from login is required on mutations.

export type Device = {
  device_id: string;
  system_name: string;
  hostname?: string | null;
  os_version?: string | null;
  agent_version?: string | null;
  last_seen_at?: string | null;
};

export type Health = {
  agent_status: string;
  database: string;
  encryption: string;
  storage_used_bytes: number;
  storage_max_bytes: number;
  last_event_utc?: string | null;
  last_screenshot_utc?: string | null;
  last_integrity_check_utc?: string | null;
  last_integrity_pass?: boolean | null;
  agent_version: string;
  configuration_version: number;
};

export type ActivityRow = {
  event_id: string;
  event_type: string;
  timestamp_utc: string;
  application_name?: string | null;
  window_title?: string | null;
  metadata_json?: string | null;
};

export type ScreenshotRow = {
  screenshot_id: string;
  timestamp_utc: string;
  file_size: number;
  sha256: string;
  monitor_id?: number | null;
};

export type AuditRow = {
  action: string;
  timestamp_utc: string;
  actor?: string | null;
  metadata_json?: string | null;
};

export type UsageItem = { name: string; seconds: number; sessions: number };

export type UsbDevice = {
  instance_id: string;
  vendor_id?: string | null;
  product_id?: string | null;
  serial?: string | null;
  description?: string | null;
};

export type AlertRow = {
  severity: "high" | "medium" | "low";
  kind: string;
  message: string;
  timestamp_utc: string;
  event_id: string;
};

/** UTC ISO bounds for a date-range query. */
export type Range = { from?: string; to?: string };

function qs(o?: Range): string {
  if (!o) return "";
  const p = new URLSearchParams();
  if (o.from) p.set("from", o.from);
  if (o.to) p.set("to", o.to);
  const s = p.toString();
  return s ? `?${s}` : "";
}

let csrf: string | null = null;

async function req(path: string, init?: RequestInit): Promise<Response> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
  });
  if (res.status === 401) throw new Error("unauthorized");
  return res;
}

async function json<T>(path: string): Promise<T> {
  const res = await req(path);
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText);
  return res.json();
}

export const api = {
  authed: false,
  async login(password: string): Promise<boolean> {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    if (!res.ok) return false;
    csrf = (await res.json()).csrf;
    this.authed = true;
    return true;
  },
  async logout(): Promise<void> {
    await fetch("/api/logout", { method: "POST" });
    this.authed = false;
    csrf = null;
  },
  device: () => json<{ device: Device | null; health: Health | null }>("/api/device"),
  health: () => json<Health>("/api/health"),
  timeline: (o?: Range) => json<ActivityRow[]>(`/api/timeline${qs(o)}`),
  browser: (o?: Range) => json<ActivityRow[]>(`/api/browser${qs(o)}`),
  systemEvents: (o?: Range) => json<ActivityRow[]>(`/api/system-events${qs(o)}`),
  screenshots: (o?: Range) => json<ScreenshotRow[]>(`/api/screenshots${qs(o)}`),
  audit: () => json<AuditRow[]>("/api/audit"),
  storage: () => json<{ used_bytes: number; policy: any }>("/api/storage"),
  config: () => json<{ agent: any; policy: any }>("/api/config"),
  usage: (kind: "app" | "browser", days: number) =>
    json<UsageItem[]>(`/api/usage?kind=${kind}&days=${days}`),
  idle: (days: number) => json<{ idle_seconds: number; days: number }>(`/api/idle?days=${days}`),
  alerts: (days: number) => json<AlertRow[]>(`/api/alerts?days=${days}`),
  alertRules: () => json<any>("/api/alert-rules"),
  async updateAlertRules(rules: any): Promise<void> {
    const res = await req("/api/alert-rules", { method: "PUT", body: JSON.stringify({ csrf, rules }) });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText);
  },
  usbDevices: () => json<UsbDevice[]>("/api/usb-devices"),
  transferSummary: (days: number) => json<{ total_bytes: number; file_count: number; by_kind: Record<string, number> }>(`/api/transfer-summary?days=${days}`),
  screenshotImageUrl: (id: string) => `/api/screenshots/${id}/image`,
  screenshotThumbUrl: (id: string) => `/api/screenshots/${id}/image?thumb=1`,
  async updateRetention(retention: any): Promise<void> {
    const res = await req("/api/retention", { method: "PUT", body: JSON.stringify({ csrf, retention }) });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText);
  },
  async purgeBrowser(opts?: { mode?: string; domains?: string[]; days?: number }): Promise<{ deleted: number; mode: string }> {
    const res = await req("/api/retention/purge-browser", { method: "POST", body: JSON.stringify({ csrf, ...(opts || {}) }) });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText);
    return res.json();
  },
  async purgeScreenshots(): Promise<{ deleted: number; by_age: number; by_heuristic: number }> {
    const res = await req("/api/retention/purge-screenshots", { method: "POST", body: JSON.stringify({ csrf }) });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText);
    return res.json();
  },
  async verifyIntegrity(): Promise<{ events_checked: number; invalid_records: number; pass: boolean; first_breaks: string[] }> {
    const res = await req("/api/integrity/verify", {
      method: "POST",
      body: JSON.stringify({ csrf }),
    });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText);
    return res.json();
  },
};

export function fmtBytes(n: number): string {
  if (n >= 1_073_741_824) return (n / 1_073_741_824).toFixed(2) + " GB";
  if (n >= 1_048_576) return (n / 1_048_576).toFixed(1) + " MB";
  if (n >= 1024) return (n / 1024).toFixed(0) + " KB";
  return n + " B";
}

export function fmtDuration(sec: number): string {
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${sec}s`;
}

// All timestamps are stored UTC; the UI shows them in India Standard Time (IST, UTC+5:30).
const IST = "Asia/Kolkata";

export function fmtTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString("en-IN", {
    timeZone: IST, year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true,
  }) + " IST";
}

function nextDay(dateStr: string): string {
  const [y, m, d] = dateStr.split("-").map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  dt.setUTCDate(dt.getUTCDate() + 1);
  return dt.toISOString().slice(0, 10);
}

/** IST calendar range (date inputs, YYYY-MM-DD) → RFC-3339 IST (+05:30) bounds that match
 *  the stored timestamp format: from = IST 00:00 of `fromDate`; to = IST 00:00 of the day
 *  after `toDate` (exclusive). String comparison against stored +05:30 timestamps is
 *  chronological. */
export function istRangeToUtc(fromDate?: string, toDate?: string): Range {
  const r: Range = {};
  if (fromDate) r.from = `${fromDate}T00:00:00+05:30`;
  if (toDate) r.to = `${nextDay(toDate)}T00:00:00+05:30`;
  return r;
}

/** Today's date (IST) as YYYY-MM-DD, for date-input defaults. */
export function istToday(): string {
  const parts = new Intl.DateTimeFormat("en-CA", { timeZone: IST, year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
  return parts; // en-CA yields YYYY-MM-DD
}
