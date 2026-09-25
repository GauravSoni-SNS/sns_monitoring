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
  timeline: () => json<ActivityRow[]>("/api/timeline"),
  browser: () => json<ActivityRow[]>("/api/browser"),
  systemEvents: () => json<ActivityRow[]>("/api/system-events"),
  screenshots: () => json<ScreenshotRow[]>("/api/screenshots"),
  audit: () => json<AuditRow[]>("/api/audit"),
  storage: () => json<{ used_bytes: number; policy: any }>("/api/storage"),
  config: () => json<{ agent: any; policy: any }>("/api/config"),
  usage: (kind: "app" | "browser", days: number) =>
    json<UsageItem[]>(`/api/usage?kind=${kind}&days=${days}`),
  screenshotImageUrl: (id: string) => `/api/screenshots/${id}/image`,
  screenshotThumbUrl: (id: string) => `/api/screenshots/${id}/image?thumb=1`,
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

export function fmtTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}
