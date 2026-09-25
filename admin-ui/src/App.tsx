import { useEffect, useState } from "react";
import {
  api, fmtBytes, fmtDuration, fmtTime,
  type ActivityRow, type AuditRow, type ScreenshotRow, type UsageItem,
} from "./api";

const NAV = [
  "Dashboard", "Usage Time", "Timeline", "Browser", "Screenshots",
  "System Events", "Storage", "Audit Log", "Integrity", "Configuration",
] as const;
type View = (typeof NAV)[number];

export function App() {
  const [authed, setAuthed] = useState(false);
  return authed ? <Shell onLogout={() => setAuthed(false)} /> : <Login onOk={() => setAuthed(true)} />;
}

/* ------------------------------- login -------------------------------- */
function Login({ onOk }: { onOk: () => void }) {
  const [pw, setPw] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit() {
    setBusy(true); setErr("");
    try {
      if (await api.login(pw)) onOk();
      else setErr("Invalid credentials.");
    } catch { setErr("Login failed."); }
    finally { setBusy(false); }
  }
  return (
    <div className="login-wrap">
      <div className="login">
        <div className="brand"><div className="logo">S</div><h1>SNS Endpoint Security</h1></div>
        <p className="sub">Authorized local administrator only.</p>
        <div className="field">
          <input type="password" placeholder="Admin password" value={pw}
            autoFocus autoComplete="current-password"
            onChange={(e) => setPw(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()} />
          <button className="btn" onClick={submit} disabled={busy}>{busy ? "…" : "Sign in"}</button>
        </div>
        <div className="err">{err}</div>
      </div>
    </div>
  );
}

/* ------------------------------- shell -------------------------------- */
function Shell({ onLogout }: { onLogout: () => void }) {
  const [view, setView] = useState<View>("Dashboard");
  const [device, setDevice] = useState<string>("");
  useEffect(() => { api.device().then((d) => setDevice(d.device?.system_name || "")).catch(() => {}); }, []);
  async function logout() { await api.logout(); onLogout(); }
  return (
    <div className="shell">
      <aside>
        <div className="brand"><div className="logo">S</div><b>SNS Security</b></div>
        <nav className="side">
          {NAV.map((n) => (
            <a key={n} className={n === view ? "active" : ""} onClick={() => setView(n)}>
              <span className="dot" />{n}
            </a>
          ))}
        </nav>
        <div className="foot"><button className="btn ghost" style={{ width: "100%" }} onClick={logout}>Sign out</button></div>
      </aside>
      <main>
        <div className="topbar">
          <h2>{view}</h2>
          <span className="spacer" />
          {device && <span className="chip">Device <b>{device}</b></span>}
        </div>
        <ViewRouter view={view} />
      </main>
    </div>
  );
}

function ViewRouter({ view }: { view: View }) {
  switch (view) {
    case "Dashboard": return <Dashboard />;
    case "Usage Time": return <Usage />;
    case "Timeline": return <ActivityTable loader={api.timeline} cols={["timestamp_utc", "event_type", "application_name", "window_title"]} />;
    case "Browser": return <ActivityTable loader={api.browser} cols={["timestamp_utc", "application_name", "window_title", "metadata_json"]} />;
    case "System Events": return <ActivityTable loader={api.systemEvents} cols={["timestamp_utc", "event_type", "metadata_json"]} />;
    case "Screenshots": return <Screenshots />;
    case "Storage": return <Storage />;
    case "Audit Log": return <Audit />;
    case "Integrity": return <Integrity />;
    case "Configuration": return <Config />;
  }
}

/* ------------------------------ helpers ------------------------------- */
function useAsync<T>(fn: () => Promise<T>, deps: any[] = []): { data: T | null; err: string; loading: boolean } {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let alive = true;
    setLoading(true); setErr("");
    fn().then((d) => alive && setData(d)).catch((e) => alive && setErr(String(e.message || e))).finally(() => alive && setLoading(false));
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return { data, err, loading };
}

function Card({ label, children, cls }: { label: string; children: any; cls?: string }) {
  return <div className="card"><h4>{label}</h4><div className={"val " + (cls || "")}>{children}</div></div>;
}

function InfoButton({ onClick }: { onClick: () => void }) {
  return <button className="info-btn" title="Details" onClick={onClick}>i</button>;
}

/** Right-side detail drawer: key/value pairs + raw metadata JSON. */
function DetailDrawer({ title, item, onClose }: { title: string; item: Record<string, any> | null; onClose: () => void }) {
  if (!item) return null;
  const entries = Object.entries(item).filter(([k]) => k !== "metadata_json");
  let meta: any = null;
  if (item.metadata_json) { try { meta = JSON.parse(item.metadata_json); } catch { meta = item.metadata_json; } }
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <div className="drawer">
        <header><b>{title}</b><button className="x" onClick={onClose}>×</button></header>
        <div className="body">
          <dl className="kv">
            {entries.map(([k, v]) => (
              <div key={k} style={{ display: "contents" }}>
                <dt>{k.replace(/_/g, " ")}</dt>
                <dd className={k.includes("id") || k.includes("hash") || k.includes("sha") ? "mono" : ""}>
                  {v == null || v === "" ? "—" : String(v)}
                </dd>
              </div>
            ))}
          </dl>
          {meta != null && (
            <>
              <div className="section-title" style={{ marginTop: 16 }}>Metadata</div>
              <pre className="json">{typeof meta === "string" ? meta : JSON.stringify(meta, null, 2)}</pre>
            </>
          )}
        </div>
      </div>
    </>
  );
}

/* ------------------------------- icons -------------------------------- */
function Icon({ name, size = 18 }: { name: string; size?: number }) {
  const p: Record<string, any> = {
    width: size, height: size, viewBox: "0 0 24 24", fill: "none",
    stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round", strokeLinejoin: "round",
  };
  switch (name) {
    case "shield": return <svg {...p}><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" /><path d="M9 12l2 2 4-4" /></svg>;
    case "drive": return <svg {...p}><rect x="3" y="5" width="18" height="6" rx="2" /><rect x="3" y="13" width="18" height="6" rx="2" /><path d="M7 8h.01M7 16h.01" /></svg>;
    case "clock": return <svg {...p}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></svg>;
    case "camera": return <svg {...p}><path d="M4 8h3l1.5-2h7L18 8h2a1 1 0 011 1v9a1 1 0 01-1 1H4a1 1 0 01-1-1V9a1 1 0 011-1z" /><circle cx="12" cy="13" r="3.2" /></svg>;
    case "check": return <svg {...p}><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" /><path d="M9 12l2 2 4-4" /></svg>;
    case "copy": return <svg {...p}><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 012-2h10" /></svg>;
    case "done": return <svg {...p}><path d="M4 12l5 5L20 6" /></svg>;
    default: return null;
  }
}

/* ---------------------------- dashboard bits --------------------------- */
function CopyChip({ label, value }: { label: string; value: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); setDone(true); setTimeout(() => setDone(false), 1400); } catch {}
  };
  return (
    <div className="copychip">
      <div className="cc-body">
        <div className="cc-label">{label}</div>
        <div className="cc-val">{value}</div>
      </div>
      <button className="cc-btn" title="Copy" onClick={copy}><Icon name={done ? "done" : "copy"} size={15} /></button>
    </div>
  );
}

function StatusBadge({ label, value, tone, live }: { label: string; value: string; tone: string; live?: boolean }) {
  return (
    <div className="status-badge">
      <span className={`sb-dot ${tone}${live ? " live" : ""}`} />
      <div>
        <div className="sb-label">{label}</div>
        <div className={`sb-val ${tone}`}>{value}</div>
      </div>
    </div>
  );
}

function Metric({ icon, label, val, sub, meter }: { icon: string; label: string; val: any; sub?: any; meter?: number }) {
  return (
    <div className="card metric">
      <div className="m-icon"><Icon name={icon} size={20} /></div>
      <div className="m-body">
        <div className="m-label">{label}</div>
        <div className="m-val">{val}</div>
        {sub != null && <div className="m-sub">{sub}</div>}
        {meter != null && <div className="meter"><span style={{ width: `${Math.min(100, meter)}%` }} /></div>}
      </div>
    </div>
  );
}

/* ----------------------------- dashboard ------------------------------ */
function Dashboard() {
  const { data, err, loading } = useAsync(() => api.device());
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  const dev = data?.device, h = data?.health;
  const integ = h?.last_integrity_pass;
  const pct = h && h.storage_max_bytes ? Math.round((h.storage_used_bytes / h.storage_max_bytes) * 100) : 0;
  return (
    <div className="dash">
      <section className="device-hero">
        <div className="dh-avatar"><Icon name="shield" size={26} /></div>
        <div className="dh-left">
          <div className="dh-eyebrow">Managed device</div>
          <div className="dh-name">{dev?.system_name || "—"}</div>
          <div className="dh-meta">
            <span>Hostname <b>{dev?.hostname || "—"}</b></span>
            <span>OS <b>{dev?.os_version || "—"}</b></span>
            <span>Agent <b>v{dev?.agent_version || h?.agent_version || "—"}</b></span>
            <span>Last seen <b>{fmtTime(dev?.last_seen_at)}</b></span>
          </div>
        </div>
        <div className="dh-right">
          <CopyChip label="Device ID" value={dev?.device_id || "—"} />
        </div>
      </section>

      <section className="status-strip">
        <StatusBadge label="Agent" value={h?.agent_status || "—"} tone="ok" live={h?.agent_status === "RUNNING"} />
        <StatusBadge label="Database" value={h?.database || "—"} tone={h?.database === "HEALTHY" ? "ok" : "warn"} />
        <StatusBadge label="Encryption" value={h?.encryption || "—"} tone="ok" />
        <StatusBadge label="Integrity" value={integ == null ? "—" : integ ? "PASS" : "FAIL"} tone={integ == null ? "warn" : integ ? "ok" : "bad"} />
      </section>

      <section className="grid metrics">
        <Metric icon="drive" label="Storage" meter={pct}
          val={h ? `${fmtBytes(h.storage_used_bytes)} / ${fmtBytes(h.storage_max_bytes)}` : "—"}
          sub={`${pct}% used`} />
        <Metric icon="clock" label="Last event" val={fmtTime(h?.last_event_utc)} />
        <Metric icon="camera" label="Last screenshot" val={fmtTime(h?.last_screenshot_utc)} />
        <Metric icon="check" label="Integrity checked" val={fmtTime(h?.last_integrity_check_utc)}
          sub={integ == null ? undefined : integ ? "Chain valid" : "Chain broken"} />
      </section>
    </div>
  );
}

/* ------------------------------- usage -------------------------------- */
function Usage() {
  const [days, setDays] = useState(7);
  const app = useAsync(() => api.usage("app", days), [days]);
  const web = useAsync(() => api.usage("browser", days), [days]);
  return (
    <>
      <div className="toolbar">
        <span className="muted">Window:</span>
        <select value={days} onChange={(e) => setDays(Number(e.target.value))} style={{ width: 140 }}>
          <option value={1}>Last 24 hours</option>
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
        </select>
      </div>
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
        <div className="card">
          <h4>Application usage time</h4>
          <UsageBars items={app.data} loading={app.loading} err={app.err} />
        </div>
        <div className="card">
          <h4>Browser domain time</h4>
          <UsageBars items={web.data} loading={web.loading} err={web.err} />
        </div>
      </div>
    </>
  );
}

function UsageBars({ items, loading, err }: { items: UsageItem[] | null; loading: boolean; err: string }) {
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  const rows = (items || []).slice(0, 15);
  if (!rows.length) return <div className="muted">No activity in this window.</div>;
  const max = Math.max(...rows.map((r) => r.seconds), 1);
  return (
    <div className="bars">
      {rows.map((r) => (
        <div className="bar-row" key={r.name}>
          <div className="bar-name" title={r.name}>{r.name}</div>
          <div className="bar-track"><div className="bar-fill" style={{ width: `${(r.seconds / max) * 100}%` }} /></div>
          <div className="bar-val">{fmtDuration(r.seconds)}</div>
        </div>
      ))}
    </div>
  );
}

/* --------------------------- activity table --------------------------- */
function ActivityTable({ loader, cols }: { loader: () => Promise<ActivityRow[]>; cols: string[] }) {
  const { data, err, loading } = useAsync(loader);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<ActivityRow | null>(null);
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  const rows = (data || []).filter((r) =>
    !q || JSON.stringify(r).toLowerCase().includes(q.toLowerCase()));
  const label = (c: string) => c.replace(/_/g, " ").replace("utc", "time");
  return (
    <>
      <div className="toolbar">
        <input placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="muted">{rows.length} rows</span>
      </div>
      <div className="tablewrap">
        <table>
          <thead><tr>{cols.map((c) => <th key={c}>{label(c)}</th>)}<th style={{ width: 44 }}></th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.event_id}>
                {cols.map((c) => {
                  const v = (r as any)[c];
                  if (c === "timestamp_utc") return <td key={c} className="mono">{fmtTime(v)}</td>;
                  if (c === "event_type") return <td key={c}><span className="evtype">{v}</span></td>;
                  return <td key={c} className={"cellclip " + (c === "metadata_json" ? "mono" : "")}>{v ?? "—"}</td>;
                })}
                <td><InfoButton onClick={() => setSel(r)} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <DetailDrawer title="Event detail" item={sel} onClose={() => setSel(null)} />
    </>
  );
}

/* ----------------------------- screenshots ---------------------------- */
/** Decrypted thumbnail preview; falls back to a lock icon if decrypt/verify fails. */
function ShotThumb({ id, onOpen }: { id: string; onOpen: () => void }) {
  const [failed, setFailed] = useState(false);
  return (
    <div className="frame" title="Click to decrypt & view full" onClick={onOpen}>
      {failed
        ? <span className="lock">🔒</span>
        : <img className="thumbimg" src={api.screenshotThumbUrl(id)} alt="" loading="lazy" onError={() => setFailed(true)} />}
    </div>
  );
}

function Screenshots() {
  const { data, err, loading } = useAsync(() => api.screenshots());
  const [open, setOpen] = useState<ScreenshotRow | null>(null);
  const [sel, setSel] = useState<ScreenshotRow | null>(null);
  const [imgErr, setImgErr] = useState("");
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  const rows = data || [];
  if (!rows.length) return <div className="muted">No screenshots captured yet.</div>;
  return (
    <>
      <div className="toolbar"><span className="muted">{rows.length} screenshots · click a card to decrypt & view</span></div>
      <div className="shots">
        {rows.map((r) => (
          <div className="shot" key={r.screenshot_id}>
            <ShotThumb id={r.screenshot_id} onOpen={() => { setImgErr(""); setOpen(r); }} />
            <div className="meta">
              <span className="t" title={fmtTime(r.timestamp_utc)}>{fmtTime(r.timestamp_utc)}</span>
              <InfoButton onClick={() => setSel(r)} />
            </div>
          </div>
        ))}
      </div>
      {open && (
        <div className="overlay" onClick={() => setOpen(null)}>
          {imgErr
            ? <div className="err">{imgErr}</div>
            : <img src={api.screenshotImageUrl(open.screenshot_id)} alt=""
                onError={() => setImgErr("Could not decrypt/verify this screenshot (possible tamper).")} />}
          <div className="cap">{fmtTime(open.timestamp_utc)} · click to close</div>
        </div>
      )}
      <DetailDrawer title="Screenshot detail" item={sel} onClose={() => setSel(null)} />
    </>
  );
}

/* ------------------------------ storage ------------------------------- */
function Storage() {
  const { data, err, loading } = useAsync(() => api.storage());
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  const p = data?.policy || {}, st = p.storage || {}, ret = p.retention || {};
  const used = data?.used_bytes || 0, max = st.max_bytes || 1;
  const pct = Math.min(100, Math.round((used / max) * 100));
  return (
    <div className="grid kpi">
      <div className="card" style={{ gridColumn: "1 / -1" }}>
        <h4>Disk usage</h4>
        <div className="val sm">{fmtBytes(used)} / {fmtBytes(max)} ({pct}%)</div>
        <div className="bar-track" style={{ marginTop: 10, height: 12 }}>
          <div className="bar-fill" style={{ width: `${pct}%`, background: pct >= (st.critical_pct || 90) ? "var(--bad)" : pct >= (st.warn_pct || 80) ? "var(--warn)" : undefined }} />
        </div>
      </div>
      <Card label="Warn / Critical" cls="sm">{st.warn_pct}% / {st.critical_pct}%</Card>
      <Card label="Screenshot retention" cls="sm">{ret.screenshot_days} days</Card>
      <Card label="Event retention" cls="sm">{ret.event_days} days</Card>
      <Card label="Delete un-synced" cls="sm">{String(ret.delete_unsynced)}</Card>
    </div>
  );
}

/* ------------------------------- audit -------------------------------- */
function Audit() {
  const { data, err, loading } = useAsync(() => api.audit());
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  const rows: AuditRow[] = data || [];
  return (
    <div className="tablewrap">
      <table>
        <thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Detail</th></tr></thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              <td className="mono">{fmtTime(r.timestamp_utc)}</td>
              <td><span className="evtype">{r.action}</span></td>
              <td>{r.actor || "—"}</td>
              <td className="mono">{r.metadata_json || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ----------------------------- integrity ------------------------------ */
function Integrity() {
  const [res, setRes] = useState<{ events_checked: number; invalid_records: number; pass: boolean; first_breaks: string[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  async function run() {
    setBusy(true); setErr(""); setRes(null);
    try { setRes(await api.verifyIntegrity()); }
    catch (e: any) { setErr(String(e.message || e)); }
    finally { setBusy(false); }
  }
  return (
    <>
      <button className="btn" onClick={run} disabled={busy}>{busy ? "Verifying…" : "Run integrity verification"}</button>
      {err && <div className="err">{err}</div>}
      {res && (
        <div className="grid kpi" style={{ marginTop: 16 }}>
          <Card label="Events checked">{res.events_checked.toLocaleString()}</Card>
          <Card label="Invalid records">{res.invalid_records}</Card>
          <Card label="Result"><span className={"pill " + (res.pass ? "ok" : "bad")}>{res.pass ? "PASS" : "FAIL"}</span></Card>
        </div>
      )}
    </>
  );
}

/* ------------------------------- config ------------------------------- */
function Config() {
  const { data, err, loading } = useAsync(() => api.config());
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  return (
    <>
      <div className="section-title">Policy</div>
      <pre className="json">{JSON.stringify(data?.policy, null, 2)}</pre>
      <div className="section-title" style={{ marginTop: 16 }}>Agent (password redacted)</div>
      <pre className="json">{JSON.stringify(data?.agent, null, 2)}</pre>
    </>
  );
}
