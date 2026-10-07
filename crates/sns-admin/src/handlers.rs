//! Admin API handlers (spec §31–33). All DB/file work is synchronous (no await while a
//! rusqlite connection is open), which keeps the SQLite connection off any await point.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use sns_core::clock::now_utc_iso;
use sns_core::config::Policy;
use sns_core::security::{crypto, KeyManager};
use sns_core::storage::dropbox::{self, DropRecord};
use sns_core::storage::{filesystem, Storage};
use sns_shared::events::{ActivityEvent, EventType};
use sns_shared::ids::new_event_id;

use crate::auth;
use crate::state::AppState;

const SESSION_COOKIE: &str = "sns_session";

// ------------------------------- helpers -----------------------------------

fn db(state: &AppState) -> Result<Storage, Response> {
    // Inspection-only fast open (no migrate / WAL-pragma per request).
    Storage::open_reader(state.data_root.join("database").join("activity.db"), &state.device_id)
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")))
}

fn error(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|kv| {
        let kv = kv.trim();
        kv.strip_prefix(&format!("{SESSION_COOKIE}=")).map(|v| v.to_string())
    })
}

/// Returns the caller's valid session token or a 401 response.
fn require_auth(state: &AppState, headers: &HeaderMap) -> Result<String, Response> {
    match session_token(headers) {
        Some(t) if state.valid_session(&t) => Ok(t),
        _ => Err(error(StatusCode::UNAUTHORIZED, "authentication required")),
    }
}

// ------------------------------- auth --------------------------------------

#[derive(Deserialize)]
pub struct LoginBody {
    password: String,
}

pub async fn login(State(state): State<AppState>, Json(body): Json<LoginBody>) -> Response {
    if !state.login_allowed() {
        return error(StatusCode::TOO_MANY_REQUESTS, "too many login attempts");
    }
    if !auth::check_login(&body.password, &state.password_hash) {
        // Best-effort audit of the failed attempt (append-only; safe concurrent writer).
        if let Ok(s) = db(&state) {
            let _ = s.audit("ADMIN_LOGIN_FAILED", Some("admin"), None);
        }
        return error(StatusCode::UNAUTHORIZED, "invalid credentials");
    }

    let token = auth::new_session_token();
    let csrf = auth::new_session_token();
    state.issue_session(&token, &csrf);
    if let Ok(s) = db(&state) {
        let _ = s.audit("ADMIN_LOGIN", Some("admin"), None);
    }

    let cookie = format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        state.ttl.as_secs()
    );
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, cookie.parse().unwrap());
    (headers, Json(json!({ "ok": true, "csrf": csrf }))).into_response()
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(t) = session_token(&headers) {
        state.revoke(&t);
    }
    let clear = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    let mut h = HeaderMap::new();
    h.insert(header::SET_COOKIE, clear.parse().unwrap());
    (h, Json(json!({ "ok": true }))).into_response()
}

// ------------------------------- reads -------------------------------------

pub async fn device(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    let s = match db(&state) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let dev = s.device_row().ok().flatten();
    let health = read_health(&state);
    Json(json!({ "device": dev, "health": health })).into_response()
}

pub async fn health(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    Json(read_health(&state).unwrap_or(json!(null))).into_response()
}

fn read_health(state: &AppState) -> Option<serde_json::Value> {
    let raw = std::fs::read(state.data_root.join("runtime").join("health.json")).ok()?;
    serde_json::from_slice(&raw).ok()
}

#[derive(Deserialize)]
pub struct RangeQuery {
    /// UTC ISO lower bound (inclusive).
    from: Option<String>,
    /// UTC ISO upper bound (exclusive).
    to: Option<String>,
}

pub async fn timeline(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<RangeQuery>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    match db(&state).and_then(|s| s.recent_activity(500, q.from.as_deref(), q.to.as_deref()).map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))) {
        Ok(rows) => Json(rows).into_response(),
        Err(r) => r,
    }
}

pub async fn browser(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<RangeQuery>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    match db(&state).and_then(|s| s.recent_browser(500, q.from.as_deref(), q.to.as_deref()).map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))) {
        Ok(rows) => Json(rows).into_response(),
        Err(r) => r,
    }
}

pub async fn system_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<RangeQuery>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    // Lifecycle events live in the chained activity table in Phase 1.
    let types = ["AGENT_STARTUP", "AGENT_SHUTDOWN", "SYSTEM_STARTUP", "SYSTEM_SHUTDOWN",
                 "USER_SESSION_STARTED", "USER_SESSION_ENDED", "USB_DEVICE_CONNECTED",
                 "USB_DEVICE_DISCONNECTED", "STORAGE_WARNING", "STORAGE_CRITICAL",
                 "INTEGRITY_FAILURE", "CONFIGURATION_CHANGED", "SESSION_IDLE", "SESSION_ACTIVE",
                 "FILE_COPIED_TO_USB", "DOCUMENT_PRINTED"];
    match db(&state).and_then(|s| s.recent_activity(800, q.from.as_deref(), q.to.as_deref()).map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))) {
        Ok(rows) => {
            let filtered: Vec<_> = rows.into_iter().filter(|r| types.contains(&r.event_type.as_str())).collect();
            Json(filtered).into_response()
        }
        Err(r) => r,
    }
}

pub async fn screenshots(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<RangeQuery>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    match db(&state).and_then(|s| {
        s.list_screenshots_range(300, q.from.as_deref(), q.to.as_deref())
            .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
    }) {
        Ok(rows) => Json(rows).into_response(),
        Err(r) => r,
    }
}

pub async fn audit(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    match db(&state).and_then(|s| s.recent_audit(300).map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))) {
        Ok(rows) => Json(rows).into_response(),
        Err(r) => r,
    }
}

#[derive(Deserialize)]
pub struct UsageQuery {
    /// "app" (default) or "browser".
    kind: Option<String>,
    /// look-back window in days (default 7).
    days: Option<u32>,
}

pub async fn usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<UsageQuery>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    let days = q.days.unwrap_or(7).min(365);
    let since = sns_core::clock::iso_days_ago(days);
    let (name_col, event_type) = match q.kind.as_deref() {
        Some("browser") => ("window_title", "BROWSER_ACTIVITY"),
        _ => ("application_name", "ACTIVE_APPLICATION_CHANGED"),
    };
    // 15-min idle cap so an app left in focus does not inflate totals.
    match db(&state).and_then(|s| {
        s.usage_by(name_col, event_type, &since, 900)
            .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
    }) {
        Ok(rows) => Json(rows).into_response(),
        Err(r) => r,
    }
}

#[derive(Deserialize)]
pub struct IdleQuery {
    /// look-back window in days (default 1 = today-ish).
    days: Option<u32>,
}

/// Total idle seconds over the look-back window (feature #2). Derived from the
/// SESSION_IDLE/SESSION_ACTIVE transition events.
pub async fn idle(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<IdleQuery>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    let days = q.days.unwrap_or(1).min(365);
    let since = sns_core::clock::iso_days_ago(days);
    match db(&state).and_then(|s| {
        s.idle_seconds_since(&since)
            .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
    }) {
        Ok(secs) => Json(serde_json::json!({ "idle_seconds": secs, "days": days })).into_response(),
        Err(r) => r,
    }
}

#[derive(Deserialize)]
pub struct AlertsQuery {
    /// look-back window in days (default 7).
    days: Option<u32>,
}

/// Local alerts (feature #4): load the rules (config/alerts.json or defaults) and evaluate
/// them over recent events. Read-only; no new capture, no network.
pub async fn alerts(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<AlertsQuery>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    let days = q.days.unwrap_or(7).min(365);
    let since = sns_core::clock::iso_days_ago(days);
    let rules = match sns_core::alerts::AlertRules::load_or_default(
        state.data_root.join("config").join("alerts.json"),
    ) {
        Ok(r) => r,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    match db(&state).and_then(|s| {
        s.recent_activity(5000, Some(since.as_str()), None)
            .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
    }) {
        Ok(rows) => Json(sns_core::alerts::evaluate(&rules, &rows)).into_response(),
        Err(r) => r,
    }
}

/// Current alert rules (config/alerts.json or defaults), for the editor.
pub async fn alert_rules(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    match sns_core::alerts::AlertRules::load_or_default(state.data_root.join("config").join("alerts.json")) {
        Ok(rules) => Json(rules).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct AlertRulesUpdate {
    csrf: String,
    rules: sns_core::alerts::AlertRules,
}

/// Save alert rules to config/alerts.json. Audited. Re-read on each alerts evaluation.
pub async fn update_alert_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AlertRulesUpdate>,
) -> Response {
    let token = match require_auth(&state, &headers) {
        Ok(t) => t,
        Err(r) => return r,
    };
    if !state.csrf_matches(&token, &body.csrf) {
        return error(StatusCode::FORBIDDEN, "bad csrf token");
    }
    let path = state.data_root.join("config").join("alerts.json");
    let bytes = match serde_json::to_vec_pretty(&body.rules) {
        Ok(b) => b,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    if let Err(e) = std::fs::write(&path, bytes) {
        return error(StatusCode::INTERNAL_SERVER_ERROR, &format!("write alerts.json: {e}"));
    }
    if let Ok(s) = db(&state) {
        let _ = s.audit("ALERT_RULES_CHANGED", Some("admin"), None);
    }
    Json(json!({ "ok": true })).into_response()
}

#[derive(Deserialize)]
pub struct DaysQuery {
    days: Option<u32>,
}

/// Transfer summary — total volume + per-kind breakdown of files copied to USB in the window.
pub async fn transfer_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<DaysQuery>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    let days = q.days.unwrap_or(7).min(365);
    let since = sns_core::clock::iso_days_ago(days);
    let rows = match db(&state).and_then(|s| {
        s.recent_activity(5000, Some(since.as_str()), None)
            .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
    }) {
        Ok(v) => v,
        Err(r) => return r,
    };
    // Extract (path, size) from FILE_COPIED_TO_USB metadata.
    let files: Vec<(String, u64)> = rows
        .iter()
        .filter(|r| r.event_type == "FILE_COPIED_TO_USB")
        .filter_map(|r| {
            let meta = r.metadata_json.as_deref()?;
            let v: serde_json::Value = serde_json::from_str(meta).ok()?;
            let path = v.get("path").and_then(|p| p.as_str()).unwrap_or("").to_string();
            let size = v.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
            Some((path, size))
        })
        .collect();
    Json(sns_core::collectors::usbfiles::summarize(&files)).into_response()
}

/// Installed data-transfer apps detected on this machine (names + category). Live registry
/// read; no app data/traffic is accessed.
pub async fn transfer_apps(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    Json(sns_core::collectors::transferapps::scan_installed()).into_response()
}

/// Live inventory of USB devices currently connected (any class), with identity. Unlike the
/// event stream (connect/disconnect, baselined at boot), this reflects the *present* set, so
/// already-plugged devices (mouse/keyboard/etc.) are visible without a replug. Live read via
/// SetupDi; no capture, no persistence.
pub async fn usb_devices(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    let devices = sns_core::collectors::usb::list_usb_devices();
    Json(devices).into_response()
}

pub async fn storage(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    let used = filesystem::dir_size_bytes(&state.data_root);
    let policy = Policy::load(state.data_root.join("config").join("policy.json")).ok();
    Json(json!({ "used_bytes": used, "policy": policy })).into_response()
}

pub async fn config(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    // Return policy fully; agent.json with the password hash redacted.
    let policy = Policy::load(state.data_root.join("config").join("policy.json")).ok();
    let mut agent: serde_json::Value = std::fs::read(state.data_root.join("config").join("agent.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(json!({}));
    if let Some(admin) = agent.get_mut("admin").and_then(|a| a.as_object_mut()) {
        admin.insert("password_hash".into(), json!("<redacted>"));
    }
    Json(json!({ "agent": agent, "policy": policy })).into_response()
}

#[derive(Deserialize)]
pub struct CsrfBody {
    csrf: String,
}

pub async fn integrity_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CsrfBody>,
) -> Response {
    let token = match require_auth(&state, &headers) {
        Ok(t) => t,
        Err(r) => return r,
    };
    if !state.csrf_matches(&token, &body.csrf) {
        return error(StatusCode::FORBIDDEN, "bad csrf token");
    }
    match db(&state).and_then(|s| s.verify_integrity().map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))) {
        Ok(report) => Json(json!({
            "events_checked": report.events_checked,
            "invalid_records": report.invalid_records,
            "pass": report.is_pass(),
            "first_breaks": report.first_breaks,
        }))
        .into_response(),
        Err(r) => r,
    }
}

// ------------------------------ retention (#5) -----------------------------

fn db_writer(state: &AppState) -> Result<Storage, Response> {
    Storage::open(state.data_root.join("database").join("activity.db"), &state.device_id, "NORMAL")
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")))
}

fn load_policy(state: &AppState) -> Result<Policy, Response> {
    Policy::load(state.data_root.join("config").join("policy.json"))
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &format!("policy: {e}")))
}

#[derive(Deserialize)]
pub struct RetentionUpdate {
    csrf: String,
    retention: sns_core::config::RetentionPolicy,
}

/// Update the retention section of policy.json (validated). Audited. Capture-policy fields are
/// untouched; the service re-reads policy on its next cycle.
pub async fn update_retention(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RetentionUpdate>,
) -> Response {
    let token = match require_auth(&state, &headers) {
        Ok(t) => t,
        Err(r) => return r,
    };
    if !state.csrf_matches(&token, &body.csrf) {
        return error(StatusCode::FORBIDDEN, "bad csrf token");
    }
    let mut policy = match load_policy(&state) {
        Ok(p) => p,
        Err(r) => return r,
    };
    policy.retention = body.retention;
    if let Err(e) = policy.validate() {
        return error(StatusCode::BAD_REQUEST, &format!("invalid policy: {e}"));
    }
    let path = state.data_root.join("config").join("policy.json");
    let json_bytes = match serde_json::to_vec_pretty(&policy) {
        Ok(b) => b,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    if let Err(e) = std::fs::write(&path, json_bytes) {
        return error(StatusCode::INTERNAL_SERVER_ERROR, &format!("write policy: {e}"));
    }
    if let Ok(s) = db(&state) {
        let _ = s.audit("RETENTION_POLICY_CHANGED", Some("admin"), None);
    }
    Json(json!({ "ok": true })).into_response()
}

#[derive(Deserialize)]
pub struct PurgeBrowserBody {
    csrf: String,
    /// Optional overrides from the form, so the admin can purge without saving policy first.
    mode: Option<String>,
    domains: Option<Vec<String>>,
    days: Option<u32>,
}

/// Run browser-history removal now. Uses the form-supplied mode/domains/days if present,
/// otherwise the saved policy. Deletes matching BROWSER_ACTIVITY rows and re-seals the chain.
pub async fn purge_browser(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PurgeBrowserBody>,
) -> Response {
    let token = match require_auth(&state, &headers) {
        Ok(t) => t,
        Err(r) => return r,
    };
    if !state.csrf_matches(&token, &body.csrf) {
        return error(StatusCode::FORBIDDEN, "bad csrf token");
    }
    let policy = match load_policy(&state) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let def = &policy.retention.browser;
    let mode = body.mode.clone().unwrap_or_else(|| def.mode.clone());
    let domains = body.domains.clone().unwrap_or_else(|| def.domains.clone());
    let days = body.days.unwrap_or(def.days);
    let br = sns_core::config::BrowserRetention { mode, domains, days };
    if br.mode == "none" {
        return Json(json!({ "deleted": 0, "mode": "none" })).into_response();
    }
    let cutoff = sns_core::clock::iso_days_ago(br.days);
    let mut writer = match db_writer(&state) {
        Ok(w) => w,
        Err(r) => return r,
    };
    match writer.purge_browser(&br.mode, &br.domains, &cutoff) {
        Ok(n) => {
            let _ = writer.audit("BROWSER_HISTORY_PURGED", Some("admin"), Some(&format!("{{\"deleted\":{n},\"mode\":\"{}\"}}", br.mode)));
            Json(json!({ "deleted": n, "mode": br.mode })).into_response()
        }
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// Run screenshot cleanup now: delete frames older than `max_age_days`, plus (if enabled)
/// blank/lock/near-duplicate frames detected by decrypting + fingerprinting the survivors.
/// Unlinks the files. Audited.
pub async fn purge_screenshots(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CsrfBody>,
) -> Response {
    let token = match require_auth(&state, &headers) {
        Ok(t) => t,
        Err(r) => return r,
    };
    if !state.csrf_matches(&token, &body.csrf) {
        return error(StatusCode::FORBIDDEN, "bad csrf token");
    }
    let policy = match load_policy(&state) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let sc = &policy.retention.screenshot_cleanup;
    let writer = match db_writer(&state) {
        Ok(w) => w,
        Err(r) => return r,
    };

    // 1) Age gate: everything older than max_age_days. `0` = disabled (no age deletion) so a
    // zero cannot accidentally wipe every screenshot — the heuristic (if on) still runs.
    let aged = if sc.max_age_days == 0 {
        Vec::new()
    } else {
        let age_cut = sns_core::clock::iso_days_ago(sc.max_age_days);
        match writer.screenshots_for_cleanup(Some(&age_cut)) {
            Ok(v) => v,
            Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        }
    };
    let aged_ids: std::collections::HashSet<String> = aged.iter().map(|(id, _)| id.clone()).collect();

    // 2) Heuristic over the survivors (needs decrypt).
    let mut heuristic_ids: Vec<String> = Vec::new();
    let mut path_of: std::collections::HashMap<String, String> =
        aged.iter().cloned().map(|(id, p)| (id, p)).collect();
    if sc.heuristic_enabled {
        let km = match KeyManager::load(state.data_root.join("keys").join("keyring.json")) {
            Ok(k) => k,
            Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &format!("keys: {e}")),
        };
        let survivors: Vec<(String, String)> = match writer.screenshots_for_cleanup(None) {
            Ok(v) => v.into_iter().filter(|(id, _)| !aged_ids.contains(id)).collect(),
            Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        };
        let frames: Vec<(String, Option<sns_core::collectors::screenshot::Fingerprint>)> = survivors
            .iter()
            .map(|(id, path)| {
                let fp = std::fs::read(path)
                    .ok()
                    .and_then(|blob| crypto::decrypt(km.data_key(), &blob).ok())
                    .and_then(|png| sns_core::collectors::screenshot::fingerprint(&png).ok());
                (id.clone(), fp)
            })
            .collect();
        for (id, p) in &survivors {
            path_of.insert(id.clone(), p.clone());
        }
        heuristic_ids = sns_core::collectors::screenshot::plan_cleanup(&frames, true);
    }

    // 3) Delete rows + unlink files.
    let mut all_ids: Vec<String> = aged_ids.iter().cloned().collect();
    all_ids.extend(heuristic_ids.iter().cloned());
    let deleted = match writer.delete_screenshots_by_ids(&all_ids) {
        Ok(n) => n,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    for id in &all_ids {
        if let Some(p) = path_of.get(id) {
            let _ = std::fs::remove_file(p);
        }
    }
    let _ = writer.audit(
        "SCREENSHOTS_CLEANED",
        Some("admin"),
        Some(&format!("{{\"age\":{},\"heuristic\":{},\"deleted\":{}}}", aged_ids.len(), heuristic_ids.len(), deleted)),
    );
    Json(json!({
        "deleted": deleted,
        "by_age": aged_ids.len(),
        "by_heuristic": heuristic_ids.len(),
    }))
    .into_response()
}

// ------------------------- screenshot on-demand view -----------------------

#[derive(Deserialize)]
pub struct ImgQuery {
    /// `1` → small downscaled preview (not audited); absent → full-size (audited view).
    thumb: Option<u8>,
}

pub async fn screenshot_image(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<ImgQuery>,
) -> Response {
    if let Err(r) = require_auth(&state, &headers) {
        return r;
    }
    let is_thumb = q.thumb == Some(1);
    let s = match db(&state) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let meta = match s.get_screenshot(&id) {
        Ok(Some(m)) => m,
        Ok(None) => return error(StatusCode::NOT_FOUND, "screenshot not found"),
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let ciphertext = match std::fs::read(&meta.file_path) {
        Ok(b) => b,
        Err(_) => return error(StatusCode::NOT_FOUND, "screenshot file missing"),
    };

    // Tamper check: SHA-256 of the on-disk ciphertext must match the recorded hash (spec §12).
    let sha = hex::encode(Sha256::digest(&ciphertext));
    if sha != meta.sha256 {
        let _ = s.audit("SCREENSHOT_TAMPER_DETECTED", Some("admin"), Some(&id));
        report_integrity_failure(&state, &id, "screenshot sha256 mismatch");
        return error(StatusCode::CONFLICT, "integrity check failed: file modified");
    }

    // Decrypt in memory only (GCM auth tag is a second tamper check).
    let km = match KeyManager::load(state.data_root.join("keys").join("keyring.json")) {
        Ok(k) => k,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &format!("key: {e}")),
    };
    let png = match crypto::decrypt(km.data_key(), &ciphertext) {
        Ok(p) => p,
        Err(_) => {
            let _ = s.audit("SCREENSHOT_TAMPER_DETECTED", Some("admin"), Some(&id));
            report_integrity_failure(&state, &id, "screenshot decrypt/auth failed");
            return error(StatusCode::CONFLICT, "integrity check failed: auth tag");
        }
    };

    // Thumbnail preview: downscale, do NOT audit (previews load in bulk on the gallery).
    if is_thumb {
        return match sns_core::collectors::screenshot::thumbnail(&png, 256) {
            Ok(t) => (
                [(header::CONTENT_TYPE, "image/png"), (header::CACHE_CONTROL, "private, max-age=300")],
                t,
            )
                .into_response(),
            Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "thumbnail failed"),
        };
    }

    // Full-size open = an actual admin view → audited.
    let _ = s.audit("SCREENSHOT_VIEWED", Some("admin"), Some(&id));
    ([(header::CONTENT_TYPE, "image/png")], png).into_response()
}

/// Report a tamper to the service via the drop box so it chains an INTEGRITY_FAILURE event
/// (preserving the single-writer hash chain — the admin never writes the chain directly).
fn report_integrity_failure(state: &AppState, screenshot_id: &str, reason: &str) {
    let ev = ActivityEvent {
        event_id: new_event_id(),
        device_id: (*state.device_id).clone(),
        event_type: EventType::IntegrityFailure,
        timestamp_utc: now_utc_iso(),
        application_name: None,
        process_name: None,
        window_title: None,
        metadata_json: Some(json!({ "screenshot_id": screenshot_id, "reason": reason }).to_string()),
    };
    let stem = ev.event_id.clone();
    let _ = dropbox::write_record(&state.data_root, &stem, &DropRecord::Activity(ev));
}

// ------------------------------- UI ----------------------------------------

/// The built React SPA (admin-ui/dist), embedded at compile time.
#[derive(rust_embed::RustEmbed)]
#[folder = "../../admin-ui/dist"]
struct Ui;

/// Serve a static asset, falling back to index.html for SPA client-side routes.
pub async fn static_handler(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    let file = Ui::get(path).or_else(|| Ui::get("index.html"));
    match file {
        Some(f) => {
            let ct = content_type(if Ui::get(path).is_some() { path } else { "index.html" });
            ([(header::CONTENT_TYPE, ct)], f.data.into_owned()).into_response()
        }
        None => (StatusCode::NOT_FOUND, "UI not built. Run: npm --prefix admin-ui run build").into_response(),
    }
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "json" => "application/json",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        _ => "application/octet-stream",
    }
}
