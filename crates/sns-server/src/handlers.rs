//! HTTP handlers. Every data path is org-scoped: device endpoints act only within the token's
//! org; admin endpoints act only within the session's org.

use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth;
use crate::state::AppState;

const SESSION_COOKIE: &str = "sns_srv_session";
const SESSION_TTL: Duration = Duration::from_secs(3600);

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

pub async fn healthz() -> Response {
    Json(json!({ "ok": true })).into_response()
}

/// Latest agent version + download URL, for agent auto-update checks. Configured via
/// SNS_AGENT_VERSION / SNS_AGENT_URL env (so ops can publish a new build without a rebuild).
pub async fn agent_version() -> Response {
    let version = std::env::var("SNS_AGENT_VERSION").unwrap_or_else(|_| "1.0.0".into());
    let url = std::env::var("SNS_AGENT_URL").unwrap_or_default();
    Json(json!({ "version": version, "url": url })).into_response()
}

/// The central dashboard (single embedded page; talks to the org-scoped admin API).
pub async fn dashboard() -> Response {
    axum::response::Html(include_str!("dashboard.html")).into_response()
}

// ------------------------------- device auth -------------------------------

/// Resolve a Bearer device token → (org_id, device_pk). None if missing/invalid/revoked.
async fn device_principal(state: &AppState, headers: &HeaderMap) -> Option<(i64, i64)> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?.trim();
    let hash = auth::sha256_hex(token);
    let row = sqlx::query_as::<_, (i64, i64)>(
        "SELECT org_id, device_pk FROM device_tokens WHERE token_hash = $1 AND revoked_at IS NULL",
    )
    .bind(hash)
    .fetch_optional(&state.db)
    .await
    .ok()??;
    Some(row)
}

// ------------------------------- registration ------------------------------

#[derive(Deserialize)]
pub struct RegisterReq {
    pub enroll_token: String,
    pub device_id: String,
    pub system_name: Option<String>,
    pub hostname: Option<String>,
    pub os_version: Option<String>,
    pub agent_version: Option<String>,
}

#[derive(Deserialize)]
pub struct SignupReq {
    pub org_name: String,
    pub admin_email: String,
    pub admin_password: String,
}

/// Self-serve org signup: creates the business, its boss admin, a trial license, and returns
/// a one-time device enroll token. This is how a customer onboards without the CLI.
pub async fn signup(State(state): State<AppState>, Json(req): Json<SignupReq>) -> Response {
    if req.org_name.trim().is_empty() || !req.admin_email.contains('@') || req.admin_password.len() < 8 {
        return err(StatusCode::BAD_REQUEST, "org name, a valid email, and an 8+ char password are required");
    }
    // Email must be unique across the system (one login per person).
    let taken: Option<i64> = sqlx::query_scalar("SELECT id FROM admin_users WHERE email = $1")
        .bind(&req.admin_email)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    if taken.is_some() {
        return err(StatusCode::CONFLICT, "that email is already registered");
    }
    let enroll_token = auth::generate_token();
    let org_id = match sqlx::query_scalar::<_, i64>(
        "INSERT INTO orgs (name, enroll_token_hash) VALUES ($1,$2) RETURNING id",
    )
    .bind(req.org_name.trim())
    .bind(auth::sha256_hex(&enroll_token))
    .fetch_one(&state.db)
    .await
    {
        Ok(id) => id,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let phc = match auth::hash_password(&req.admin_password) {
        Ok(h) => h,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    if let Err(e) = sqlx::query("INSERT INTO admin_users (org_id, email, password_hash, role) VALUES ($1,$2,$3,'admin')")
        .bind(org_id).bind(&req.admin_email).bind(&phc).execute(&state.db).await
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
    }
    // 14-day trial, 5 seats.
    let _ = sqlx::query(
        "INSERT INTO licenses (org_id, plan, seats, status, trial_ends)
         VALUES ($1,'trial',5,'active', now() + interval '14 days')",
    )
    .bind(org_id)
    .execute(&state.db)
    .await;
    Json(json!({ "ok": true, "org_id": org_id, "enroll_token": enroll_token })).into_response()
}

/// Seat / license gate: Ok(()) if a NEW device may enroll, Err(reason) otherwise. Existing
/// devices (re-register) always pass. Orgs with no license row are treated as unlimited
/// (CLI-provisioned before licensing existed).
async fn license_allows_new_device(state: &AppState, org_id: i64) -> Result<(), String> {
    let lic = sqlx::query_as::<_, (String, i32, String, Option<time::OffsetDateTime>)>(
        "SELECT plan, seats, status, trial_ends FROM licenses WHERE org_id = $1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| e.to_string())?;
    let Some((plan, seats, status, trial_ends)) = lic else {
        return Ok(()); // no license row → unlimited (legacy/CLI org)
    };
    if status != "active" {
        return Err("license suspended".into());
    }
    if plan == "trial" {
        if let Some(ends) = trial_ends {
            if ends < time::OffsetDateTime::now_utc() {
                return Err("trial expired".into());
            }
        }
    }
    let used: i64 = sqlx::query_scalar("SELECT count(*) FROM devices WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| e.to_string())?;
    if used >= seats as i64 {
        return Err(format!("seat limit reached ({seats}); upgrade your plan"));
    }
    Ok(())
}

/// Enroll a device into its org (identified by the enroll token) and issue a device token.
/// Idempotent on (org_id, device_id): re-registering updates the row and issues a fresh token.
pub async fn register(State(state): State<AppState>, Json(req): Json<RegisterReq>) -> Response {
    let org_id = match sqlx::query_scalar::<_, i64>("SELECT id FROM orgs WHERE enroll_token_hash = $1")
        .bind(auth::sha256_hex(&req.enroll_token))
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => return err(StatusCode::UNAUTHORIZED, "invalid enroll token"),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    // Seat / license gate for a NEW device (existing devices re-register freely).
    let is_new: bool = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM devices WHERE org_id = $1 AND device_id = $2",
    )
    .bind(org_id)
    .bind(&req.device_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .is_none();
    if is_new {
        if let Err(reason) = license_allows_new_device(&state, org_id).await {
            return err(StatusCode::FORBIDDEN, &reason);
        }
    }

    let device_pk = match sqlx::query_scalar::<_, i64>(
        "INSERT INTO devices (org_id, device_id, system_name, hostname, os_version, agent_version, last_seen_at)
         VALUES ($1,$2,$3,$4,$5,$6, now())
         ON CONFLICT (org_id, device_id) DO UPDATE SET
            system_name = EXCLUDED.system_name, hostname = EXCLUDED.hostname,
            os_version = EXCLUDED.os_version, agent_version = EXCLUDED.agent_version,
            last_seen_at = now()
         RETURNING id",
    )
    .bind(org_id)
    .bind(&req.device_id)
    .bind(&req.system_name)
    .bind(&req.hostname)
    .bind(&req.os_version)
    .bind(&req.agent_version)
    .fetch_one(&state.db)
    .await
    {
        Ok(pk) => pk,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let token = auth::generate_token();
    if let Err(e) = sqlx::query(
        "INSERT INTO device_tokens (org_id, device_pk, token_hash) VALUES ($1,$2,$3)",
    )
    .bind(org_id)
    .bind(device_pk)
    .bind(auth::sha256_hex(&token))
    .execute(&state.db)
    .await
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
    }

    // Ensure the org has a screenshot key and hand it to the agent (over TLS) so it can
    // re-encrypt screenshots under it before upload.
    let screenshot_key = match ensure_org_screenshot_key(&state, org_id).await {
        Ok(k) => k,
        Err(r) => return r,
    };

    // Token + screenshot key are returned exactly once; the server keeps only the token hash.
    Json(json!({ "device_id": req.device_id, "token": token, "screenshot_key": screenshot_key })).into_response()
}

/// Return the org's screenshot key, generating + storing one if it doesn't have it yet.
async fn ensure_org_screenshot_key(state: &AppState, org_id: i64) -> Result<String, Response> {
    let existing: Option<Option<String>> =
        sqlx::query_scalar("SELECT screenshot_key FROM orgs WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if let Some(Some(k)) = existing {
        if !k.is_empty() {
            return Ok(k);
        }
    }
    // Generate a 32-byte key (hex) and store it.
    let key = auth::generate_token(); // 32 random bytes, hex = 64 chars
    sqlx::query("UPDATE orgs SET screenshot_key = $1 WHERE id = $2")
        .bind(&key)
        .bind(org_id)
        .execute(&state.db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(key)
}

async fn org_screenshot_key(state: &AppState, org_id: i64) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT screenshot_key FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .flatten()
}

/// License + seat usage for the org's dashboard.
pub async fn admin_license(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org_id) = admin_org(&state, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let lic = sqlx::query_as::<_, (String, i32, String, Option<String>)>(
        "SELECT plan, seats, status, trial_ends::text FROM licenses WHERE org_id = $1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let used: i64 = sqlx::query_scalar("SELECT count(*) FROM devices WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    match lic {
        Some((plan, seats, status, trial_ends)) => Json(json!({
            "plan": plan, "seats": seats, "status": status, "trial_ends": trial_ends, "used": used
        })).into_response(),
        None => Json(json!({ "plan": "unlimited", "seats": null, "status": "active", "used": used })).into_response(),
    }
}

/// The self-serve signup page.
pub async fn signup_page() -> Response {
    axum::response::Html(include_str!("signup.html")).into_response()
}

/// OS-detecting agent download page (Windows / macOS / Linux installers).
pub async fn download_page() -> Response {
    axum::response::Html(include_str!("download.html")).into_response()
}

// ---------------------------- screenshot ingest ----------------------------

#[derive(Deserialize)]
pub struct ScreenshotMeta {
    pub screenshot_id: String,
    pub timestamp_utc: String,
    pub sha256: Option<String>,
    pub file_size: Option<i64>,
    pub monitor_id: Option<i32>,
}

/// Upload one screenshot: metadata in the query string, the org-encrypted blob as the raw body.
pub async fn ingest_screenshot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(meta): Query<ScreenshotMeta>,
    body: axum::body::Bytes,
) -> Response {
    let Some((org_id, device_pk)) = device_principal(&state, &headers).await else {
        return err(StatusCode::UNAUTHORIZED, "invalid device token");
    };
    // Idempotent: skip if we already have this screenshot for the org.
    let exists: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM screenshots WHERE org_id = $1 AND screenshot_id = $2",
    )
    .bind(org_id)
    .bind(&meta.screenshot_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    if exists.is_some() {
        return Json(json!({ "accepted": false, "duplicate": true })).into_response();
    }
    if let Err(e) = crate::blob::store(&meta.screenshot_id, &body) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("blob: {e}"));
    }
    let res = sqlx::query(
        "INSERT INTO screenshots (org_id, device_pk, screenshot_id, timestamp_utc, sha256, file_size, monitor_id, blob_url)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (org_id, screenshot_id) DO NOTHING",
    )
    .bind(org_id)
    .bind(device_pk)
    .bind(&meta.screenshot_id)
    .bind(&meta.timestamp_utc)
    .bind(&meta.sha256)
    .bind(meta.file_size)
    .bind(meta.monitor_id)
    .bind(format!("file://{}", meta.screenshot_id))
    .execute(&state.db)
    .await;
    match res {
        Ok(_) => Json(json!({ "accepted": true })).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ShotRow {
    pub screenshot_id: String,
    pub device_id: String,
    pub timestamp_utc: String,
    pub file_size: Option<i64>,
    pub monitor_id: Option<i32>,
}

pub async fn admin_screenshots(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<EventsQuery>,
) -> Response {
    let Some(org_id) = admin_org(&state, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT s.screenshot_id, d.device_id, s.timestamp_utc, s.file_size, s.monitor_id
         FROM screenshots s JOIN devices d ON d.id = s.device_pk WHERE s.org_id = ",
    );
    qb.push_bind(org_id);
    if let Some(dev) = &q.device {
        qb.push(" AND d.device_id = ").push_bind(dev.clone());
    }
    if let Some(f) = &q.from {
        qb.push(" AND s.timestamp_utc >= ").push_bind(f.clone());
    }
    if let Some(t) = &q.to {
        qb.push(" AND s.timestamp_utc < ").push_bind(t.clone());
    }
    qb.push(" ORDER BY s.timestamp_utc DESC LIMIT 300");
    match qb.build_query_as::<ShotRow>().fetch_all(&state.db).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// Decrypt + serve one screenshot PNG for the org's admin.
pub async fn admin_screenshot_image(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(org_id) = admin_org(&state, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    // Confirm the screenshot belongs to this org.
    let owned: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM screenshots WHERE org_id = $1 AND screenshot_id = $2",
    )
    .bind(org_id)
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    if owned.is_none() {
        return err(StatusCode::NOT_FOUND, "not found");
    }
    let Some(key) = org_screenshot_key(&state, org_id).await else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "no org key");
    };
    let blob = match crate::blob::load(&id) {
        Ok(b) => b,
        Err(_) => return err(StatusCode::NOT_FOUND, "blob missing"),
    };
    match crate::blob::decrypt(&key, &blob) {
        Some(png) => ([(header::CONTENT_TYPE, "image/png")], png).into_response(),
        None => err(StatusCode::INTERNAL_SERVER_ERROR, "decrypt failed"),
    }
}

// ------------------------------- event ingest ------------------------------

#[derive(Deserialize)]
pub struct WireEvent {
    pub event_id: String,
    pub event_type: String,
    pub timestamp_utc: String,
    pub application_name: Option<String>,
    pub window_title: Option<String>,
    pub metadata_json: Option<String>,
    pub event_hash: Option<String>,
    pub previous_event_hash: Option<String>,
}

/// Idempotent batch upload of events for the authenticated device. Duplicates (same
/// org + event_id) are silently skipped, so retries are safe.
pub async fn ingest_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(events): Json<Vec<WireEvent>>,
) -> Response {
    let Some((org_id, device_pk)) = device_principal(&state, &headers).await else {
        return err(StatusCode::UNAUTHORIZED, "invalid device token");
    };
    let mut accepted = 0u64;
    for e in &events {
        let res = sqlx::query(
            "INSERT INTO events (org_id, device_pk, event_id, event_type, timestamp_utc,
                application_name, window_title, metadata_json, event_hash, previous_event_hash)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
             ON CONFLICT (org_id, event_id) DO NOTHING",
        )
        .bind(org_id)
        .bind(device_pk)
        .bind(&e.event_id)
        .bind(&e.event_type)
        .bind(&e.timestamp_utc)
        .bind(&e.application_name)
        .bind(&e.window_title)
        .bind(&e.metadata_json)
        .bind(&e.event_hash)
        .bind(&e.previous_event_hash)
        .execute(&state.db)
        .await;
        match res {
            Ok(r) => accepted += r.rows_affected(),
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        }
    }
    let _ = sqlx::query("UPDATE devices SET last_seen_at = now() WHERE id = $1")
        .bind(device_pk)
        .execute(&state.db)
        .await;
    Json(json!({ "received": events.len(), "accepted": accepted })).into_response()
}

// ------------------------------- admin auth --------------------------------

#[derive(Deserialize)]
pub struct LoginReq {
    pub email: String,
    pub password: String,
}

pub async fn admin_login(State(state): State<AppState>, Json(req): Json<LoginReq>) -> Response {
    let row = sqlx::query_as::<_, (i64, String)>(
        "SELECT org_id, password_hash FROM admin_users WHERE email = $1",
    )
    .bind(&req.email)
    .fetch_optional(&state.db)
    .await;
    let (org_id, phc) = match row {
        Ok(Some(v)) => v,
        Ok(None) => return err(StatusCode::UNAUTHORIZED, "invalid credentials"),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    if !auth::verify_password(&req.password, &phc) {
        return err(StatusCode::UNAUTHORIZED, "invalid credentials");
    }
    let (token, csrf) = state.sessions.issue(org_id, SESSION_TTL);
    let cookie = format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600");
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, cookie.parse().unwrap());
    (headers, Json(json!({ "ok": true, "csrf": csrf }))).into_response()
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|kv| kv.trim().strip_prefix(&format!("{SESSION_COOKIE}=")).map(|v| v.to_string()))
}

fn admin_org(state: &AppState, headers: &HeaderMap) -> Option<i64> {
    session_token(headers).and_then(|t| state.sessions.org_of(&t))
}

// ------------------------------- admin queries -----------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct DeviceRow {
    pub device_id: String,
    pub system_name: Option<String>,
    pub hostname: Option<String>,
    pub os_version: Option<String>,
    pub agent_version: Option<String>,
    pub last_seen_at: Option<String>,
}

pub async fn admin_devices(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org_id) = admin_org(&state, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    match sqlx::query_as::<_, DeviceRow>(
        "SELECT device_id, system_name, hostname, os_version, agent_version,
                last_seen_at::text AS last_seen_at
         FROM devices WHERE org_id = $1 ORDER BY last_seen_at DESC NULLS LAST",
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct EventsQuery {
    pub device: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub event_type: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct EventRow {
    pub device_id: String,
    pub event_id: String,
    pub event_type: String,
    pub timestamp_utc: String,
    pub application_name: Option<String>,
    pub window_title: Option<String>,
    pub metadata_json: Option<String>,
}

pub async fn admin_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<EventsQuery>,
) -> Response {
    let Some(org_id) = admin_org(&state, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT d.device_id, e.event_id, e.event_type, e.timestamp_utc, e.application_name,
                e.window_title, e.metadata_json
         FROM events e JOIN devices d ON d.id = e.device_pk
         WHERE e.org_id = ",
    );
    qb.push_bind(org_id);
    if let Some(dev) = &q.device {
        qb.push(" AND d.device_id = ").push_bind(dev.clone());
    }
    if let Some(f) = &q.from {
        qb.push(" AND e.timestamp_utc >= ").push_bind(f.clone());
    }
    if let Some(t) = &q.to {
        qb.push(" AND e.timestamp_utc < ").push_bind(t.clone());
    }
    if let Some(ty) = &q.event_type {
        qb.push(" AND e.event_type = ").push_bind(ty.clone());
    }
    qb.push(" ORDER BY e.timestamp_utc DESC LIMIT 1000");
    match qb.build_query_as::<EventRow>().fetch_all(&state.db).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}
