//! HTTP handlers. Every data path is org-scoped: device endpoints act only within the token's
//! org; admin endpoints act only within the session's org.

use std::time::Duration;

use axum::extract::{Query, State};
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

    // Token is returned exactly once; the server keeps only its hash.
    Json(json!({ "device_id": req.device_id, "token": token })).into_response()
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
