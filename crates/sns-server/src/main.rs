//! `sns-server` — the central, multi-tenant org server (Phase D).
//!
//! Each business is an `org`; its boss (admin) signs in and sees only that org's devices.
//! Agents enroll with an org enroll token, receive a per-device bearer token, and upload their
//! already-encrypted, integrity-chained events idempotently (ULID-keyed).
//!
//! Usage:
//!   DATABASE_URL=postgres://user:pass@host/db  sns-server serve
//!   DATABASE_URL=...  sns-server provision-org --name "Acme" --admin-email boss@acme.com --admin-password '...'
//!
//! TLS is terminated by a reverse proxy (or add rustls); bind defaults to 0.0.0.0:8080.

mod auth;
mod blob;
mod handlers;
mod state;

use axum::routing::{get, post};
use axum::Router;
use sqlx::postgres::PgPoolOptions;

use state::AppState;

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("SNS_LOG").unwrap_or_else(|_| "info".into()))
        .try_init()
        .ok();

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("DATABASE_URL is required (postgres://…)"))?;
    let db = PgPoolOptions::new().max_connections(10).connect(&database_url).await?;
    sqlx::migrate!("./migrations").run(&db).await?;

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("provision-org") => provision_org(&db, &args).await,
        Some("serve") | None => serve(db).await,
        Some(other) => {
            eprintln!("unknown command: {other}\n  commands: serve | provision-org");
            std::process::exit(2);
        }
    }
}

async fn serve(db: sqlx::PgPool) -> anyhow::Result<()> {
    let state = AppState { db, sessions: auth::Sessions::default() };
    let app = Router::new()
        .route("/", get(handlers::dashboard))
        .route("/signup", get(handlers::signup_page))
        .route("/api/v1/healthz", get(handlers::healthz))
        .route("/api/v1/agent/version", get(handlers::agent_version))
        .route("/api/v1/signup", post(handlers::signup))
        .route("/api/v1/admin/license", get(handlers::admin_license))
        .route("/api/v1/devices/register", post(handlers::register))
        .route("/api/v1/ingest/events", post(handlers::ingest_events))
        .route("/api/v1/ingest/screenshot", post(handlers::ingest_screenshot))
        .route("/api/v1/admin/login", post(handlers::admin_login))
        .route("/api/v1/admin/devices", get(handlers::admin_devices))
        .route("/api/v1/admin/events", get(handlers::admin_events))
        .route("/api/v1/admin/screenshots", get(handlers::admin_screenshots))
        .route("/api/v1/admin/screenshots/:id/image", get(handlers::admin_screenshot_image))
        // Screenshots can be a few MB; allow up to 16 MB request bodies.
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024))
        .with_state(state);

    let bind = env("SNS_SERVER_BIND", "0.0.0.0:8080");
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "sns-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Create a new org (business) with an admin user, and print the one-time enroll token that
/// its devices use to register. Simple flag parser: --name, --admin-email, --admin-password.
async fn provision_org(db: &sqlx::PgPool, args: &[String]) -> anyhow::Result<()> {
    let mut name = None;
    let mut email = None;
    let mut password = None;
    let mut i = 2;
    while i + 1 < args.len() {
        match args[i].as_str() {
            "--name" => name = Some(args[i + 1].clone()),
            "--admin-email" => email = Some(args[i + 1].clone()),
            "--admin-password" => password = Some(args[i + 1].clone()),
            _ => {}
        }
        i += 2;
    }
    let name = name.ok_or_else(|| anyhow::anyhow!("--name required"))?;
    let email = email.ok_or_else(|| anyhow::anyhow!("--admin-email required"))?;
    let password = password.ok_or_else(|| anyhow::anyhow!("--admin-password required"))?;

    let enroll_token = auth::generate_token();
    let org_id: i64 = sqlx::query_scalar(
        "INSERT INTO orgs (name, enroll_token_hash) VALUES ($1,$2) RETURNING id",
    )
    .bind(&name)
    .bind(auth::sha256_hex(&enroll_token))
    .fetch_one(db)
    .await?;

    let phc = auth::hash_password(&password)?;
    sqlx::query("INSERT INTO admin_users (org_id, email, password_hash, role) VALUES ($1,$2,$3,'admin')")
        .bind(org_id)
        .bind(&email)
        .bind(&phc)
        .execute(db)
        .await?;

    println!("Provisioned org '{name}' (id {org_id}).");
    println!("Admin login: {email}");
    println!("Device enroll token (store securely, shown once):\n  {enroll_token}");
    Ok(())
}
