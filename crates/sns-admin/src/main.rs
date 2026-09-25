//! `sns-admin` — authenticated, localhost-only administration backend (spec §31–33).
//!
//! Read-only over the collected data except: login/logout, an authorized integrity run, and
//! screenshot views (which append to the audit log). It never inserts chained activity
//! events directly — a detected tamper is reported to the service via the drop box so the
//! single-writer hash chain stays consistent. Screenshots are decrypted **in memory only**
//! and never written back to disk (spec §12, §33).
//
// Handlers return `Result<_, axum::response::Response>`; Response is a large type, tripping
// clippy's result_large_err. That is an intentional handler ergonomics choice.
#![allow(clippy::result_large_err)]

mod auth;
mod handlers;
mod state;

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::routing::{get, post};
use axum::Router;

use sns_core::config::AgentConfig;
use state::AppState;

fn data_root() -> PathBuf {
    std::env::var_os("SNS_DATA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(sns_core::DEFAULT_DATA_ROOT))
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SNS_LOG").unwrap_or_else(|_| "info".into()),
        )
        .try_init()
        .ok();

    let root = data_root();
    let cfg = AgentConfig::load(root.join("config").join("agent.json"))?;
    // validate() already rejected a non-loopback bind by default (spec §31).
    let addr: SocketAddr = format!("{}:{}", cfg.admin.bind, cfg.admin.port).parse()?;
    let state = AppState::new(root, &cfg);

    let app = Router::new()
        .route("/api/login", post(handlers::login))
        .route("/api/logout", post(handlers::logout))
        .route("/api/device", get(handlers::device))
        .route("/api/health", get(handlers::health))
        .route("/api/timeline", get(handlers::timeline))
        .route("/api/browser", get(handlers::browser))
        .route("/api/system-events", get(handlers::system_events))
        .route("/api/screenshots", get(handlers::screenshots))
        .route("/api/screenshots/:id/image", get(handlers::screenshot_image))
        .route("/api/usage", get(handlers::usage))
        .route("/api/storage", get(handlers::storage))
        .route("/api/audit", get(handlers::audit))
        .route("/api/config", get(handlers::config))
        .route("/api/integrity/verify", post(handlers::integrity_verify))
        .fallback(get(handlers::static_handler))
        .with_state(state);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(%addr, "admin backend listening (loopback-only)");
        axum::serve(listener, app).await?;
        anyhow::Ok(())
    })
}
