//! Library surface of the service host so its lifecycle can be integration-tested
//! (graceful shutdown, crash recovery) without the SCM. The production binary (`main.rs`)
//! and the SCM host (`service_win`) use these same modules.

pub mod agent;

#[cfg(windows)]
pub mod service_win;

/// Shared with the binary so both resolve the data root identically.
pub fn init_logging(root: &std::path::Path) {
    let logs = root.join("logs");
    let _ = std::fs::create_dir_all(&logs);
    // IST-dated log filename (suffix in India Standard Time).
    let (y, m, d) = sns_core::clock::ymd_utc();
    let file = tracing_appender::rolling::never(&logs, format!("agent-{y:04}-{m:02}-{d:02}.log"));
    let _ = tracing_subscriber::fmt()
        .with_writer(file)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SNS_LOG").unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}
