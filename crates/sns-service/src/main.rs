//! Production entrypoint. In production this runs under the Windows Service Control
//! Manager — NEVER `cargo run` in production (spec §2, §29). A `--console` flag runs the
//! same agent in the foreground for development/diagnostics only.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use sns_core::collectors::system::ShutdownReason;
use sns_service::agent::{Agent, Paths};
use sns_service::init_logging;

fn data_root() -> std::path::PathBuf {
    std::env::var_os("SNS_DATA_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(sns_core::DEFAULT_DATA_ROOT))
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let console = args.iter().any(|a| a == "--console");

    #[cfg(windows)]
    if !console {
        // Hand off to the SCM dispatcher; blocks until the service stops.
        return sns_service::service_win::run();
    }

    // Console/dev path (and the only path on non-Windows).
    run_console()
}

/// Foreground run for development. Ctrl-C triggers the same graceful shutdown as an SCM
/// STOP so the lifecycle can be exercised without installing the service.
fn run_console() -> anyhow::Result<()> {
    init_logging(&data_root());
    let shutdown = Arc::new(AtomicBool::new(false));
    let paths = Paths::from_root(data_root());

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut agent = Agent::boot(&paths, shutdown.clone())?;

        let sig = shutdown.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            sig.store(true, std::sync::atomic::Ordering::Relaxed);
        });

        agent.run().await?;
        agent.shutdown(ShutdownReason::ServiceStop);
        anyhow::Ok(())
    })
}
