//! Windows Service host (spec §2, §3, §6, §28). Registers with the SCM, maps control
//! requests to the agent's graceful shutdown, and reports status transitions. Compiled
//! only on Windows.

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, SessionChangeReason, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

use crate::agent::{Agent, Paths, SessionSignal};
use sns_core::collectors::system::ShutdownReason;

pub const SERVICE_NAME: &str = "SNSSecurityAgent";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Called by SCM. Any error here is logged; we never panic across the FFI boundary.
pub fn run() -> anyhow::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        // Cannot surface a UI (spec §34); rely on the log + SCM error reporting.
        tracing::error!(error = %e, "service_main failed");
    }
}

fn run_service() -> anyhow::Result<()> {
    let root = std::env::var_os("SNS_DATA_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(sns_core::DEFAULT_DATA_ROOT));
    crate::init_logging(&root);

    let shutdown = Arc::new(AtomicBool::new(false));
    // Reason is set by the control handler so AGENT_SHUTDOWN records why (spec §7).
    let reason = Arc::new(std::sync::Mutex::new(ShutdownReason::ServiceStop));

    // Inbox shared with the agent: the handler pushes logon/logoff signals, the agent loop
    // drains them into USER_SESSION_STARTED/ENDED events (spec §5, §15).
    let session_inbox: Arc<Mutex<Vec<SessionSignal>>> = Arc::new(Mutex::new(Vec::new()));

    let handler_shutdown = shutdown.clone();
    let handler_reason = reason.clone();
    let handler_inbox = session_inbox.clone();
    let event_handler = move |control: ServiceControl| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                *handler_reason.lock().unwrap() = ShutdownReason::ServiceStop;
                handler_shutdown.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            // We accept PRESHUTDOWN (mutually exclusive with SHUTDOWN) for extra time, but
            // still classify a plain SHUTDOWN if it arrives.
            ServiceControl::Shutdown => {
                *handler_reason.lock().unwrap() = ShutdownReason::WindowsShutdown;
                handler_shutdown.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Preshutdown => {
                *handler_reason.lock().unwrap() = ShutdownReason::Preshutdown;
                handler_shutdown.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::SessionChange(param) => {
                let sid = param.notification.session_id;
                let signal = match param.reason {
                    SessionChangeReason::SessionLogon
                    | SessionChangeReason::ConsoleConnect
                    | SessionChangeReason::RemoteConnect
                    | SessionChangeReason::SessionCreate => Some(SessionSignal::Started { session_id: sid }),
                    SessionChangeReason::SessionLogoff
                    | SessionChangeReason::ConsoleDisconnect
                    | SessionChangeReason::RemoteDisconnect
                    | SessionChangeReason::SessionTerminate => Some(SessionSignal::Ended { session_id: sid }),
                    _ => None, // lock/unlock/remote-control: not recorded as start/end
                };
                if let Some(s) = signal {
                    handler_inbox.lock().unwrap().push(s);
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    let set_state = |state: ServiceState, accept: ServiceControlAccept, wait: Duration| {
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: wait,
            process_id: None,
        })
    };

    set_state(ServiceState::StartPending, ServiceControlAccept::empty(), Duration::from_secs(30))?;

    let paths = Paths::from_root(root);
    let rt = tokio::runtime::Runtime::new()?;
    let boot = rt.block_on(async { Agent::boot(&paths, shutdown.clone()) });
    let mut agent = match boot {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "agent boot failed");
            set_state(ServiceState::Stopped, ServiceControlAccept::empty(), Duration::default())?;
            return Err(e);
        }
    };

    // Share the session inbox so logon/logoff signals reach the agent loop (spec §5, §15).
    agent.attach_session_inbox(session_inbox.clone());

    // PRESHUTDOWN and SHUTDOWN are mutually exclusive; accept PRESHUTDOWN for extra time.
    let accepted = ServiceControlAccept::STOP
        | ServiceControlAccept::PRESHUTDOWN
        | ServiceControlAccept::SESSION_CHANGE;
    set_state(ServiceState::Running, accepted, Duration::default())?;

    rt.block_on(agent.run())?;

    set_state(ServiceState::StopPending, ServiceControlAccept::empty(), Duration::from_secs(30))?;
    let final_reason = *reason.lock().unwrap();
    agent.shutdown(final_reason);
    set_state(ServiceState::Stopped, ServiceControlAccept::empty(), Duration::default())?;
    Ok(())
}
