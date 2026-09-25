//! Service lifecycle integration tests (spec §6, §7, §8, §9, §28, §37). These exercise the
//! exact graceful-shutdown and crash-recovery code the SCM STOP path calls, without needing
//! elevation or the SCM itself. Screenshots are disabled so no capture happens during tests.

use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use sns_core::config::{AdminConfig, AgentConfig, LoggingConfig, Policy};
use sns_core::collectors::system::ShutdownReason;
use sns_core::security::password::hash_password;
use sns_core::security::KeyManager;
use sns_core::storage::Storage;
use sns_shared::events::EventType;
use sns_shared::ids::new_device_id;

use std::sync::Mutex;

use sns_service::agent::{Agent, Paths, SessionSignal};

/// Initialize a data root the way `sns-agentctl init` would (device id, wrapped key, config,
/// policy, db) but with screenshots disabled for a quiet, capture-free test.
fn setup(root: &Path) -> String {
    for d in ["config", "keys", "database", "runtime", "logs"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    KeyManager::initialize(root.join("keys").join("keyring.json")).unwrap();

    let device_id = new_device_id();
    let cfg = AgentConfig {
        schema_version: 1,
        device_id: device_id.clone(),
        system_name: "SNS-TEST-001".into(),
        agent_version: "1.0.0".into(),
        admin: AdminConfig {
            bind: "127.0.0.1".into(),
            port: 7731,
            password_hash: hash_password("test-admin-pw").unwrap(),
            session_ttl_seconds: 1800,
        },
        logging: LoggingConfig { level: "info".into(), max_file_mb: 20, max_files: 10 },
    };
    std::fs::write(
        root.join("config").join("agent.json"),
        serde_json::to_vec_pretty(&cfg).unwrap(),
    )
    .unwrap();

    let mut policy = Policy::default_policy();
    policy.screenshot.enabled = false; // no capture during tests
    std::fs::write(
        root.join("config").join("policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();

    device_id
}

fn count_type(root: &Path, device_id: &str, ty: EventType) -> usize {
    let s = Storage::open(root.join("database").join("activity.db"), device_id, "NORMAL").unwrap();
    s.load_activity_chain()
        .unwrap()
        .iter()
        .filter(|r| r.event.event_type == ty)
        .count()
}

#[test]
fn graceful_shutdown_writes_agent_shutdown_and_keeps_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let device_id = setup(root);
    let paths = Paths::from_root(root);

    {
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut agent = Agent::boot(&paths, shutdown).unwrap(); // writes AGENT_STARTUP
        agent.shutdown(ShutdownReason::WindowsShutdown); // writes AGENT_SHUTDOWN, checkpoints
    } // agent dropped → DEK zeroized, DB closed

    // Reopen and assert the lifecycle events + intact chain (spec §7, §8, §22).
    assert_eq!(count_type(root, &device_id, EventType::AgentStartup), 1);
    assert_eq!(count_type(root, &device_id, EventType::AgentShutdown), 1);

    let s = Storage::open(root.join("database").join("activity.db"), &device_id, "NORMAL").unwrap();
    assert!(s.integrity_check().unwrap());
    assert!(s.verify_integrity().unwrap().is_pass());
}

#[test]
fn session_signals_become_chained_session_events() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let device_id = setup(root);
    let paths = Paths::from_root(root);

    let shutdown = Arc::new(AtomicBool::new(false));
    let mut agent = Agent::boot(&paths, shutdown).unwrap();

    // Simulate the SCM control handler pushing a logon then a logoff (spec §5, §15).
    let inbox = Arc::new(Mutex::new(vec![
        SessionSignal::Started { session_id: 2 },
        SessionSignal::Ended { session_id: 2 },
    ]));
    agent.attach_session_inbox(inbox);
    agent.drain_session_signals();
    agent.shutdown(ShutdownReason::ServiceStop);
    drop(agent);

    assert_eq!(count_type(root, &device_id, EventType::UserSessionStarted), 1);
    assert_eq!(count_type(root, &device_id, EventType::UserSessionEnded), 1);

    // Chain still valid after inserting session events.
    let s = Storage::open(root.join("database").join("activity.db"), &device_id, "NORMAL").unwrap();
    assert!(s.verify_integrity().unwrap().is_pass());
}

#[test]
fn crash_without_shutdown_recovers_and_chain_stays_valid() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let device_id = setup(root);
    let paths = Paths::from_root(root);

    // First run: boot then *drop without shutdown* — simulates a crash / power loss (spec §9).
    {
        let shutdown = Arc::new(AtomicBool::new(false));
        let _agent = Agent::boot(&paths, shutdown).unwrap();
        // no shutdown() call
    }

    // Recovery run: boot again. WAL recovers, integrity holds, a second AGENT_STARTUP lands,
    // and there is no AGENT_SHUTDOWN in between (an inferred ungraceful stop).
    {
        let shutdown = Arc::new(AtomicBool::new(false));
        let _agent = Agent::boot(&paths, shutdown).unwrap();
    }

    assert!(count_type(root, &device_id, EventType::AgentStartup) >= 2);
    assert_eq!(count_type(root, &device_id, EventType::AgentShutdown), 0);

    let s = Storage::open(root.join("database").join("activity.db"), &device_id, "NORMAL").unwrap();
    assert!(s.integrity_check().unwrap());
    assert!(s.verify_integrity().unwrap().is_pass());
}
