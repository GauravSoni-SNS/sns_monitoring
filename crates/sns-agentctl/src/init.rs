//! `sns-agentctl init` — first-install initialization (spec §38 steps 4–6, 9).
//! Generates the immutable device_id, DPAPI-wraps a fresh DEK, writes agent.json +
//! default policy.json, and creates + migrates activity.db. Idempotent-guarded: refuses
//! to clobber an existing install.

use std::path::{Path, PathBuf};

use sns_core::config::{AdminConfig, AgentConfig, LoggingConfig, Policy};
use sns_core::identity::Identity;
use sns_core::security::password::hash_password;
use sns_core::security::KeyManager;
use sns_core::storage::Storage;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct InitArgs {
    pub system_name: String,
    pub admin_password: String,
    pub data_root: PathBuf,
}

pub fn run(args: InitArgs) -> anyhow::Result<()> {
    let root = &args.data_root;
    let agent_json = root.join("config").join("agent.json");
    if agent_json.exists() {
        anyhow::bail!("already initialized: {} exists", agent_json.display());
    }
    for d in ["config", "database", "keys", "runtime", "logs"] {
        std::fs::create_dir_all(root.join(d))?;
    }

    // Identity: immutable device_id + admin-set system name (spec §9, §10).
    let identity = Identity::create(&args.system_name)?;

    // Key protection: generate + wrap DEK (spec §21, §38.6).
    let _km = KeyManager::initialize(root.join("keys").join("keyring.json"))?;

    // agent.json (admin password stored only as Argon2id hash; spec §31).
    let cfg = AgentConfig {
        schema_version: 1,
        device_id: identity.device_id.clone(),
        system_name: identity.system_name.clone(),
        agent_version: AGENT_VERSION.to_string(),
        admin: AdminConfig {
            bind: "127.0.0.1".into(),
            port: 7731,
            password_hash: hash_password(&args.admin_password)?,
            session_ttl_seconds: 1800,
        },
        logging: LoggingConfig { level: "info".into(), max_file_mb: 20, max_files: 10 },
    };
    cfg.validate()?;
    write_json(&agent_json, &cfg)?;

    // policy.json defaults (spec §19, §25).
    let policy = Policy::default_policy();
    write_json(&root.join("config").join("policy.json"), &policy)?;

    // DB create + migrate; record install in audit_log (spec §38.4).
    let storage = Storage::open(
        root.join("database").join("activity.db"),
        &identity.device_id,
        &policy.durability.sqlite_synchronous,
    )?;
    storage.upsert_device(
        &identity.system_name,
        sns_core::identity::hostname().as_deref(),
        None,
        AGENT_VERSION,
    )?;
    storage.audit("INSTALL", Some("installer"), None)?;

    println!("Initialized device {} ({})", identity.system_name, identity.device_id);
    Ok(())
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
