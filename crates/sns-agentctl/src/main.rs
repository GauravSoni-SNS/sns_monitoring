//! `sns-agentctl` — diagnostic CLI (spec §22, §29). A **read-only client**: it inspects
//! local state, it does NOT run the collectors (that is the service's job). Closing this
//! terminal has no effect on the running service (spec §4, §29).
//!
//! Commands: `status` · `health` · `verify-integrity` · `diagnostics`.

mod init;

use std::path::PathBuf;

use sns_core::config::AgentConfig;
use sns_core::storage::Storage;

fn data_root() -> PathBuf {
    std::env::var_os("SNS_DATA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(sns_core::DEFAULT_DATA_ROOT))
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "help".into());
    let code = match cmd.as_str() {
        "init" => cmd_init(),
        "set-password" => cmd_set_password(),
        "verify-integrity" => cmd_verify_integrity(),
        "status" => cmd_status(),
        "health" => cmd_health(),
        "diagnostics" => cmd_diagnostics(),
        "probe-url" => cmd_probe_url(),
        "usb-list" => cmd_usb_list(),
        "enroll" => cmd_enroll(),
        "apps" => cmd_apps(),
        "help" | "--help" | "-h" => {
            print_help();
            0
        }
        other => {
            eprintln!("unknown command: {other}");
            print_help();
            2
        }
    };
    std::process::exit(code);
}

fn print_help() {
    println!(
        "sns-agentctl <command>\n\
         \n  init               First-install: device_id, keys, config, db\
         \n  set-password       Reset the admin-panel password (elevated)\
         \n  status             Service + device summary\
         \n  health             Health snapshot (spec §26)\
         \n  verify-integrity   Recompute the event hash chain (spec §22)\
         \n  diagnostics        Paths, config validity, db reachability\
         \n  probe-url          Read the FOREGROUND browser's address bar once (verify UIA)\
         \n  usb-list           List all USB devices currently connected (name, VID/PID/serial)\
         \n  enroll             Configure central-server sync: --server <url> --token <enroll>\
         \n\nRead-only. Does not run collectors; the Windows Service does that."
    );
}

fn open_storage() -> anyhow::Result<(AgentConfig, Storage)> {
    let root = data_root();
    let cfg = AgentConfig::load(root.join("config").join("agent.json"))?;
    // Light inspection open: no migrate / WAL-pragma, avoids contending with the service.
    let storage = Storage::open_reader(root.join("database").join("activity.db"), &cfg.device_id)?;
    Ok((cfg, storage))
}

/// Simple `--flag value` extractor (no external arg-parser dependency).
fn flag(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

/// Reset the admin-panel password (spec §31). Rewrites the Argon2id hash in agent.json.
/// Must run elevated (config is Admins-writable). New password via --password or the
/// SNS_ADMIN_PASSWORD env var (preferred — keeps it out of the command line).
fn cmd_set_password() -> i32 {
    let pw = flag("--password")
        .or_else(|| std::env::var("SNS_ADMIN_PASSWORD").ok())
        .unwrap_or_default();
    if pw.is_empty() {
        eprintln!("set-password requires --password <pw> or SNS_ADMIN_PASSWORD env var");
        return 2;
    }
    let path = data_root().join("config").join("agent.json");
    let mut cfg = match AgentConfig::load(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("load agent.json failed (run elevated?): {e}");
            return 2;
        }
    };
    match sns_core::security::password::hash_password(&pw) {
        Ok(h) => cfg.admin.password_hash = h,
        Err(e) => {
            eprintln!("hash error: {e}");
            return 2;
        }
    }
    match serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string()).and_then(|b| std::fs::write(&path, b).map_err(|e| e.to_string())) {
        Ok(()) => {
            println!("Admin password updated. Sign in again; restart sns-admin if it is running.");
            0
        }
        Err(e) => {
            eprintln!("write agent.json failed (run elevated?): {e}");
            2
        }
    }
}

fn cmd_init() -> i32 {
    let system_name = match flag("--system-name") {
        Some(s) => s,
        None => {
            eprintln!("init requires --system-name <name>");
            return 2;
        }
    };
    // Password may come from a flag or, preferably, an env var so it is not in the
    // process command line. Never echoed or logged.
    let admin_password = flag("--admin-password")
        .or_else(|| std::env::var("SNS_ADMIN_PASSWORD").ok())
        .unwrap_or_default();
    if admin_password.is_empty() {
        eprintln!("init requires --admin-password <pw> or SNS_ADMIN_PASSWORD env var");
        return 2;
    }
    let data_root = flag("--data-root").map(PathBuf::from).unwrap_or_else(data_root);

    match init::run(init::InitArgs { system_name, admin_password, data_root }) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("init error: {e}");
            2
        }
    }
}

fn cmd_verify_integrity() -> i32 {
    match open_storage().and_then(|(_, s)| Ok(s.verify_integrity()?)) {
        Ok(report) => {
            println!("Events checked: {}", report.events_checked);
            println!("Invalid records: {}", report.invalid_records);
            println!("Integrity: {}", if report.is_pass() { "PASS" } else { "FAIL" });
            if !report.first_breaks.is_empty() {
                println!("First breaks: {}", report.first_breaks.join(", "));
            }
            if report.is_pass() { 0 } else { 1 }
        }
        Err(e) => {
            eprintln!("verify-integrity error: {e}");
            2
        }
    }
}

fn cmd_status() -> i32 {
    match open_storage() {
        Ok((cfg, s)) => {
            println!("System Name: {}", cfg.system_name);
            println!("Device ID:   {}", cfg.device_id);
            println!("Agent:       {}", cfg.agent_version);
            println!("DB integrity_check: {}", if s.integrity_check().unwrap_or(false) { "ok" } else { "FAILED" });
            println!("Activity events: {}", s.activity_count().unwrap_or(-1));
            println!("Screenshots:     {}", s.screenshot_count().unwrap_or(-1));
            if let Ok(Some(ts)) = s.last_screenshot_time() {
                println!("Last screenshot: {ts}");
            }
            0
        }
        Err(e) => {
            eprintln!("status error: {e}");
            2
        }
    }
}

fn cmd_health() -> i32 {
    // Health snapshot is published by the running service under runtime/health.json.
    let path = data_root().join("runtime").join("health.json");
    match std::fs::read_to_string(&path) {
        Ok(json) => {
            println!("{json}");
            0
        }
        Err(_) => {
            eprintln!("no health snapshot at {} (is the service running?)", path.display());
            2
        }
    }
}

fn cmd_diagnostics() -> i32 {
    let root = data_root();
    println!("Data root: {}", root.display());
    for sub in ["config/agent.json", "config/policy.json", "keys/keyring.json", "database/activity.db"] {
        let p = root.join(sub);
        println!("  {:<24} {}", sub, if p.exists() { "present" } else { "MISSING" });
    }
    match AgentConfig::load(root.join("config").join("agent.json")) {
        Ok(_) => println!("agent.json: valid"),
        Err(e) => println!("agent.json: INVALID ({e})"),
    }
    0
}

/// One-shot UI Automation probe: prints the current FOREGROUND browser's address-bar value.
/// Focus a browser tab, then run this. Verifies the live-URL capture path (feature C)
/// without needing the service running. Reads only the on-screen address bar — no history,
/// stores, or credentials.
fn cmd_probe_url() -> i32 {
    match sns_core::collectors::browser::foreground_browser_url() {
        Some(url) => {
            let domain = sns_core::collectors::browser::extract_domain(&url).unwrap_or_else(|| url.clone());
            println!("foreground URL : {url}");
            println!("domain         : {domain}");
            0
        }
        None => {
            println!("no browser address bar in the foreground (focus a Chrome/Edge/Firefox tab and retry)");
            1
        }
    }
}

/// List installed data-transfer apps detected on this machine (remote access, torrent,
/// cloud sync, messaging, file-transfer tools). Reads only program names from the registry.
fn cmd_apps() -> i32 {
    let apps = sns_core::collectors::transferapps::scan_installed();
    if apps.is_empty() {
        println!("no known data-transfer apps detected");
        return 0;
    }
    println!("{} data-transfer app(s) detected:\n", apps.len());
    for a in &apps {
        println!("  [{}] {}", a.category, a.name);
    }
    0
}

/// Configure central-server sync in policy.json: enable it, set server URL + enroll token.
/// The service registers on its next cycle and persists the device token itself.
fn cmd_enroll() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    let get = |flag: &str| -> Option<String> {
        args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
    };
    let (Some(server), Some(token)) = (get("--server"), get("--token")) else {
        eprintln!("usage: sns-agentctl enroll --server <https://host> --token <enroll-token>");
        return 2;
    };
    let path = data_root().join("config").join("policy.json");
    let mut policy = match sns_core::config::Policy::load(&path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("load policy: {e}");
            return 1;
        }
    };
    policy.sync.enabled = true;
    policy.sync.server_url = server.trim_end_matches('/').to_string();
    policy.sync.enroll_token = token;
    policy.sync.device_token = String::new(); // force a fresh registration
    match serde_json::to_vec_pretty(&policy).map_err(|e| e.to_string()).and_then(|b| std::fs::write(&path, b).map_err(|e| e.to_string())) {
        Ok(_) => {
            println!("Sync enabled → {}", policy.sync.server_url);
            println!("The service will register and begin uploading within ~1 minute.");
            0
        }
        Err(e) => {
            eprintln!("write policy: {e}");
            1
        }
    }
}

/// List every USB device currently connected (all classes), with identity. Same data the
/// admin "USB Devices" view shows. Live read; no persistence.
fn cmd_usb_list() -> i32 {
    let devices = sns_core::collectors::usb::list_usb_devices();
    if devices.is_empty() {
        println!("no USB devices detected");
        return 0;
    }
    println!("{} USB device(s) connected:\n", devices.len());
    for d in &devices {
        let name = d.description.as_deref().unwrap_or("(no name)");
        let vid = d.vendor_id.as_deref().unwrap_or("----");
        let pid = d.product_id.as_deref().unwrap_or("----");
        let serial = d.serial.as_deref().unwrap_or("-");
        println!("  {name}");
        println!("      VID={vid}  PID={pid}  serial={serial}");
        println!("      {}", d.instance_id);
    }
    0
}
