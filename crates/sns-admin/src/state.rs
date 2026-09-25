//! Shared server state: session store + login rate limiter (spec §31, §40).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sns_core::config::AgentConfig;

#[derive(Clone)]
pub struct AppState {
    pub data_root: PathBuf,
    pub password_hash: Arc<String>,
    pub device_id: Arc<String>,
    pub ttl: Duration,
    sessions: Arc<Mutex<HashMap<String, Instant>>>, // token -> expiry
    login_gate: Arc<Mutex<LoginGate>>,
    /// Per-process CSRF secret issued at login and required on mutations.
    pub csrf: Arc<Mutex<HashMap<String, String>>>, // token -> csrf
}

struct LoginGate {
    window_start: Instant,
    count: u32,
}

impl AppState {
    pub fn new(data_root: PathBuf, cfg: &AgentConfig) -> Self {
        Self {
            data_root,
            password_hash: Arc::new(cfg.admin.password_hash.clone()),
            device_id: Arc::new(cfg.device_id.clone()),
            ttl: Duration::from_secs(cfg.admin.session_ttl_seconds),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            login_gate: Arc::new(Mutex::new(LoginGate {
                window_start: Instant::now(),
                count: 0,
            })),
            csrf: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Rate-limit login attempts: max 5 per rolling 60s window (spec §31 "rate limiting").
    pub fn login_allowed(&self) -> bool {
        let mut g = self.login_gate.lock().unwrap();
        if g.window_start.elapsed() > Duration::from_secs(60) {
            g.window_start = Instant::now();
            g.count = 0;
        }
        g.count += 1;
        g.count <= 5
    }

    pub fn issue_session(&self, token: &str, csrf: &str) {
        let expiry = Instant::now() + self.ttl;
        self.sessions.lock().unwrap().insert(token.to_string(), expiry);
        self.csrf.lock().unwrap().insert(token.to_string(), csrf.to_string());
    }

    pub fn valid_session(&self, token: &str) -> bool {
        let mut s = self.sessions.lock().unwrap();
        match s.get(token) {
            Some(exp) if *exp > Instant::now() => true,
            Some(_) => {
                s.remove(token); // expired
                false
            }
            None => false,
        }
    }

    pub fn csrf_matches(&self, token: &str, submitted: &str) -> bool {
        self.csrf
            .lock()
            .unwrap()
            .get(token)
            .map(|c| c == submitted)
            .unwrap_or(false)
    }

    pub fn revoke(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
        self.csrf.lock().unwrap().remove(token);
    }
}
