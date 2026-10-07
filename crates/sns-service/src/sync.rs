//! Central-server sync (Phase D.2). Registers the device once, then uploads un-synced events
//! in batches over HTTPS. Idempotent on the server (ULID), so retries are safe; only events
//! the server accepts are marked SYNCED locally.
//!
//! NOTE: this is the agent's only outbound network path, and it is active only when
//! `policy.sync.enabled` and a `server_url` are configured. It sends the already-encrypted,
//! hash-chained event metadata — screenshot blobs are a later step (D.2b).

use std::time::Duration;

use sns_core::config::SyncPolicy;
use sns_core::storage::db::SyncEvent;
use sns_core::storage::Storage;

const BATCH: u32 = 500;
const TIMEOUT: Duration = Duration::from_secs(20);

/// Outcome of a sync cycle, for logging.
#[derive(Debug, Default)]
pub struct SyncOutcome {
    pub uploaded: usize,
    pub registered: bool,
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(TIMEOUT).build()
}

/// Register this device with the server using the enroll token; returns the device token.
fn register(sync: &SyncPolicy, device_id: &str, system_name: &str, agent_version: &str) -> anyhow::Result<String> {
    let url = format!("{}/api/v1/devices/register", sync.server_url.trim_end_matches('/'));
    let resp = agent()
        .post(&url)
        .send_json(ureq::json!({
            "enroll_token": sync.enroll_token,
            "device_id": device_id,
            "system_name": system_name,
            "agent_version": agent_version,
        }))?;
    let v: serde_json::Value = resp.into_json()?;
    v.get("token")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("register: no token in response"))
}

/// Push a batch of events; returns Ok(()) on a 2xx. The server dedups by ULID.
fn push_events(sync: &SyncPolicy, token: &str, events: &[SyncEvent]) -> anyhow::Result<()> {
    let url = format!("{}/api/v1/ingest/events", sync.server_url.trim_end_matches('/'));
    agent()
        .post(&url)
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(serde_json::to_value(events)?)?;
    Ok(())
}

/// Run one sync cycle. If no device token is set yet, registers first (and returns the token
/// via `new_token` so the caller can persist it to config). Uploads up to a few batches.
pub fn run_once(
    sync: &SyncPolicy,
    storage: &Storage,
    device_id: &str,
    system_name: &str,
    agent_version: &str,
    new_token: &mut Option<String>,
) -> anyhow::Result<SyncOutcome> {
    let mut outcome = SyncOutcome::default();
    if !sync.enabled || sync.server_url.is_empty() {
        return Ok(outcome);
    }

    // Obtain a device token: use the configured one, or register now.
    let token = if !sync.device_token.is_empty() {
        sync.device_token.clone()
    } else if !sync.enroll_token.is_empty() {
        let t = register(sync, device_id, system_name, agent_version)?;
        outcome.registered = true;
        *new_token = Some(t.clone());
        t
    } else {
        return Err(anyhow::anyhow!("sync: no device_token and no enroll_token"));
    };

    // Upload in batches until the queue is drained or a batch comes back empty.
    loop {
        let batch = storage.unsynced_events(BATCH)?;
        if batch.is_empty() {
            break;
        }
        push_events(sync, &token, &batch)?;
        let ids: Vec<String> = batch.iter().map(|e| e.event_id.clone()).collect();
        storage.mark_events_synced(&ids)?;
        outcome.uploaded += ids.len();
        if (batch.len() as u32) < BATCH {
            break;
        }
    }
    Ok(outcome)
}
