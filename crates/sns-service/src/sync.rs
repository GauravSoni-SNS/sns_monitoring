//! Central-server sync (Phase D.2). Registers the device once, then uploads un-synced events
//! in batches over HTTPS. Idempotent on the server (ULID), so retries are safe; only events
//! the server accepts are marked SYNCED locally.
//!
//! NOTE: this is the agent's only outbound network path, and it is active only when
//! `policy.sync.enabled` and a `server_url` are configured. It sends the already-encrypted,
//! hash-chained event metadata — screenshot blobs are a later step (D.2b).

use std::time::Duration;

use sns_core::config::SyncPolicy;
use sns_core::security::crypto::{self, DataKey};
use sns_core::security::KeyManager;
use sns_core::storage::db::SyncEvent;
use sns_core::storage::Storage;

const BATCH: u32 = 500;
const SHOT_BATCH: u32 = 20;
const TIMEOUT: Duration = Duration::from_secs(60);

/// Outcome of a sync cycle, for logging.
#[derive(Debug, Default)]
pub struct SyncOutcome {
    pub uploaded: usize,
    pub screenshots: usize,
    pub registered: bool,
}

/// Credentials returned by registration that the caller must persist.
#[derive(Debug, Default)]
pub struct NewCreds {
    pub token: Option<String>,
    pub screenshot_key: Option<String>,
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(TIMEOUT).build()
}

/// Register this device with the server; returns the device token + org screenshot key.
fn register(sync: &SyncPolicy, device_id: &str, system_name: &str, agent_version: &str) -> anyhow::Result<(String, String)> {
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
    let token = v.get("token").and_then(|t| t.as_str())
        .ok_or_else(|| anyhow::anyhow!("register: no token"))?.to_string();
    let key = v.get("screenshot_key").and_then(|t| t.as_str()).unwrap_or("").to_string();
    Ok((token, key))
}

/// Re-encrypt a locally-stored screenshot under the org key and upload it.
fn push_screenshot(
    sync: &SyncPolicy,
    token: &str,
    org_key: &DataKey,
    device_key: &DataKey,
    meta: &sns_shared::models::ScreenshotMeta,
) -> anyhow::Result<()> {
    // Read the device-encrypted blob, decrypt with the device key, re-encrypt under the org key.
    let on_disk = std::fs::read(&meta.file_path)?;
    let png = crypto::decrypt(device_key, &on_disk).map_err(|_| anyhow::anyhow!("local decrypt"))?;
    let org_blob = crypto::encrypt(org_key, &png).map_err(|_| anyhow::anyhow!("org encrypt"))?;
    let url = format!(
        "{}/api/v1/ingest/screenshot?screenshot_id={}&timestamp_utc={}&sha256={}&file_size={}&monitor_id={}",
        sync.server_url.trim_end_matches('/'),
        urlencode(&meta.screenshot_id),
        urlencode(&meta.timestamp_utc),
        urlencode(&meta.sha256),
        meta.file_size,
        meta.monitor_id.unwrap_or(0),
    );
    agent()
        .post(&url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("Content-Type", "application/octet-stream")
        .send_bytes(&org_blob)?;
    Ok(())
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{:02X}", b),
        })
        .collect()
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
    keys: &KeyManager,
    device_id: &str,
    system_name: &str,
    agent_version: &str,
    creds: &mut NewCreds,
) -> anyhow::Result<SyncOutcome> {
    let mut outcome = SyncOutcome::default();
    if !sync.enabled || sync.server_url.is_empty() {
        return Ok(outcome);
    }

    // Obtain device token + org screenshot key: use configured, or register now.
    let (token, screenshot_key) = if !sync.device_token.is_empty() {
        (sync.device_token.clone(), sync.screenshot_key.clone())
    } else if !sync.enroll_token.is_empty() {
        let (t, k) = register(sync, device_id, system_name, agent_version)?;
        outcome.registered = true;
        creds.token = Some(t.clone());
        creds.screenshot_key = Some(k.clone());
        (t, k)
    } else {
        return Err(anyhow::anyhow!("sync: no device_token and no enroll_token"));
    };

    // Events: upload in batches until drained.
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

    // Screenshots: re-encrypt under the org key and upload (if we have a key).
    if let Some(org_key) = org_key_from_hex(&screenshot_key) {
        loop {
            let batch = storage.unsynced_screenshots(SHOT_BATCH)?;
            if batch.is_empty() {
                break;
            }
            let mut done = Vec::new();
            for meta in &batch {
                match push_screenshot(sync, &token, &org_key, keys.data_key(), meta) {
                    Ok(_) => done.push(meta.screenshot_id.clone()),
                    Err(e) => tracing::warn!(error = %e, id = %meta.screenshot_id, "screenshot upload failed"),
                }
            }
            if done.is_empty() {
                break; // avoid a tight loop if every upload is failing
            }
            storage.mark_screenshots_synced(&done)?;
            outcome.screenshots += done.len();
            if (batch.len() as u32) < SHOT_BATCH {
                break;
            }
        }
    }

    Ok(outcome)
}

/// Build a DataKey from a 64-char hex org key; None if absent/malformed.
fn org_key_from_hex(hex_key: &str) -> Option<DataKey> {
    if hex_key.is_empty() {
        return None;
    }
    let v = hex::decode(hex_key).ok()?;
    if v.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&v);
    Some(DataKey::from_bytes(k))
}
