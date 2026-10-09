//! Admission is completed before accepting a WebSocket or allocating MPC state.
use anyhow::{Result, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Capability {
    /// SHA-256 of an independently generated 256-bit bearer token.
    token_hash: String,
    expires: u64,
    max_sessions: usize,
    starts_per_minute: usize,
}
struct Tenant {
    expires: u64,
    slots: Arc<Semaphore>,
    starts: Mutex<(Instant, usize)>,
    limit: usize,
}
pub(super) struct Admission {
    tenants: HashMap<String, Tenant>,
}
impl Admission {
    pub fn from_env() -> Result<Self> {
        let json = std::env::var("ZKF_CAPABILITIES").unwrap_or_else(|_| "[]".into());
        Self::parse(&json)
    }
    fn parse(json: &str) -> Result<Self> {
        let capabilities: Vec<Capability> = serde_json::from_str(json)?;
        ensure!(
            capabilities.len() <= 4096,
            "too many admission capabilities"
        );
        let mut tenants = HashMap::new();
        for cap in capabilities {
            ensure!(
                cap.token_hash.len() == 64 && hex::decode(&cap.token_hash)?.len() == 32,
                "invalid capability hash"
            );
            ensure!(
                (1..=128).contains(&cap.max_sessions)
                    && (1..=10000).contains(&cap.starts_per_minute),
                "invalid tenant quota"
            );
            ensure!(
                tenants
                    .insert(
                        cap.token_hash.to_ascii_lowercase(),
                        Tenant {
                            expires: cap.expires,
                            slots: Arc::new(Semaphore::new(cap.max_sessions)),
                            starts: Mutex::new((Instant::now(), 0)),
                            limit: cap.starts_per_minute,
                        }
                    )
                    .is_none(),
                "duplicate capability"
            );
        }
        Ok(Self { tenants })
    }
    pub fn is_empty(&self) -> bool {
        self.tenants.is_empty()
    }
    pub fn admit(&self, head: &str) -> std::result::Result<OwnedSemaphorePermit, &'static str> {
        let target = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or("401 Unauthorized")?;
        let url = url::Url::parse(&format!("https://notary.invalid{target}"))
            .map_err(|_| "401 Unauthorized")?;
        let tokens: Vec<_> = url
            .query_pairs()
            .filter(|(k, _)| k == "capability")
            .collect();
        if tokens.len() != 1
            || tokens[0].1.len() != 64
            || hex::decode(tokens[0].1.as_ref()).is_err()
        {
            return Err("401 Unauthorized");
        }
        let hash = hex::encode(Sha256::digest(tokens[0].1.as_bytes()));
        let tenant = self.tenants.get(&hash).ok_or("401 Unauthorized")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "401 Unauthorized")?
            .as_secs();
        if now >= tenant.expires {
            return Err("401 Unauthorized");
        }
        let mut starts = tenant
            .starts
            .lock()
            .map_err(|_| "503 Service Unavailable")?;
        if starts.0.elapsed().as_secs() >= 60 {
            *starts = (Instant::now(), 0);
        }
        if starts.1 >= tenant.limit {
            return Err("429 Too Many Requests");
        }
        starts.1 += 1;
        tenant
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| "429 Too Many Requests")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capabilities_expiry_concurrency_and_rate_are_enforced() {
        let token = "ab".repeat(32);
        let hash = hex::encode(Sha256::digest(token.as_bytes()));
        let admission = Admission::parse(&format!(
            r#"[{{"tokenHash":"{hash}","expires":9999999999,"maxSessions":1,"startsPerMinute":2}}]"#
        ))
        .unwrap();
        let request = format!("GET /notarize?capability={token} HTTP/1.1\r\n");
        assert!(admission.admit("GET /notarize HTTP/1.1").is_err());
        let slot = admission.admit(&request).unwrap();
        assert!(admission.admit(&request).is_err());
        drop(slot);
        assert!(admission.admit(&request).is_err()); // reconnect attempt consumed quota
        let expired = Admission::parse(&format!(
            r#"[{{"tokenHash":"{hash}","expires":1,"maxSessions":1,"startsPerMinute":2}}]"#
        ))
        .unwrap();
        assert!(expired.admit(&request).is_err());
    }
}
