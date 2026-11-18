//! Optional, short-lived evidence of authenticated peer traffic.
use crate::Id;
use serde::{Deserialize, Deserializer, Serialize};

/// Maximum observations a single node can submit.
pub const MAX_PEERS: usize = 128;
/// Maximum JSON report size shared with the Go controller.
pub const MAX_REPORT_BYTES: usize = 32768;
/// Observations and reports expire after two minutes.
pub const TTL_SECONDS: i64 = 120;

/// Carrier on which the node observed actual peer traffic.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Path {
    /// Direct authenticated peer connection.
    Direct,
    /// Authenticated relay path, including its TLS/TCP fallback.
    Relay,
}

/// Privacy-bounded recent contact with an overlay peer.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    /// Canonical overlay node ID, not a network address.
    pub peer_id: String,
    /// Carrier associated with the named peer.
    pub path: Path,
    /// Include RTT only when measured to this peer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    /// Wall clock time of the observation, in Unix seconds.
    pub last_contact_unix_seconds: i64,
}

impl Peer {
    /// Checks the wire bounds and returns the canonical peer identifier.
    pub fn check(&self, now: i64) -> Result<Id, &'static str> {
        let peer = self
            .peer_id
            .parse()
            .map_err(|_| "invalid topology peer ID")?;
        if self.last_contact_unix_seconds <= now.saturating_sub(TTL_SECONDS)
            || self.last_contact_unix_seconds > now.saturating_add(5)
        {
            return Err("topology contact is outside the retention window");
        }
        if self
            .latency_ms
            .is_some_and(|v| !v.is_finite() || v <= 0.0 || v > 60_000.0)
        {
            return Err("invalid topology RTT");
        }
        Ok(peer)
    }
}

/// Latest report from one authenticated node; an opt-out removes its report.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Report {
    /// Whether the node has opted in to topology reporting.
    pub enabled: bool,
    /// Observations, with no packet content or addresses.
    #[serde(deserialize_with = "null_peers")]
    pub peers: Vec<Peer>,
}

fn null_peers<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Peer>, D::Error> {
    Ok(Option::<Vec<Peer>>::deserialize(d)?.unwrap_or_default())
}
