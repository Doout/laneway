//! JSON contract shared by the fleet controller and opt-in update agents.
use serde::{Deserialize, Serialize};

/// Atomic claim/presence endpoint on the node mTLS API.
pub const POLL_PATH: &str = "/v1/node/fleet-updates/poll";

/// Return the terminal-evidence endpoint for a canonical assignment ID.
pub fn result_path(id: crate::Id) -> String {
    format!("/v1/node/fleet-updates/{id}/result")
}

/// Fields an update agent uses from an assigned plan.
#[derive(Debug, Serialize, Deserialize)]
pub struct Assignment {
    /// Opaque canonical update ID.
    pub id: String,
    /// Exact stable release tag.
    pub version: String,
    /// Installation kind.
    pub component: Component,
    /// Configured opt-in lane.
    pub channel: Channel,
}

/// No assignment is represented as an explicit JSON null.
#[derive(Debug, Serialize, Deserialize)]
pub struct PollReply {
    /// Newly claimed assignment, if there is eligible work.
    #[serde(deserialize_with = "present_assignment")]
    pub update: Option<Assignment>,
}

fn present_assignment<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<Option<Assignment>, D::Error> {
    Option::deserialize(de)
}

/// The controller only assigns releases in the locally configured lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    /// A system service installation of Laneway.
    Node,
    /// A containerized connector installation.
    Connector,
}

/// Explicit scheduling lanes; neither implies automatic discovery of releases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// The stable scheduling lane.
    Stable,
    /// The manual scheduling lane.
    Manual,
}

/// A locally verified terminal update outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The requested version is running and healthy.
    Healthy,
    /// The previous version is running and healthy again.
    RolledBack,
    /// The installation could not be completed.
    Failed,
}

macro_rules! as_str {
    ($name:ident { $($variant:ident => $wire:literal),+ }) => {
        impl $name {
            /// The exact stable JSON/SQLite value.
            pub const fn as_str(&self) -> &'static str {
                match self { $(Self::$variant => $wire),+ }
            }
        }
    };
}
as_str!(Component { Node => "node", Connector => "connector" });
as_str!(Channel { Stable => "stable", Manual => "manual" });
as_str!(Outcome { Healthy => "healthy", RolledBack => "rolled_back", Failed => "failed" });

/// Create a release plan. The first `canary_count` entries are canaries.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    /// Exact stable release tag.
    pub version: String,
    /// Installation kind.
    pub component: Component,
    /// Local opt-in lane.
    pub channel: Channel,
    /// Canonical IDs in administrator-defined canary order.
    pub node_ids: Vec<String>,
    /// Number of entries that can claim before promotion.
    pub canary_count: usize,
}

/// Poll and optionally claim one assignment as an authenticated node.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Poll {
    /// Node ID read from the local runtime.
    pub runtime_node_id: String,
    /// Network ID read from the local runtime.
    pub runtime_network_id: String,
    /// Configured installation kind.
    pub component: Component,
    /// Configured lane.
    pub channel: Channel,
    /// Version observed before the update.
    pub current_version: String,
}

/// Report terminal evidence for a claimed assignment.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// Node ID read from the local runtime.
    pub runtime_node_id: String,
    /// Network ID read from the local runtime.
    pub runtime_network_id: String,
    /// Locally verified result.
    pub state: Outcome,
    /// Exact running version, or empty when unverified after failure.
    #[serde(default)]
    pub observed_version: String,
    /// Short diagnostic without raw logs or credentials.
    #[serde(default)]
    pub detail: String,
}

/// Accept only bounded, exact stable GitHub release tags.
pub fn valid_version(value: &str) -> bool {
    if value.len() > 64 {
        return false;
    }
    let Some(version) = value.strip_prefix('v') else {
        return false;
    };
    let mut parts = version.split('.');
    (0..3).all(|_| {
        parts.next().is_some_and(|p| {
            !p.is_empty()
                && (p.len() == 1 || !p.starts_with('0'))
                && p.bytes().all(|b| b.is_ascii_digit())
        })
    }) && parts.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_update_is_not_no_work() {
        assert!(serde_json::from_str::<PollReply>("{}").is_err());
        assert!(
            serde_json::from_str::<PollReply>(r#"{"update":null}"#)
                .unwrap()
                .update
                .is_none()
        );
    }

    #[test]
    fn only_exact_bounded_stable_tags() {
        assert!(valid_version("v0.100.9"));
        for v in [
            "1.2.3",
            "latest",
            "v01.2.3",
            "v1.2.3-rc.1",
            "v1.2.3.4",
            "v1..3",
            "v１.2.3",
            "v1.2.3\n",
        ] {
            assert!(!valid_version(v), "{v:?}");
        }
        assert!(!valid_version(&format!("v1.0.{}", "9".repeat(60))));
    }
}
