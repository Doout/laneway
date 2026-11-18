//! Bounded JSON exchanged by authenticated nodes and the controller.
use serde::{Deserialize, Serialize};

macro_rules! state {
    ($name:ident, $doc:literal, {$($(#[$meta:meta])* $variant:ident => $value:literal),+ $(,)?}) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
        pub enum $name {
            $($(#[$meta])* #[serde(rename = $value)] $variant),+
        }
        impl $name {
            /// Returns the exact stable-v1 JSON spelling.
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value),+ }
            }
            /// Reads a stable-v1 state without accepting unrecognized strings.
            pub fn from_wire(value: &str) -> Option<Self> {
                match value { $($value => Some(Self::$variant),)+ _ => None }
            }
        }
    };
}
state!(Platform, "Operating system of the reporting node.", {
    /// Linux.
    Linux => "linux",
    /// macOS.
    Darwin => "darwin",
    /// Windows.
    Windows => "windows",
    /// A known but unlisted platform.
    Other => "other",
    /// The platform was not determined.
    Unknown => "unknown",
});
state!(Certificate, "Validity of the local identity.", {
    /// The current leaf is valid.
    Healthy => "healthy",
    /// The leaf is within its renewal period.
    RenewalDue => "renewal_due",
    /// The leaf has expired.
    Expired => "expired",
    /// The controller revoked the leaf.
    Revoked => "revoked",
    /// No validity information is available.
    Unknown => "unknown",
});
state!(Configuration, "Status of the applied configuration.", {
    /// The applied lease is current.
    Current => "current",
    /// The node has not applied the latest epoch.
    Stale => "stale",
    /// The last lease expired.
    Expired => "expired",
    /// No configuration status is available.
    Unknown => "unknown",
});
state!(Carrier, "State of the encrypted transport.", {
    /// A direct peer path is available.
    Direct => "direct",
    /// A relay QUIC path is available.
    RelayQuic => "relay_quic",
    /// The relay TCP fallback is active.
    RelayTcp => "relay_tcp",
    /// Carrier negotiation is underway.
    Negotiating => "negotiating",
    /// The available path is degraded.
    Degraded => "degraded",
    /// No carrier is connected.
    Disconnected => "disconnected",
    /// The carrier is unknown.
    Unknown => "unknown",
});
state!(Route, "Readiness of the local route configuration.", {
    /// Routes are applied.
    Ready => "ready",
    /// Route configuration has a known impairment.
    Degraded => "degraded",
    /// No usable route configuration exists.
    Unavailable => "unavailable",
    /// Route health could not be determined.
    Unknown => "unknown",
});
state!(SelectedExit, "Readiness of the user's selected exit.", {
    /// Exit routing is not requested.
    NotSelected => "not_selected",
    /// The selected exit is usable.
    Ready => "ready",
    /// The selected exit has a known impairment.
    Degraded => "degraded",
    /// The requested exit is not usable.
    Unavailable => "unavailable",
    /// Exit health could not be determined.
    Unknown => "unknown",
});

/// Short-lived diagnostic report. It carries no addresses, packet data,
/// identifiers, credentials, or arbitrary diagnostic text.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// How long the controller can retain the report as current.
    pub valid_for_seconds: u32,
    /// Product version, limited to printable ASCII without spaces.
    pub product_version: String,
    /// Operating system.
    pub platform: Platform,
    /// Local certificate validity.
    pub certificate_state: Certificate,
    /// Status of the applied configuration.
    pub configuration_state: Configuration,
    /// Currently available transport.
    pub carrier_state: Carrier,
    /// Readiness of local routing.
    pub route_state: Route,
    /// Readiness of the requested exit path.
    pub selected_exit_state: SelectedExit,
    /// Cumulative local cleanup failures.
    pub cleanup_failure_count: u32,
    /// Most recent epoch the node applied, or zero before the first apply.
    pub configuration_epoch: u64,
}

/// Maximum cleanup count representable in a status report.
pub const MAX_CLEANUP_FAILURES: u32 = 1_000_000_000;

impl Report {
    /// Checks stable-v1 field bounds.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(10..=300).contains(&self.valid_for_seconds) {
            return Err("endpoint status valid_for_seconds must be 10..300");
        }
        if !(1..=64).contains(&self.product_version.len())
            || !self
                .product_version
                .bytes()
                .all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err("endpoint status product_version must be 1..64 printable ASCII bytes");
        }
        if self.cleanup_failure_count > MAX_CLEANUP_FAILURES {
            return Err("endpoint cleanup failure count is too large");
        }
        if self.configuration_epoch > i64::MAX as u64 {
            return Err("endpoint configuration epoch is too large");
        }
        Ok(())
    }
}
