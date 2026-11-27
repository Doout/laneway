#![deny(missing_docs)]

//! Native Laneway node dataplane. The crate owns the TUN hot path,
//! immutable routing, authenticated QUIC relay/direct carriers, bounded queues,
//! and reconnect lifecycle without per-packet cross-language IPC.

mod agent;
mod authority;
pub mod benchmark;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod client_package;
mod codec;
mod config;
mod connector;
mod controller;
mod controller_tls;
mod diagnostics;
mod direct;
mod dns;
mod exit_intent;
#[cfg(target_os = "linux")]
pub mod fleet_update;
mod foreground_routes;
mod kernel;
mod local_api;
mod metrics;
mod nft_state;
mod packet_pool;
mod private_dns;
mod probe;
mod relay;
mod renewal;
pub mod rootless;
mod routing;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod signed_release;
mod state;
mod status_report;
mod tcp_fallback;
mod tls;
mod topology;
mod tun;
mod wireguard;

pub use agent::Agent;
pub use config::{
    Config, ConnectorConfig, ControllerConfig, DiagnosticsConfig, DirectConfig, DirectPeerConfig,
    ForegroundRoutes, ForwardingConfig, IdentityConfig, RelayConfig, RouteConfig, RouteKind,
    TcpFallbackConfig, TlsConfig, TunConfig,
};
pub use metrics::{Metrics, MetricsSnapshot};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use renewal::recover_node_credential;
#[doc(hidden)]
pub use renewal::renew_saved_login;
pub use routing::{PacketMeta, Route, RoutingTable, locally_owned, packet_meta};
#[cfg(target_os = "linux")]
pub use wireguard::{SharedHostExit, WireGuardNode};
pub use wireguard::{WireGuardDatagram, WireGuardRelay};

/// IP packet budget for userspace TCP over a minimum-size QUIC path.
///
/// The 1200-byte UDP payload must also fit the short header (flags, largest
/// connection ID and packet number), AEAD tag, Quinn's DATAGRAM frame bound
/// and a Laneway route header. Both relay hops can have a different path MTU.
pub const TCP_RELAY_IP_MTU: usize =
    1200 - (1 + 20 + 4 + 16 + 9) - laneway_protocol::PACKET_HEADER_LEN;

/// Run the privileged macOS network helper with the inherited control socket.
/// No node configuration or credentials are loaded in this process.
#[cfg(target_os = "macos")]
pub fn macos_network_helper() -> anyhow::Result<()> {
    tun::serve_inherited()
}

fn product_version() -> &'static str {
    option_env!("LANEWAY_PRODUCT_VERSION")
        .filter(|value| {
            (1..=64).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_graphic())
        })
        .unwrap_or(env!("CARGO_PKG_VERSION"))
}

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod deployment_update;
