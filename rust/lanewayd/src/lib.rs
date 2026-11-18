#![deny(missing_docs)]

//! Native Laneway node dataplane. The crate owns the TUN hot path,
//! immutable routing, authenticated QUIC relay/direct carriers, bounded queues,
//! and reconnect lifecycle without per-packet cross-language IPC.

mod agent;
mod authority;
pub mod benchmark;
mod codec;
mod config;
mod connector;
mod controller;
mod diagnostics;
mod direct;
mod dns;
mod exit_intent;
mod foreground_routes;
mod kernel;
mod local_api;
mod metrics;
mod nft_state;
mod packet_pool;
mod probe;
mod relay;
mod renewal;
mod routing;
mod state;
mod status_report;
mod tcp_fallback;
mod tls;
mod tun;
mod wireguard;

pub use agent::Agent;
pub use config::{
    Config, ConnectorConfig, ControllerConfig, DiagnosticsConfig, DirectConfig, DirectPeerConfig,
    ForegroundRoutes, ForwardingConfig, IdentityConfig, RelayConfig, RouteConfig, RouteKind,
    TcpFallbackConfig, TlsConfig, TunConfig,
};
pub use metrics::{Metrics, MetricsSnapshot};
pub use routing::{PacketMeta, Route, RoutingTable, locally_owned, packet_meta};
#[cfg(target_os = "linux")]
pub use wireguard::{SharedHostExit, WireGuardNode};
pub use wireguard::{WireGuardDatagram, WireGuardRelay};

fn product_version() -> &'static str {
    option_env!("LANEWAY_PRODUCT_VERSION")
        .filter(|value| {
            (1..=64).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_graphic())
        })
        .unwrap_or(env!("CARGO_PKG_VERSION"))
}
