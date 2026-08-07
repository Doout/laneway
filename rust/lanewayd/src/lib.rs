#![deny(missing_docs)]

//! Native Linux Laneway node dataplane. The crate owns the TUN hot path,
//! immutable routing, authenticated QUIC relay/direct carriers, bounded queues,
//! and reconnect lifecycle without per-packet cross-language IPC.

mod agent;
mod authority;
pub mod benchmark;
mod codec;
mod config;
mod controller;
mod diagnostics;
mod direct;
mod dns;
mod exit_intent;
mod kernel;
mod local_api;
mod metrics;
mod nft_state;
mod packet_pool;
mod probe;
mod relay;
mod routing;
mod state;
mod tcp_fallback;
mod tls;
mod tun;

pub use agent::Agent;
pub use config::{
    Config, ControllerConfig, DiagnosticsConfig, DirectConfig, DirectPeerConfig, ForwardingConfig,
    IdentityConfig, RelayConfig, RouteConfig, RouteKind, TcpFallbackConfig, TlsConfig, TunConfig,
};
pub use metrics::{Metrics, MetricsSnapshot};
pub use routing::{PacketMeta, Route, RoutingTable, locally_owned, packet_meta};
