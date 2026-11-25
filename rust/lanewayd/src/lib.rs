#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Laneway node dataplane. The transport core supports unprivileged relay
//! clients, direct carriers, Linux TUN devices, and adopted macOS utun devices.

#[cfg(feature = "native")]
mod agent;
mod authority;
#[cfg(feature = "native")]
pub mod benchmark;
mod codec;
mod config;
mod controller;
mod controller_tls;
#[cfg(feature = "native")]
mod diagnostics;
#[cfg(feature = "native")]
mod direct;
#[cfg(feature = "native")]
mod dns;
#[cfg(feature = "native")]
mod exit_intent;
#[cfg(feature = "native")]
mod kernel;
#[cfg(feature = "native")]
mod local_api;
mod metrics;
#[cfg(feature = "native")]
mod nft_state;
mod packet_pool;
#[cfg(feature = "native")]
mod probe;
mod relay;
pub mod rootless;
mod routing;
#[cfg(feature = "native")]
mod session;
mod state;
mod tcp_fallback;
mod tls;
#[cfg(feature = "native")]
mod tun;
#[cfg(all(feature = "native", target_os = "macos"))]
mod utun;

#[cfg(feature = "native")]
pub use agent::Agent;
pub use config::{
    Config, ControllerConfig, DiagnosticsConfig, DirectConfig, DirectPeerConfig, ExitFailureMode,
    ForwardMode, ForwardingConfig, IdentityConfig, RelayConfig, RouteConfig, RouteKind,
    SubnetForwardConfig, TcpFallbackConfig, TlsConfig, TunConfig,
};
pub use metrics::{Metrics, MetricsSnapshot};
pub use routing::{PacketMeta, Route, RoutingTable, locally_owned, packet_meta};
#[cfg(feature = "native")]
pub use session::{
    ConfigurationFilter, SessionExitPlan, SessionNetwork, SessionNetworkOpener, SessionRoute,
    SessionRoutes, SessionStatus,
};
#[cfg(all(feature = "native", target_os = "macos"))]
pub use utun::UtunPackets;
