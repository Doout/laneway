#![deny(unsafe_code)]
#![deny(missing_docs)]

//! Production-oriented Rust implementation of the Laneway v1 QUIC and
//! TLS/TCP fallback relay carriers.

pub mod allocator;
pub mod benchmark;
mod codec;
mod config;
mod controller;
mod diagnostics;
mod metrics;
mod packet_pool;
mod registry;
mod server;
mod tcp;
mod tls;

pub use config::{Config, PeerConfig, RelayConfig, TcpFallbackConfig, TlsConfig};
pub use metrics::{Metrics, MetricsSnapshot};
pub use server::Server;
