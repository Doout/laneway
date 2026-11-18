//! Docker's local-scope Laneway driver and v1 ownership state.
mod driver;
#[cfg(target_os = "linux")]
mod linux;
mod listener;
mod model;
mod store;
#[cfg(test)]
mod tests;

use thiserror::Error;

pub use driver::{Backend, Driver, Reply};
#[cfg(target_os = "linux")]
pub use linux::LinuxBackend;
pub use listener::serve_until;
pub use model::{Authorization, Egress, Endpoint, Ingress, Network, Phase, Policy};
pub use store::Store;

/// Errors reported to Docker as an `Err` JSON field.
#[derive(Debug, Error)]
pub enum Error {
    #[error("dockerplugin: invalid configuration: {0}")]
    Invalid(String),
    #[error("dockerplugin: policy is not controller-authorized: {0}")]
    Unauthorized(String),
    #[error("dockerplugin: ownership conflict: {0}")]
    Conflict(String),
    #[error("dockerplugin: object not found")]
    NotFound,
    #[error("dockerplugin: state I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("dockerplugin: invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("dockerplugin: network backend: {0}")]
    Backend(String),
}

/// Result of a driver operation.
pub type Result<T> = std::result::Result<T, Error>;

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

fn conflict(message: impl Into<String>) -> Error {
    Error::Conflict(message.into())
}
