//! Durable singleton gateway intent, provider ownership and runtime reconciliation.
mod lifecycle;
pub use lifecycle::reconcile;
#[cfg(test)]
mod tests;

use super::{
    Connection, Failure, Storage,
    actuator::{self, RuntimeStatus},
    provider::Provider,
};
use crate::{
    bootstrap_discovery::Discovery,
    gateway_overlay::{self as overlay, GatewaySpec},
};
use laneway_protocol::Id;
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
use serde::{Deserialize, Serialize};
use std::{fs::File, net::Ipv4Addr, os::unix::fs::PermissionsExt, path::Path};

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub network_id: String,
    pub client_node_id: String,
    pub resource_id: String,
    pub tcp_port: u16,
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
enum Phase {
    Planned,
    CreatingAccount,
    AccountCreated,
    CreatingKey,
    Submitted,
    ChangingClient,
    WaitingForRoute,
    Ready,
    Failed,
    Removing,
    Retrying,
}

#[derive(Deserialize, Serialize)]
pub(super) struct Binding {
    gateway_id: String,
    selection: Selection,
    destination: Ipv4Addr,
    phase: Phase,
    account_id: Option<String>,
    key_id: Option<String>,
    // Persist the possibility of a side effect before issuing it.
    account_possible: bool,
    worker_possible: bool,
    #[serde(default)]
    key_expires_at: Option<u64>,
    #[serde(default)]
    submitted_at: u64,
    #[serde(default)]
    last_confirmed: u64,
    #[serde(default)]
    retry_after: u64,
    #[serde(default)]
    next_scope_check: u64,
    #[serde(default)]
    not_found_since: Option<u64>,
    #[serde(default)]
    pending_client: Option<String>,
    detail: Option<String>,
}

impl Binding {
    fn spec(&self) -> Result<GatewaySpec, Failure> {
        Ok(GatewaySpec {
            gateway: self.gateway_id.parse().map_err(|_| Failure::Storage)?,
            network: self
                .selection
                .network_id
                .parse()
                .map_err(|_| Failure::GatewayUnsupported)?,
            client: self
                .selection
                .client_node_id
                .parse()
                .map_err(|_| Failure::GatewayUnsupported)?,
            address: self.destination,
            port: self.selection.tcp_port,
        })
    }

    fn name(&self) -> String {
        format!("laneway-{}", self.gateway_id)
    }
}

#[derive(Serialize)]
pub struct Status {
    state: &'static str,
    gateway_id: Option<String>,
    network_id: Option<String>,
    client_node_id: Option<String>,
    resource_id: Option<String>,
    destination: Option<Ipv4Addr>,
    tcp_port: Option<u16>,
    runtime_available: bool,
    detail: Option<String>,
}

fn random_id() -> Result<String, Failure> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| Failure::Storage)?;
    Id::new(bytes)
        .map(|id| id.to_string())
        .map_err(|_| Failure::Storage)
}

pub struct Candidate {
    binding: Binding,
    existing: bool,
    change_to: Option<String>,
}

pub async fn prepare(
    database: &Path,
    connection: &Connection,
    selection: Selection,
    configured: bool,
    expected: Option<&str>,
) -> Result<Candidate, Failure> {
    if !configured || !actuator::available(database) {
        return Err(Failure::GatewayUnavailable);
    }
    if selection.tcp_port == 0
        || !(1..=1024).contains(&selection.resource_id.len())
        || !selection
            .resource_id
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
        || selection.network_id.parse::<Id>().is_err()
        || selection.client_node_id.parse::<Id>().is_err()
    {
        return Err(Failure::GatewayUnsupported);
    }
    let store = Storage::for_database(database);
    if let Some(existing) = store.binding()? {
        let old = &existing.selection;
        if matches!(existing.phase, Phase::Removing)
            || old.network_id != selection.network_id
            || old.resource_id != selection.resource_id
            || old.tcp_port != selection.tcp_port
        {
            return Err(Failure::GatewayConflict);
        }
        let tag = format!("{}:{}", existing.gateway_id, old.client_node_id);
        if expected.is_some_and(|value| value != tag) {
            return Err(Failure::GatewayChanged);
        }
        let change_to = if old.client_node_id == selection.client_node_id {
            None
        } else {
            if expected.is_none() {
                return Err(Failure::GatewayChanged);
            }
            if existing.phase != Phase::Ready {
                return Err(Failure::GatewayConflict);
            }
            Some(selection.client_node_id)
        };
        return Ok(Candidate {
            binding: existing,
            existing: true,
            change_to,
        });
    }
    if expected.is_some() {
        return Err(Failure::GatewayChanged);
    }
    let provider =
        Provider::from_credentials(connection.credentials()).map_err(|_| Failure::Rejected)?;
    let destination = provider
        .resolve_resource(&selection.resource_id, selection.tcp_port)
        .await
        .map_err(|error| match error {
            super::provider::ProviderError::ResourceMismatch
            | super::provider::ProviderError::InvalidInput => Failure::GatewayUnsupported,
            super::provider::ProviderError::RateLimited => Failure::RateLimited,
            super::provider::ProviderError::Rejected => Failure::Rejected,
            _ => Failure::Unavailable,
        })?;
    let mut binding = Binding {
        gateway_id: random_id()?,
        selection,
        destination,
        phase: Phase::Planned,
        account_id: None,
        key_id: None,
        account_possible: false,
        worker_possible: false,
        detail: None,
        key_expires_at: None,
        submitted_at: 0,
        last_confirmed: 0,
        retry_after: 0,
        next_scope_check: 0,
        not_found_since: None,
        pending_client: None,
    };
    let spec = binding.spec()?;
    let path = database.to_owned();
    binding.detail = tokio::task::spawn_blocking(move || overlay::preflight(&path, &spec))
        .await
        .map_err(|_| Failure::Storage)?
        .map_err(|_| Failure::GatewayRoute)?
        .map(|conflict| conflict.to_string());
    Ok(Candidate {
        binding,
        existing: false,
        change_to: None,
    })
}

impl Storage {
    pub(super) fn binding(&self) -> Result<Option<Binding>, Failure> {
        match std::fs::symlink_metadata(&self.0) {
            Ok(metadata) if metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0 => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            _ => return Err(Failure::Storage),
        }
        self.read_json(&self.0.join("twingate-gateway.json"))
    }

    pub(super) fn require_gateway_disabled(&self) -> Result<(), Failure> {
        if self.binding()?.is_some() {
            Err(Failure::GatewayConflict)
        } else {
            Ok(())
        }
    }

    fn persist(&self, binding: &Binding) -> Result<(), Failure> {
        self.write_json(&self.0.join("twingate-gateway.json"), binding)
    }

    fn operation(&self) -> Result<File, Failure> {
        self.with_lock(|store| {
            let file = File::from(
                open(
                    store.0.join("gateway-operation.lock"),
                    OFlags::CREATE
                        | OFlags::RDWR
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC
                        | OFlags::NONBLOCK,
                    Mode::RUSR | Mode::WUSR,
                )
                .map_err(|_| Failure::Storage)?,
            );
            let meta = file.metadata().map_err(|_| Failure::Storage)?;
            if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
                return Err(Failure::Storage);
            }
            flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|err| {
                if err == rustix::io::Errno::WOULDBLOCK {
                    Failure::GatewayBusy
                } else {
                    Failure::Storage
                }
            })?;
            Ok(file)
        })
    }

    pub fn request_gateway(
        &self,
        connection: &Connection,
        candidate: Candidate,
    ) -> Result<(), Failure> {
        let _operation = self.operation()?;
        self.with_lock(|store| {
            store.current_connection(connection)?;
            let Candidate {
                binding: candidate,
                existing,
                change_to,
            } = candidate;
            match store.binding()? {
                Some(mut binding)
                    if binding.selection == candidate.selection
                        && binding.gateway_id == candidate.gateway_id =>
                {
                    if let Some(new_client) = change_to {
                        if binding.phase != Phase::Ready {
                            return Err(Failure::GatewayConflict);
                        }
                        binding.phase = Phase::ChangingClient;
                        binding.pending_client = Some(new_client);
                        binding.detail = None;
                        return store.persist(&binding);
                    }
                    match binding.phase {
                        Phase::Removing => Err(Failure::GatewayConflict),
                        Phase::Failed | Phase::Submitted if binding.detail.is_some() => {
                            binding.phase = Phase::Retrying;
                            binding.detail = None;
                            binding.retry_after = 0;
                            store.persist(&binding)
                        }
                        _ => Ok(()),
                    }
                }
                Some(ref binding)
                    if !existing
                        && binding.selection == candidate.selection
                        && binding.phase != Phase::Removing =>
                {
                    Ok(())
                }
                Some(_) => Err(Failure::GatewayConflict),
                None if !existing => store.persist(&candidate),
                None => Err(Failure::GatewayConflict),
            }
        })
    }

    pub fn remove_gateway(&self, expected: Option<&str>) -> Result<(), Failure> {
        let _operation = self.operation()?;
        if let Some(mut binding) = self.binding()? {
            if Some(binding.gateway_id.as_str()) != expected {
                return Err(Failure::GatewayChanged);
            }
            binding.phase = Phase::Removing;
            binding.retry_after = 0;
            binding.detail = None;
            self.persist(&binding)?;
        }
        Ok(())
    }

    pub fn gateway_status(&self, database: &Path, configured: bool) -> Result<Status, Failure> {
        let available = configured && actuator::available(database);
        let binding = self.binding()?;
        let state = match binding.as_ref().map(|b| b.phase) {
            None => "disabled",
            Some(Phase::Removing) => "removing",
            Some(Phase::Failed) => "degraded",
            Some(Phase::Submitted) if binding.as_ref().is_some_and(|b| b.detail.is_some()) => {
                "degraded"
            }
            Some(Phase::Ready)
                if available
                    && binding.as_ref().is_some_and(|b| {
                        super::verification_time().is_ok_and(|now| {
                            now.checked_sub(b.last_confirmed)
                                .is_some_and(|age| age < 90)
                        }) && matches!(
                            actuator::status(database, &b.gateway_id),
                            Ok(RuntimeStatus::Online)
                        )
                    }) =>
            {
                "ready"
            }
            Some(Phase::Ready) => "degraded",
            Some(_) => "provisioning",
        };
        Ok(Status {
            state,
            runtime_available: available,
            gateway_id: binding.as_ref().map(|b| b.gateway_id.clone()),
            network_id: binding.as_ref().map(|b| b.selection.network_id.clone()),
            client_node_id: binding.as_ref().map(|b| b.selection.client_node_id.clone()),
            resource_id: binding.as_ref().map(|b| b.selection.resource_id.clone()),
            destination: binding.as_ref().map(|b| b.destination),
            tcp_port: binding.as_ref().map(|b| b.selection.tcp_port),
            detail: binding.and_then(|b| b.detail),
        })
    }
}
