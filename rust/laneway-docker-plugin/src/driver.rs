use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    path::PathBuf,
    sync::{Mutex, MutexGuard},
};

use ipnet::Ipv4Net;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::{
    Authorization, Endpoint, Error, Network, Phase, Policy, Result, Store, conflict, invalid,
    model::{endpoint_names, network_names, usable, valid_id, valid_sandbox},
    store::read_private,
};

/// Host networking behind the Linux privilege boundary. Join must be
/// idempotent for the same recorded endpoint, including after restart.
pub trait Backend: Send + Sync {
    fn apply(&self, network: &Network) -> Result<()>;
    fn remove(&self, network: &Network) -> Result<()>;
    fn join(&self, network: &Network, endpoint: &Endpoint) -> Result<()>;
    fn leave(&self, network: &Network, endpoint: &Endpoint) -> Result<()>;
}

pub struct Reply {
    pub status: u16,
    pub body: Value,
}

pub struct Driver<B> {
    store: Mutex<Store>,
    backend: B,
    authorization_path: PathBuf,
    version: String,
    now: fn() -> OffsetDateTime,
}

impl<B: Backend> Driver<B> {
    pub fn new(store: Store, backend: B, authorization_path: PathBuf, version: String) -> Self {
        Self {
            store: Mutex::new(store),
            backend,
            authorization_path,
            version,
            now: OffsetDateTime::now_utc,
        }
    }

    fn store(&self) -> Result<MutexGuard<'_, Store>> {
        self.store
            .lock()
            .map_err(|_| conflict("ownership journal lock poisoned"))
    }

    #[cfg(test)]
    pub(crate) fn set_clock(&mut self, now: fn() -> OffsetDateTime) {
        self.now = now;
    }

    /// Recover recorded networks before advertising Docker readiness.
    pub fn reconcile(&self) -> Result<()> {
        let mut store = self.store()?;
        let known = store.networks().clone();
        for network in known
            .values()
            .filter(|network| network.phase == Phase::Active)
        {
            self.authorize_recorded(network)?;
        }
        for (id, network) in known {
            if network.phase == Phase::Creating {
                // Keep the journal if the backend could not prove cleanup.
                self.backend.remove(&network)?;
                store.update(|networks| {
                    networks.remove(&id);
                    Ok(())
                })?;
            } else {
                self.backend.apply(&network)?;
            }
        }
        Ok(())
    }

    /// Handle one local Docker HTTP request using the same result shape as
    /// the Go v1 runtime. Docker expects semantic driver errors inside 200s.
    pub fn handle(&self, method: &str, path: &str, body: &[u8]) -> Reply {
        if method != "POST" && path != "/status" {
            return Reply {
                status: 405,
                body: json!({"Err":"POST required"}),
            };
        }
        if body.len() > 1 << 20 {
            return Reply {
                status: 400,
                body: json!({"Err":"Docker request exceeds the request limit"}),
            };
        }
        let result = match path {
            "/Plugin.Activate" => Ok(json!({"Implements":["NetworkDriver"]})),
            "/NetworkDriver.GetCapabilities" => {
                Ok(json!({"Scope":"local","ConnectivityScope":"local"}))
            }
            "/NetworkDriver.CreateNetwork" => {
                decode(body).and_then(|request| self.create_network(request))
            }
            "/NetworkDriver.DeleteNetwork" => {
                decode(body).and_then(|request| self.delete_network(request))
            }
            "/NetworkDriver.CreateEndpoint" => {
                decode(body).and_then(|request| self.create_endpoint(request))
            }
            "/NetworkDriver.DeleteEndpoint" => {
                decode(body).and_then(|request| self.end_endpoint(request, true))
            }
            "/NetworkDriver.Join" => decode(body).and_then(|request| self.join(request)),
            "/NetworkDriver.Leave" => {
                decode(body).and_then(|request| self.end_endpoint(request, false))
            }
            "/NetworkDriver.EndpointOperInfo" => {
                decode(body).and_then(|request| self.endpoint_info(request))
            }
            "/NetworkDriver.DiscoverNew" | "/NetworkDriver.DiscoverDelete" => Ok(json!({})),
            "/NetworkDriver.AllocateNetwork" | "/NetworkDriver.FreeNetwork" => {
                Ok(json!({"Err":"global-scope and Swarm networking are not supported"}))
            }
            "/status" => self.status(),
            _ => {
                return Reply {
                    status: 404,
                    body: json!({"Err":"unknown Docker plugin operation"}),
                };
            }
        };
        match result {
            Ok(body) => Reply { status: 200, body },
            Err(error) => Reply {
                status: if matches!(error, Error::Json(_)) {
                    400
                } else {
                    200
                },
                body: json!({"Err":error.to_string()}),
            },
        }
    }

    fn authorize(&self, network: &Network) -> Result<Vec<Ipv4Net>> {
        if !network.policy.needs_grant() {
            return Ok(Vec::new());
        }
        let grant: Authorization =
            read_private(&self.authorization_path, 1 << 20).map_err(|error| {
                Error::Unauthorized(format!("cannot read private controller snapshot: {error}"))
            })?;
        grant.authorize((self.now)(), network.subnet, &network.policy)?;
        Ok(grant.bypass_cidrs)
    }

    fn authorize_recorded(&self, network: &Network) -> Result<()> {
        if self.authorize(network)? != network.bypass_cidrs {
            return Err(Error::Unauthorized(
                "controller bypasses changed; recorded policy cannot be reused".into(),
            ));
        }
        Ok(())
    }

    fn create_network(&self, request: CreateNetwork) -> Result<Value> {
        if !valid_id(&request.id) || request.ipv4.len() != 1 || !request.ipv6.is_empty() {
            return Err(invalid(
                "one IPv4 pool and a network ID are required; IPv6 is unsupported",
            ));
        }
        let pool = &request.ipv4[0];
        let subnet = pool
            .pool
            .parse::<Ipv4Net>()
            .map_err(|_| invalid("invalid IPv4 pool"))?;
        let gateway = pool
            .gateway
            .split('/')
            .next()
            .unwrap_or_default()
            .parse::<Ipv4Addr>()
            .map_err(|_| invalid("invalid IPv4 gateway"))?;
        let policy = Policy::from_options(request.options.as_ref())?;
        let (bridge, table) = network_names(&request.id);
        let mut network = Network {
            id: request.id.clone(),
            bridge,
            table,
            subnet,
            gateway,
            policy,
            bypass_cidrs: vec![],
            phase: Phase::Creating,
            created_at: (self.now)(),
            endpoints: BTreeMap::new(),
        };
        network.validate(&request.id)?;
        let mut store = self.store()?;
        if let Some(prior) = store.networks().get(&request.id) {
            if prior.phase == Phase::Active
                && prior.subnet == subnet
                && prior.gateway == gateway
                && prior.policy == network.policy
            {
                self.authorize_recorded(prior)?;
                return Ok(json!({}));
            }
            return Err(conflict(
                "network already exists with other settings or needs recovery",
            ));
        }
        network.bypass_cidrs = self.authorize(&network)?;
        store.update(|networks| {
            networks.insert(request.id.clone(), network.clone());
            Ok(())
        })?;
        if let Err(error) = self.backend.apply(&network) {
            if let Err(cleanup) = self.backend.remove(&network) {
                return Err(Error::Backend(format!(
                    "{error}; cleanup pending: {cleanup}"
                )));
            }
            store.update(|networks| {
                networks.remove(&request.id);
                Ok(())
            })?;
            return Err(error);
        }
        store.update(|networks| {
            networks.get_mut(&request.id).ok_or(Error::NotFound)?.phase = Phase::Active;
            Ok(())
        })?;
        Ok(json!({}))
    }

    fn delete_network(&self, request: NetworkRequest) -> Result<Value> {
        let mut store = self.store()?;
        if let Some(network) = store.networks().get(&request.network) {
            if !network.endpoints.is_empty() {
                return Err(conflict("network still has endpoints"));
            }
            self.backend.remove(network)?;
            store.update(|networks| {
                networks.remove(&request.network);
                Ok(())
            })?;
        }
        Ok(json!({}))
    }

    fn create_endpoint(&self, request: EndpointRequest) -> Result<Value> {
        if !valid_id(&request.endpoint) {
            return Err(invalid("invalid endpoint ID"));
        }
        let mut store = self.store()?;
        let network = store
            .networks()
            .get(&request.network)
            .filter(|n| n.phase == Phase::Active)
            .ok_or(Error::NotFound)?;
        self.authorize_recorded(network)?;
        let interface = request
            .interface
            .filter(|data| data.ipv6.is_empty())
            .ok_or_else(|| invalid("one IPv4 endpoint address is required"))?;
        let address = interface
            .address
            .parse::<Ipv4Net>()
            .map_err(|_| invalid("invalid IPv4 endpoint address"))?
            .addr();
        if !usable(network.subnet, address) || address == network.gateway {
            return Err(invalid("endpoint address is outside its network"));
        }
        if let Some(prior) = network.endpoints.get(&request.endpoint) {
            return if prior.address == address {
                Ok(json!({}))
            } else {
                Err(conflict("endpoint already has a different address"))
            };
        }
        store.update(|networks| {
            networks
                .get_mut(&request.network)
                .ok_or(Error::NotFound)?
                .endpoints
                .insert(
                    request.endpoint.clone(),
                    Endpoint {
                        id: request.endpoint,
                        address,
                        host_veth: String::new(),
                        peer_veth: String::new(),
                        sandbox: String::new(),
                        joined: false,
                        join_pending: false,
                    },
                );
            Ok(())
        })?;
        Ok(json!({}))
    }

    fn join(&self, request: EndpointRequest) -> Result<Value> {
        if !valid_sandbox(&request.sandbox) {
            return Err(invalid("invalid Docker sandbox key"));
        }
        let mut store = self.store()?;
        let network = store
            .networks()
            .get(&request.network)
            .filter(|n| n.phase == Phase::Active)
            .ok_or(Error::NotFound)?
            .clone();
        self.authorize_recorded(&network)?;
        let mut endpoint = network
            .endpoints
            .get(&request.endpoint)
            .ok_or(Error::NotFound)?
            .clone();
        if endpoint.has_link_intent() && endpoint.sandbox != request.sandbox {
            return Err(conflict("endpoint is already joined to another sandbox"));
        }
        if !endpoint.has_link_intent() {
            (endpoint.host_veth, endpoint.peer_veth) = endpoint_names(&request.endpoint);
            endpoint.sandbox = request.sandbox;
            endpoint.join_pending = true;
            // Record ownership intent before creating a link that could survive
            // process death. An exact repeat asks the backend to verify it.
            store.update(|networks| {
                networks
                    .get_mut(&request.network)
                    .ok_or(Error::NotFound)?
                    .endpoints
                    .insert(request.endpoint.clone(), endpoint.clone());
                Ok(())
            })?;
        }
        self.backend.join(&network, &endpoint)?;
        if endpoint.join_pending {
            endpoint.join_pending = false;
            endpoint.joined = true;
            store.update(|networks| {
                networks
                    .get_mut(&request.network)
                    .ok_or(Error::NotFound)?
                    .endpoints
                    .insert(request.endpoint.clone(), endpoint.clone());
                Ok(())
            })?;
        }
        let mut result = json!({"InterfaceName":{"SrcName":endpoint.peer_veth,"DstPrefix":"eth"}, "Gateway":network.gateway});
        if !network.policy.dns.is_empty() {
            result["StaticRoutes"] = json!([]);
            result["DisableGatewayService"] = json!(true);
            result["DNSNameserver"] = json!(network.policy.dns);
        }
        Ok(result)
    }

    fn end_endpoint(&self, request: EndpointRequest, delete: bool) -> Result<Value> {
        let mut store = self.store()?;
        let Some(network) = store.networks().get(&request.network) else {
            return Ok(json!({}));
        };
        let Some(endpoint) = network.endpoints.get(&request.endpoint) else {
            return Ok(json!({}));
        };
        if endpoint.has_link_intent() {
            self.backend.leave(network, endpoint)?;
        }
        if endpoint.has_link_intent() || delete {
            store.update(|networks| {
                let endpoints = &mut networks
                    .get_mut(&request.network)
                    .ok_or(Error::NotFound)?
                    .endpoints;
                if delete {
                    endpoints.remove(&request.endpoint);
                } else if let Some(endpoint) = endpoints.get_mut(&request.endpoint) {
                    endpoint.joined = false;
                    endpoint.join_pending = false;
                    endpoint.sandbox.clear();
                    endpoint.host_veth.clear();
                    endpoint.peer_veth.clear();
                }
                Ok(())
            })?;
        }
        Ok(json!({}))
    }

    fn endpoint_info(&self, request: EndpointRequest) -> Result<Value> {
        let store = self.store()?;
        let network = store
            .networks()
            .get(&request.network)
            .ok_or(Error::NotFound)?;
        let endpoint = network
            .endpoints
            .get(&request.endpoint)
            .ok_or(Error::NotFound)?;
        Ok(
            json!({"Value":{"address":endpoint.address,"joined":endpoint.joined,"policy":network.policy.egress}}),
        )
    }

    fn status(&self) -> Result<Value> {
        let store = self.store()?;
        let mut endpoints = 0;
        let mut policies = BTreeMap::new();
        let mut diagnostics = BTreeMap::new();
        for network in store.networks().values() {
            endpoints += network.endpoints.len();
            let policy_name = serde_json::to_value(network.policy.egress)?;
            *policies
                .entry(
                    policy_name
                        .as_str()
                        .expect("egress serializes as string")
                        .to_owned(),
                )
                .or_insert(0) += 1;
            if network.phase != Phase::Active {
                diagnostics.insert(
                    &network.id,
                    String::from("network cleanup or startup reconciliation is pending"),
                );
            } else if network
                .endpoints
                .values()
                .any(|endpoint| endpoint.join_pending)
            {
                diagnostics.insert(
                    &network.id,
                    String::from("endpoint join recovery is pending"),
                );
            } else if let Err(error) = self.authorize_recorded(network) {
                diagnostics.insert(&network.id, error.to_string());
            }
        }
        Ok(
            json!({"version":self.version,"ready":diagnostics.is_empty(),"networks":store.networks().len(),"endpoints":endpoints,"policies":policies,"diagnostics":diagnostics}),
        )
    }
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    Ok(serde_json::from_slice(body)?)
}

fn null_default<'de, T: Deserialize<'de> + Default, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<T, D::Error> {
    Ok(Option::<T>::deserialize(decoder)?.unwrap_or_default())
}

#[derive(Deserialize)]
struct CreateNetwork {
    #[serde(rename = "NetworkID")]
    id: String,
    #[serde(rename = "IPv4Data", default, deserialize_with = "null_default")]
    ipv4: Vec<Ipam>,
    #[serde(rename = "IPv6Data", default, deserialize_with = "null_default")]
    ipv6: Vec<Ipam>,
    #[serde(rename = "Options")]
    options: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Ipam {
    pool: String,
    gateway: String,
}

#[derive(Deserialize)]
struct NetworkRequest {
    #[serde(rename = "NetworkID")]
    network: String,
}

#[derive(Deserialize)]
struct EndpointRequest {
    #[serde(rename = "NetworkID")]
    network: String,
    #[serde(rename = "EndpointID")]
    endpoint: String,
    #[serde(rename = "Interface")]
    interface: Option<Interface>,
    #[serde(rename = "SandboxKey", default)]
    sandbox: String,
}

#[derive(Deserialize)]
struct Interface {
    #[serde(rename = "Address")]
    address: String,
    #[serde(rename = "AddressIPv6", default)]
    ipv6: String,
}
