use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

pub(super) const VERSION: u32 = 1;
pub(super) const MAX_MESSAGE: usize = 64 << 10;
const MAX_ADDRESSES: usize = 8;
const MAX_ROUTES: usize = 1024;
const MAX_BYPASSES: usize = 64;

/// Validated interface settings and initial split-tunnel snapshot.
#[derive(Debug, PartialEq, Eq)]
pub struct Setup {
    pub name: String,
    pub mtu: u16,
    pub addresses: Vec<IpNet>,
    pub routes: RoutePlan,
}

/// Canonical destination and metric.
#[derive(Debug, PartialEq, Eq)]
pub struct Route {
    pub prefix: IpNet,
    pub metric: u32,
}

/// Complete split-tunnel snapshot, including transport addresses to exclude.
#[derive(Debug, PartialEq, Eq)]
pub struct RoutePlan {
    pub routes: Vec<Route>,
    pub transport_bypasses: Vec<IpAddr>,
}

/// Explicit split defaults and policy routing exceptions.
#[derive(Debug, PartialEq, Eq)]
pub struct ExitPlan {
    pub tunnel_prefixes: Vec<IpNet>,
    pub transport_bypasses: Vec<IpAddr>,
    pub local_lan_bypasses: Vec<IpNet>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    version: u32,
    pub id: u64,
    op: String,
    setup: Option<SetupWire>,
    routes: Option<RoutePlanWire>,
    exit_routes: Option<ExitPlanWire>,
    dns: Option<DnsWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupWire {
    #[serde(default)]
    name: String,
    #[serde(default)]
    mtu: u16,
    #[serde(default)]
    addresses: Option<Vec<IpNet>>,
    routes: Option<RoutePlanWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteWire {
    prefix: IpNet,
    #[serde(default)]
    metric: u32,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutePlanWire {
    routes: Option<Vec<RouteWire>>,
    bypasses: Option<Vec<IpAddr>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExitPlanWire {
    tunnel_prefixes: Option<Vec<IpNet>>,
    transport_bypasses: Option<Vec<IpAddr>>,
    local_lan_bypasses: Option<Vec<IpNet>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsWire {
    servers: Option<Vec<IpAddr>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Operation {
    Setup(Setup),
    ApplyRoutes(RoutePlan),
    ApplyExit(ExitPlan),
    RestoreExit,
    ApplyDns(Vec<IpAddr>),
    RestoreDns,
    Close,
}

impl Request {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_MESSAGE, "oversized helper request");
        let request: Self = serde_json::from_slice(bytes).context("invalid helper JSON")?;
        ensure!(
            request.version == VERSION && request.id != 0,
            "unsupported helper protocol or request ID"
        );
        Ok(request)
    }

    pub(super) fn is_close(&self) -> bool {
        self.op == "close"
    }

    pub(super) fn operation(self) -> Result<Operation> {
        match (
            self.op.as_str(),
            self.setup,
            self.routes,
            self.exit_routes,
            self.dns,
        ) {
            ("setup", Some(setup), None, None, None) => Ok(Operation::Setup(setup.validate()?)),
            ("apply-routes", None, Some(routes), None, None) => {
                Ok(Operation::ApplyRoutes(routes.validate()?))
            }
            ("apply-exit-routes", None, None, Some(exit), None) => {
                Ok(Operation::ApplyExit(exit.validate()?))
            }
            ("restore-exit-routes", None, None, None, None) => Ok(Operation::RestoreExit),
            ("apply-dns", None, None, None, Some(dns)) => {
                let servers = dns.servers.unwrap_or_default();
                ensure!(!servers.is_empty(), "DNS plan requires at least one server");
                Ok(Operation::ApplyDns(validate_addresses(
                    servers,
                    MAX_ADDRESSES,
                )?))
            }
            ("restore-dns", None, None, None, None) => Ok(Operation::RestoreDns),
            ("close", None, None, None, None) => Ok(Operation::Close),
            _ => bail!("unsupported helper operation or fields"),
        }
    }
}

impl SetupWire {
    fn validate(self) -> Result<Setup> {
        let name = if self.name.is_empty() {
            "lane0".into()
        } else {
            self.name
        };
        ensure!(valid_interface(&name), "invalid helper interface name");
        let mtu = if self.mtu == 0 { 1200 } else { self.mtu };
        ensure!(mtu >= 576, "invalid helper interface MTU");
        let addresses = self.addresses.unwrap_or_default();
        ensure!(
            addresses.len() <= MAX_ADDRESSES,
            "too many interface addresses"
        );
        let mut seen = BTreeSet::new();
        for prefix in &addresses {
            let address = prefix.addr();
            let bits = if address.is_ipv4() { 32 } else { 128 };
            ensure!(
                valid_unicast(address) && prefix.prefix_len() == bits && seen.insert(*prefix),
                "invalid or duplicate interface address"
            );
            ensure!(
                address.is_ipv4() || mtu >= 1280,
                "IPv6 requires MTU of at least 1280"
            );
        }
        let routes = self.routes.unwrap_or_default().validate()?;
        Ok(Setup {
            name,
            mtu,
            addresses,
            routes,
        })
    }
}

impl RoutePlanWire {
    fn validate(self) -> Result<RoutePlan> {
        let routes = self.routes.unwrap_or_default();
        ensure!(routes.len() <= MAX_ROUTES, "too many helper routes");
        let transport_bypasses =
            validate_addresses(self.bypasses.unwrap_or_default(), MAX_BYPASSES)?;
        let mut normalized = BTreeMap::new();
        for route in routes {
            validate_prefix(route.prefix)?;
            if transport_bypasses
                .iter()
                .any(|address| route.prefix.contains(address))
            {
                continue;
            }
            ensure!(
                normalized
                    .insert(route.prefix, route.metric)
                    .is_none_or(|old| old == route.metric),
                "conflicting duplicate helper route"
            );
        }
        let routes = normalized
            .into_iter()
            .map(|(prefix, metric)| Route { prefix, metric })
            .collect();
        Ok(RoutePlan {
            routes,
            transport_bypasses,
        })
    }
}

impl ExitPlanWire {
    fn validate(self) -> Result<ExitPlan> {
        let tunnel_prefixes = self.tunnel_prefixes.unwrap_or_default();
        let defaults = tunnel_prefixes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let v4 = ["0.0.0.0/1", "128.0.0.0/1"];
        let v6 = ["::/1", "8000::/1"];
        ensure!(
            defaults == v4 || defaults == v6 || defaults == [v4, v6].concat(),
            "invalid exit split defaults"
        );
        let mut transport_bypasses =
            validate_addresses(self.transport_bypasses.unwrap_or_default(), MAX_BYPASSES)?;
        ensure!(
            !transport_bypasses.is_empty(),
            "exit route plan requires a transport bypass"
        );
        transport_bypasses.sort_unstable();
        transport_bypasses.dedup();
        let mut local_lan_bypasses = self.local_lan_bypasses.unwrap_or_default();
        ensure!(
            local_lan_bypasses.len() <= MAX_BYPASSES,
            "too many local LAN bypasses"
        );
        for prefix in &local_lan_bypasses {
            validate_prefix(*prefix)?;
            ensure!(valid_unicast(prefix.addr()), "invalid local LAN bypass");
        }
        local_lan_bypasses.sort_unstable();
        local_lan_bypasses.dedup();
        Ok(ExitPlan {
            tunnel_prefixes,
            transport_bypasses,
            local_lan_bypasses,
        })
    }
}

fn validate_prefix(prefix: IpNet) -> Result<()> {
    ensure!(
        prefix.prefix_len() != 0 && prefix == prefix.trunc() && !mapped(prefix.addr()),
        "route requires a canonical non-default IPv4 or IPv6 prefix"
    );
    Ok(())
}

fn valid_unicast(address: IpAddr) -> bool {
    !mapped(address) && !address.is_unspecified() && !address.is_multicast()
}

fn validate_addresses(addresses: Vec<IpAddr>, limit: usize) -> Result<Vec<IpAddr>> {
    ensure!(addresses.len() <= limit, "too many helper addresses");
    ensure!(
        addresses.iter().copied().all(valid_unicast),
        "invalid helper unicast address"
    );
    Ok(addresses)
}

fn mapped(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(address) if address.to_ipv4_mapped().is_some())
}

pub(super) fn valid_interface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && !matches!(name, "." | "..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

#[derive(Serialize)]
pub(super) struct Reply<'a> {
    pub version: u32,
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub helper_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<&'a str>,
}
