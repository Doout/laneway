use std::{
    collections::{HashMap, HashSet},
    fs::File,
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use laneway_protocol::{
    Id,
    v1::{NodeConfiguration, RouteKind},
};

use crate::controller::Snapshot;

const MAX_SESSION_ROUTES: usize = 65_536;

/// Local route selection from a validated, controller-authenticated snapshot.
pub type ConfigurationFilter =
    Arc<dyn Fn(&NodeConfiguration) -> Result<Vec<SessionRoute>> + Send + Sync>;

/// A signed controller route selected for this local user session.
pub struct SessionRoute {
    /// The controller route ID whose next hop and metric will be preserved.
    pub id: Id,
    /// The unchanged destination or a narrower prefix within it.
    pub prefix: IpNet,
}

/// Active user session networking reported only after a carrier is available.
pub struct SessionStatus {
    /// Display name from current controller authority.
    pub name: String,
    /// Assigned host overlay addresses.
    pub overlays: Vec<IpNet>,
    /// User-selected subnet routes currently owned by this session.
    pub owned_routes: Vec<IpNet>,
    /// Ephemeral identity expiration, or zero for remembered users.
    pub identity_lease_expires_at: u64,
    /// Active packet carrier.
    pub path: &'static str,
}

/// Complete operating-system exit policy for a foreground user session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionExitPlan {
    /// The two split-default prefixes for each authorized address family.
    pub tunnel_prefixes: Vec<IpNet>,
    /// Authenticated control and transport endpoints routed over the native network.
    pub transport_bypasses: Vec<IpAddr>,
    /// User-selected local networks routed over the native network.
    pub local_lan_bypasses: Vec<IpNet>,
    /// DNS servers owned on the tunnel link while exit routing is active.
    pub dns_servers: Vec<IpAddr>,
}

/// Owner of operating-system route changes for an adopted packet device.
pub trait SessionRoutes: Send + Sync {
    /// Replaces the session's split routes and transport bypasses transactionally.
    fn apply<'a>(
        &'a mut self,
        routes: &'a [crate::RouteConfig],
        bypasses: &'a [IpAddr],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

    /// Applies helper-owned exit routing and DNS as one transaction, or restores both.
    fn apply_exit<'a>(
        &'a mut self,
        plan: Option<&'a SessionExitPlan>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            ensure!(
                plan.is_none(),
                "this session network owner supports split routes only"
            );
            Ok(())
        })
    }

    /// Restores the external network state and closes its privileged session.
    fn close(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Completes if the external network owner stops unexpectedly.
    fn stopped(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>;
}

/// Nonblocking packet descriptor and its companion route owner.
pub struct SessionNetwork {
    /// An open nonblocking packet descriptor. Linux uses raw IP datagrams,
    /// while macOS uses the four-byte Darwin utun family prefix.
    pub packet: File,
    /// The actual utun interface returned by the privileged Darwin helper.
    #[cfg(target_os = "macos")]
    pub interface_name: String,
    /// The privilege boundary that owns session routes and cleanup.
    pub routes: Box<dyn SessionRoutes>,
}

/// Opens an external packet device after the first trusted snapshot is ready.
pub trait SessionNetworkOpener: Send + Sync {
    /// Starts the privilege endpoint and installs the initial split routes.
    fn open<'a>(
        &'a self,
        config: &'a crate::TunConfig,
        routes: &'a [crate::RouteConfig],
        bypasses: &'a [IpAddr],
    ) -> Pin<Box<dyn Future<Output = Result<SessionNetwork>> + Send + 'a>>;
}

impl Snapshot {
    pub(crate) fn filter_session(&mut self, selected: Vec<SessionRoute>, local: Id) -> Result<()> {
        ensure!(
            selected.len() <= MAX_SESSION_ROUTES,
            "session selected too many routes"
        );
        let routes: HashMap<_, _> = self.routes.iter().map(|route| (route.id, route)).collect();
        let mut route_keys = HashSet::new();
        let mut requested = HashSet::new();
        let mut exits = HashSet::new();
        let mut retained = Vec::with_capacity(selected.len());
        for selection in selected {
            let route = routes
                .get(&selection.id)
                .context("session selected an unknown controller route")?;
            let prefix = selection.prefix;
            ensure!(
                prefix == prefix.trunc(),
                "session route prefix is not canonical"
            );
            ensure!(
                route.kind != RouteKind::Subnet || route.via != local,
                "a user session cannot serve a local subnet"
            );
            ensure!(
                prefix == route.destination
                    || (route.kind == RouteKind::Subnet
                        && prefix.prefix_len() > route.destination.prefix_len()
                        && route.destination.contains(&prefix)),
                "session route selection exceeds controller coverage"
            );
            if !requested.insert((route.id, prefix)) {
                continue;
            }
            ensure!(
                route_keys.insert((prefix, route.metric)),
                "session selected ambiguous routes"
            );
            if route.kind == RouteKind::Exit {
                ensure!(
                    route.via != local && self.authorized_exits.contains(&route.via),
                    "session selected an unauthorized exit"
                );
                exits.insert(route.via);
            }
            let mut narrowed = (**route).clone();
            narrowed.destination = prefix;
            retained.push(narrowed);
        }
        ensure!(
            self.routes
                .iter()
                .filter(|route| route.kind == RouteKind::Overlay && route.via == local)
                .all(|route| requested.contains(&(route.id, route.destination))),
            "session excluded a local overlay route"
        );
        self.routes = retained;
        self.authorized_exits.retain(|exit| exits.contains(exit));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use laneway_protocol::{
        policy::CompiledPolicy,
        v1::{PolicyAction, PolicySnapshot, RouteAdvertisementMode},
    };

    use super::*;
    use crate::controller::{CandidateExchangeAuthority, Route};

    fn identifier(value: u8) -> Id {
        Id::new([value; 16]).unwrap()
    }

    fn snapshot() -> Snapshot {
        let network = identifier(1);
        Snapshot {
            epoch: 1,
            valid_until: u64::MAX,
            identity_lease_expires_at: 0,
            overlays: vec!["100.64.0.1/32".parse().unwrap()],
            peers: HashMap::new(),
            routes: vec![
                Route {
                    id: identifier(4),
                    destination: "100.64.0.1/32".parse().unwrap(),
                    via: identifier(2),
                    kind: RouteKind::Overlay,
                    mode: RouteAdvertisementMode::Unspecified,
                    metric: 10,
                },
                Route {
                    id: identifier(5),
                    destination: "192.0.2.0/24".parse().unwrap(),
                    via: identifier(3),
                    kind: RouteKind::Subnet,
                    mode: RouteAdvertisementMode::Nat,
                    metric: 20,
                },
                Route {
                    id: identifier(6),
                    destination: "0.0.0.0/0".parse().unwrap(),
                    via: identifier(3),
                    kind: RouteKind::Exit,
                    mode: RouteAdvertisementMode::Nat,
                    metric: 30,
                },
            ],
            policy: CompiledPolicy::compile(
                PolicySnapshot {
                    network_id: network.as_bytes().to_vec(),
                    configuration_epoch: 1,
                    default_action: PolicyAction::Deny as i32,
                    ..Default::default()
                },
                network,
                1,
            )
            .unwrap(),
            enabled_capabilities: 0,
            revoked_serials: HashSet::new(),
            local_certificate_revoked: false,
            relays: HashMap::new(),
            candidate_exchange: CandidateExchangeAuthority {
                enabled: false,
                max_candidates: 0,
                ttl: std::time::Duration::ZERO,
            },
            authorized_exits: HashSet::from([identifier(3)]),
            certificate_renew_after: 0,
            certificate_not_after: u64::MAX,
        }
    }

    fn select(id: u8, prefix: &str) -> SessionRoute {
        SessionRoute {
            id: identifier(id),
            prefix: prefix.parse().unwrap(),
        }
    }

    #[test]
    fn narrowing_preserves_controller_gateway_metric_and_policy() {
        let mut snapshot = snapshot();
        snapshot
            .filter_session(
                vec![
                    select(4, "100.64.0.1/32"),
                    select(5, "192.0.2.8/32"),
                    select(5, "192.0.2.16/28"),
                ],
                identifier(2),
            )
            .unwrap();

        assert_eq!(snapshot.routes.len(), 3);
        assert_eq!(
            snapshot.routes[1].destination,
            "192.0.2.8/32".parse().unwrap()
        );
        assert_eq!(snapshot.routes[1].via, identifier(3));
        assert_eq!(snapshot.routes[1].metric, 20);
        assert!(!snapshot.policy.default_accepts());
        assert!(snapshot.authorized_exits.is_empty());
    }

    #[test]
    fn rejects_coverage_expansion_or_omission_of_local_identity() {
        for bad in [
            vec![select(4, "100.64.0.1/32"), select(5, "192.0.0.0/16")],
            vec![select(4, "100.64.0.1/32"), select(5, "2001:db8::1/128")],
            vec![select(5, "192.0.2.8/32")],
            vec![select(4, "100.64.0.1/32"), select(6, "0.0.0.0/1")],
        ] {
            let mut snapshot = snapshot();
            let previous = snapshot.routes.clone();
            assert!(snapshot.filter_session(bad, identifier(2)).is_err());
            assert_eq!(snapshot.routes, previous);
            assert_eq!(snapshot.authorized_exits, HashSet::from([identifier(3)]));
        }
    }
}
