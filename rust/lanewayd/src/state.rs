use std::{
    collections::HashMap,
    sync::{Arc, atomic::AtomicBool},
};

use arc_swap::{ArcSwap, ArcSwapOption};
use laneway_protocol::Id;
use quinn::Connection;

use crate::{
    controller::{CandidateExchangeAuthority, Snapshot},
    routing::RoutingTable,
};

/// One relay-local directional route handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle {
    /// Nonzero relay handle.
    pub value: u32,
    /// Negotiated maximum packet payload.
    pub max_payload: usize,
}

/// Atomically replaced relay binding snapshot.
#[derive(Clone, Debug, Default)]
pub struct Handles {
    /// Outbound handle selected by peer node.
    pub outbound: HashMap<Id, Handle>,
    /// Authenticated peer selected by inbound handle.
    pub inbound: HashMap<u32, Id>,
}

/// An authenticated direct carrier and the canonical leaf-certificate serial
/// checked against every controller revocation snapshot.
#[derive(Clone, Debug)]
pub struct DirectPath {
    /// Live QUIC connection.
    pub connection: Connection,
    /// Canonical unsigned leaf certificate serial.
    pub certificate_serial: Vec<u8>,
    /// Ensures a failed carrier is logged at most once before it is detached.
    pub(crate) send_failure_reported: Arc<AtomicBool>,
}

/// Read-mostly path and route state used by the packet hot path.
pub struct State {
    /// Immutable routing snapshot.
    pub routes: ArcSwap<RoutingTable>,
    /// Current relay handle snapshot.
    pub handles: ArcSwap<Handles>,
    /// Current authenticated direct connections keyed by peer.
    pub direct: ArcSwap<HashMap<Id, DirectPath>>,
    authority: ArcSwapOption<Snapshot>,
    controller_managed: bool,
    local_node: Option<Id>,
}

impl State {
    /// Creates empty carrier state around one compiled route table.
    pub fn new(routes: RoutingTable) -> Self {
        Self::with_controller(routes, false, None)
    }

    /// Creates fail-closed carrier state awaiting controller publication.
    pub fn controller(routes: RoutingTable, local_node: Id) -> Self {
        Self::with_controller(routes, true, Some(local_node))
    }

    fn with_controller(
        routes: RoutingTable,
        controller_managed: bool,
        local_node: Option<Id>,
    ) -> Self {
        Self {
            routes: ArcSwap::from_pointee(routes),
            handles: ArcSwap::from_pointee(Handles::default()),
            direct: ArcSwap::from_pointee(HashMap::new()),
            authority: ArcSwapOption::empty(),
            controller_managed,
            local_node,
        }
    }

    /// Publishes a complete authority snapshot and closes direct paths whose
    /// peer or certificate is no longer authorized.
    pub(crate) fn publish_authority(&self, snapshot: Arc<Snapshot>) {
        let paths = self.direct.swap(Arc::new(HashMap::new()));
        let mut retained = HashMap::new();
        for (peer, path) in paths.iter() {
            if snapshot.peers.contains_key(peer)
                && !snapshot.revoked_serials.contains(&path.certificate_serial)
            {
                retained.insert(*peer, path.clone());
            } else {
                path.connection
                    .close(0_u32.into(), b"controller authority removed");
            }
        }
        self.direct.store(Arc::new(retained));
        self.authority.store(Some(snapshot));
    }

    pub(crate) fn authority_snapshot(&self) -> Option<Arc<Snapshot>> {
        self.authority.load_full()
    }

    /// Returns the live candidate-exchange ceiling. Static mode has no
    /// controller ceiling; controller-managed mode fails closed while absent.
    pub(crate) fn candidate_exchange_authority(&self) -> Option<CandidateExchangeAuthority> {
        self.authority_snapshot()
            .filter(|snapshot| !snapshot.expired())
            .map(|snapshot| snapshot.candidate_exchange)
    }

    pub(crate) fn candidate_exchange_enabled(&self) -> bool {
        if self.controller_managed {
            self.candidate_exchange_authority()
                .is_some_and(|policy| policy.enabled)
        } else {
            true
        }
    }

    pub(crate) fn relay_targets(&self) -> Option<Vec<(Id, std::net::SocketAddr)>> {
        if !self.controller_managed {
            return None;
        }
        let mut targets: Vec<_> = self
            .authority_snapshot()
            .filter(|snapshot| !snapshot.expired())
            .into_iter()
            .flat_map(|snapshot| {
                snapshot
                    .relays
                    .iter()
                    .flat_map(|(service, relay)| {
                        relay
                            .resolved
                            .iter()
                            .map(|address| (*service, *address))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        targets.sort_unstable();
        Some(targets)
    }

    pub(crate) fn relay_authorized(&self, service: Id, address: std::net::SocketAddr) -> bool {
        if !self.controller_managed {
            return true;
        }
        self.authority_snapshot().is_some_and(|snapshot| {
            !snapshot.expired() && snapshot.authorizes_relay(service, Some(address))
        })
    }

    /// Removes all dynamic authority, routes, relay handles, and direct paths.
    pub(crate) fn fail_close(&self) {
        self.authority.store(None);
        self.routes.store(Arc::new(
            RoutingTable::compile(&[]).expect("empty routes compile"),
        ));
        self.clear_handles();
        for path in self.direct.swap(Arc::new(HashMap::new())).values() {
            path.connection
                .close(0_u32.into(), b"controller authority expired");
        }
    }

    /// Checks the active controller ACL. Static configurations retain their
    /// established route/source validation behavior.
    pub(crate) fn allows(&self, source: Id, destination: Id, packet: &[u8]) -> bool {
        if !self.controller_managed {
            return true;
        }
        self.authority.load_full().is_some_and(|snapshot| {
            !snapshot.expired()
                && snapshot.peers.contains_key(&source)
                && snapshot.peers.contains_key(&destination)
                && snapshot.policy.allows(source, destination, packet)
        })
    }

    /// Checks whether a direct certificate path remains controller-authorized.
    pub(crate) fn direct_authorized(&self, peer: Id, serial: &[u8]) -> bool {
        if !self.controller_managed {
            return true;
        }
        self.authority.load_full().is_some_and(|snapshot| {
            !snapshot.expired()
                && snapshot.peers.contains_key(&peer)
                && !snapshot.revoked_serials.contains(serial)
        })
    }

    /// Reports whether a peer currently has either an authenticated direct
    /// carrier or a live relay/TCP route-handle binding.
    pub(crate) fn has_path(&self, peer: Id) -> bool {
        self.direct.load().contains_key(&peer) || self.handles.load().outbound.contains_key(&peer)
    }

    pub(crate) fn has_direct_path(&self, peer: Id) -> bool {
        self.direct.load().contains_key(&peer)
    }

    pub(crate) fn has_relay_path(&self, peer: Id) -> bool {
        self.handles.load().outbound.contains_key(&peer)
    }

    pub(crate) fn owns(&self, static_owned: &[ipnet::IpNet], address: std::net::IpAddr) -> bool {
        if !self.controller_managed {
            return crate::routing::locally_owned(static_owned, address);
        }
        let Some(snapshot) = self.authority.load_full() else {
            return false;
        };
        if snapshot.expired() {
            return false;
        }
        snapshot
            .overlays
            .iter()
            .any(|prefix| prefix.contains(&address))
            || snapshot.routes.iter().any(|route| {
                Some(route.via) == self.local_node
                    && route.kind == laneway_protocol::v1::RouteKind::Subnet
                    && route.destination.contains(&address)
            })
    }

    /// Adds or replaces a relay binding with one atomic snapshot publication.
    pub fn bind(&self, peer: Id, handle: Handle) {
        let mut next = (**self.handles.load()).clone();
        if let Some(previous) = next.outbound.insert(peer, handle) {
            next.inbound.remove(&previous.value);
        }
        if let Some(previous_peer) = next.inbound.insert(handle.value, peer) {
            next.outbound.remove(&previous_peer);
        }
        self.handles.store(Arc::new(next));
    }

    /// Removes a relay binding by its session-local handle.
    pub fn release(&self, handle: u32) {
        let mut next = (**self.handles.load()).clone();
        if let Some(peer) = next.inbound.remove(&handle) {
            next.outbound.remove(&peer);
        }
        self.handles.store(Arc::new(next));
    }

    /// Clears all bindings when a relay session ends.
    pub fn clear_handles(&self) {
        self.handles.store(Arc::new(Handles::default()));
    }

    /// Publishes an authenticated direct path.
    pub fn attach_direct(&self, peer: Id, connection: Connection, certificate_serial: Vec<u8>) {
        let stable_id = connection.stable_id();
        let previous_snapshot = self.direct.rcu(|current| {
            let mut next = (**current).clone();
            next.insert(
                peer,
                DirectPath {
                    connection: connection.clone(),
                    certificate_serial: certificate_serial.clone(),
                    send_failure_reported: Arc::new(AtomicBool::new(false)),
                },
            );
            Arc::new(next)
        });
        if let Some(previous) = previous_snapshot
            .get(&peer)
            .filter(|previous| previous.connection.stable_id() != stable_id)
        {
            previous
                .connection
                .close(0_u32.into(), b"direct path replaced");
        }
    }

    /// Removes a direct path only when it still refers to this connection.
    pub fn detach_direct(&self, peer: Id, stable_id: usize) {
        self.direct.rcu(|current| {
            if current
                .get(&peer)
                .is_some_and(|value| value.connection.stable_id() == stable_id)
            {
                let mut next = (**current).clone();
                next.remove(&peer);
                Arc::new(next)
            } else {
                Arc::clone(current)
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        str::FromStr,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use ipnet::IpNet;
    use laneway_protocol::{
        policy::CompiledPolicy,
        v1::{IpProtocol, PolicyAction, PolicyRule, PolicySnapshot, TrafficSelector},
    };

    #[test]
    fn rebinding_is_bidirectionally_consistent() {
        let state = State::new(RoutingTable::compile(&[]).unwrap());
        let peer = Id::from_str("202122232425262728292a2b2c2d2e2f").unwrap();
        state.bind(
            peer,
            Handle {
                value: 4,
                max_payload: 1200,
            },
        );
        state.bind(
            peer,
            Handle {
                value: 8,
                max_payload: 1100,
            },
        );
        let snapshot = state.handles.load();
        assert!(!snapshot.inbound.contains_key(&4));
        assert_eq!(snapshot.inbound.get(&8), Some(&peer));
        assert_eq!(snapshot.outbound[&peer].max_payload, 1100);
        state.release(8);
        assert!(state.handles.load().outbound.is_empty());
    }

    #[tokio::test]
    async fn renewed_snapshot_keeps_policy_and_ownership_active() {
        let network = Id::from_str("000102030405060708090a0b0c0d0e0f").unwrap();
        let local = Id::from_str("101112131415161718191a1b1c1d1e1f").unwrap();
        let peer = Id::from_str("202122232425262728292a2b2c2d2e2f").unwrap();
        let epoch = 9;
        let policy = CompiledPolicy::compile(
            PolicySnapshot {
                network_id: network.as_bytes().to_vec(),
                configuration_epoch: epoch,
                rules: vec![PolicyRule {
                    rule_id: Id::from_str("303132333435363738393a3b3c3d3e3f")
                        .unwrap()
                        .as_bytes()
                        .to_vec(),
                    description: "renewal coverage".into(),
                    priority: 1,
                    selector: Some(TrafficSelector {
                        source_node_ids: vec![peer.as_bytes().to_vec()],
                        destination_node_ids: vec![local.as_bytes().to_vec()],
                        ip_protocol: IpProtocol::Any as i32,
                        ..Default::default()
                    }),
                    action: PolicyAction::Accept as i32,
                }],
                default_action: PolicyAction::Deny as i32,
            },
            network,
            epoch,
        )
        .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let relay_a = Id::from_str("404142434445464748494a4b4c4d4e4f").unwrap();
        let relay_b = Id::from_str("505152535455565758595a5b5c5d5e5f").unwrap();
        let original = Arc::new(Snapshot {
            epoch,
            valid_until: now + 1,
            overlays: vec!["100.96.0.1/32".parse::<IpNet>().unwrap()],
            peers: HashMap::from([
                (
                    local,
                    crate::controller::Peer {
                        node: local,
                        name: "local".into(),
                        overlays: vec!["100.96.0.1".parse().unwrap()],
                    },
                ),
                (
                    peer,
                    crate::controller::Peer {
                        node: peer,
                        name: "peer".into(),
                        overlays: vec!["100.96.0.2".parse().unwrap()],
                    },
                ),
            ]),
            routes: Vec::new(),
            policy,
            enabled_capabilities: 0,
            revoked_serials: HashSet::new(),
            local_certificate_revoked: false,
            relays: HashMap::from([
                (
                    relay_b,
                    crate::controller::RelayAuthority {
                        endpoint: "127.0.0.1:4455".to_owned(),
                        resolved: vec!["127.0.0.1:4455".parse().unwrap()],
                    },
                ),
                (
                    relay_a,
                    crate::controller::RelayAuthority {
                        endpoint: "127.0.0.1:4433".to_owned(),
                        resolved: vec!["127.0.0.1:4433".parse().unwrap()],
                    },
                ),
            ]),
            candidate_exchange: crate::controller::CandidateExchangeAuthority {
                enabled: true,
                max_candidates: 8,
                ttl: Duration::from_secs(120),
            },
            authorized_exits: HashSet::new(),
            certificate_renew_after: u64::MAX - 1,
            certificate_not_after: u64::MAX,
        });
        let state = State::controller(RoutingTable::compile(&[]).unwrap(), local);
        state.publish_authority(Arc::clone(&original));
        assert_eq!(
            state.relay_targets().unwrap(),
            vec![
                (relay_a, "127.0.0.1:4433".parse().unwrap()),
                (relay_b, "127.0.0.1:4455".parse().unwrap()),
            ]
        );
        assert!(state.relay_authorized(relay_a, "127.0.0.1:4433".parse().unwrap()));
        let mut withdrawn = (*original).clone();
        withdrawn.relays.remove(&relay_a);
        state.publish_authority(Arc::new(withdrawn));
        assert!(!state.relay_authorized(relay_a, "127.0.0.1:4433".parse().unwrap()));
        state.publish_authority(Arc::new(original.renew(now + 4).unwrap()));
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[12..16].copy_from_slice(&[100, 96, 0, 2]);
        packet[16..20].copy_from_slice(&[100, 96, 0, 1]);
        assert!(state.owns(&[], "100.96.0.1".parse().unwrap()));
        assert!(state.allows(peer, local, &packet));
    }
}
