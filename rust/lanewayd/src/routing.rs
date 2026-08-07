use std::{net::IpAddr, str::FromStr};

use anyhow::{Result, bail, ensure};
use ipnet::IpNet;
use laneway_protocol::Id;

use crate::config::{RouteConfig, RouteKind};

/// Parsed source and destination from one complete raw IP packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketMeta {
    /// Packet source.
    pub source: IpAddr,
    /// Packet destination.
    pub destination: IpAddr,
}

/// Immutable forwarding entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// Canonical destination prefix.
    pub prefix: IpNet,
    /// Authenticated next-hop node.
    pub via: Id,
    /// Lower values are preferred for equal-length prefixes.
    pub metric: u32,
    /// Route class.
    pub kind: RouteKind,
}

/// Immutable longest-prefix-match routing snapshot.
#[derive(Clone, Debug)]
pub struct RoutingTable {
    routes: Vec<Route>,
}

impl RoutingTable {
    /// Compiles a validated, most-specific-first snapshot.
    pub fn compile(config: &[RouteConfig]) -> Result<Self> {
        let mut routes = Vec::with_capacity(config.len());
        for item in config {
            ensure!(item.prefix.trunc() == item.prefix, "noncanonical route");
            ensure!(
                !matches!(item.prefix, IpNet::V6(prefix) if prefix.addr().to_ipv4_mapped().is_some()),
                "IPv4-mapped IPv6 route"
            );
            routes.push(Route {
                prefix: item.prefix,
                via: Id::from_str(&item.via_node)?,
                metric: item.metric,
                kind: item.kind,
            });
        }
        routes.sort_by(|left, right| {
            right
                .prefix
                .prefix_len()
                .cmp(&left.prefix.prefix_len())
                .then_with(|| left.metric.cmp(&right.metric))
                .then_with(|| left.prefix.to_string().cmp(&right.prefix.to_string()))
        });
        for window in routes.windows(2) {
            ensure!(
                window[0].prefix != window[1].prefix || window[0].metric != window[1].metric,
                "ambiguous equal-prefix/equal-metric route"
            );
        }
        Ok(Self { routes })
    }

    /// Selects the most-specific route for an address without allocation.
    pub fn lookup(&self, address: IpAddr) -> Option<&Route> {
        self.routes
            .iter()
            .find(|route| route.prefix.contains(&address))
    }

    /// Confirms that `peer` owns the packet source according to this snapshot.
    pub fn authorizes_source(&self, peer: Id, source: IpAddr) -> bool {
        self.lookup(source).is_some_and(|route| route.via == peer)
    }

    /// Returns the compiled routes.
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }
}

/// Parses and validates a complete IPv4 or IPv6 packet.
pub fn packet_meta(packet: &[u8]) -> Result<PacketMeta> {
    match packet.first().map(|value| value >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            ensure!(
                header_len >= 20 && header_len <= packet.len(),
                "invalid IPv4 header"
            );
            ensure!(total == packet.len(), "invalid IPv4 total length");
            Ok(PacketMeta {
                source: IpAddr::from(<[u8; 4]>::try_from(&packet[12..16])?),
                destination: IpAddr::from(<[u8; 4]>::try_from(&packet[16..20])?),
            })
        }
        Some(6) if packet.len() >= 40 => {
            let payload = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            ensure!(payload + 40 == packet.len(), "invalid IPv6 payload length");
            Ok(PacketMeta {
                source: IpAddr::from(<[u8; 16]>::try_from(&packet[8..24])?),
                destination: IpAddr::from(<[u8; 16]>::try_from(&packet[24..40])?),
            })
        }
        _ => bail!("invalid IP packet"),
    }
}

/// Returns true when an address belongs to one of the local overlay/subnet
/// prefixes. This is the final inbound injection boundary.
pub fn locally_owned(prefixes: &[IpNet], address: IpAddr) -> bool {
    prefixes.iter().any(|prefix| prefix.contains(&address))
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, path::PathBuf};

    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct SelectionVectors {
        routes: Vec<SelectionRoute>,
        cases: Vec<SelectionCase>,
    }

    #[derive(Deserialize)]
    struct SelectionRoute {
        id: String,
        prefix: IpNet,
        metric: u32,
    }

    #[derive(Deserialize)]
    struct SelectionCase {
        destination: IpAddr,
        expected_route_id: String,
    }

    #[derive(Deserialize)]
    struct SemanticVectors {
        routes: Vec<SemanticRoute>,
        lookups: Vec<SemanticLookup>,
        source_authorization: Vec<SourceAuthorization>,
        invalid_sets: Vec<InvalidRouteSet>,
    }

    #[derive(Deserialize)]
    struct SemanticRoute {
        #[serde(default)]
        id: String,
        prefix: IpNet,
        metric: u32,
        next_hop: String,
        #[serde(rename = "handle")]
        _handle: u32,
    }

    #[derive(Deserialize)]
    struct SemanticLookup {
        name: String,
        destination: IpAddr,
        expected_route_id: Option<String>,
        expected: Option<String>,
    }

    #[derive(Deserialize)]
    struct SourceAuthorization {
        name: String,
        source: IpAddr,
        peer: String,
        expected: bool,
    }

    #[derive(Deserialize)]
    struct InvalidRouteSet {
        name: String,
        expected_error: String,
        routes: Vec<SemanticRoute>,
    }

    fn semantic_configs(routes: &[SemanticRoute]) -> Vec<RouteConfig> {
        routes
            .iter()
            .map(|route| RouteConfig {
                prefix: route.prefix,
                via_node: route.next_hop.clone(),
                metric: route.metric,
                kind: RouteKind::Overlay,
            })
            .collect()
    }

    fn v4(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn route(prefix: &str, peer: &str) -> RouteConfig {
        RouteConfig {
            prefix: prefix.parse().unwrap(),
            via_node: peer.into(),
            metric: 100,
            kind: RouteKind::Overlay,
        }
    }

    #[test]
    fn parses_packets_and_longest_prefix_wins() {
        let a = "202122232425262728292a2b2c2d2e2f";
        let b = "303132333435363738393a3b3c3d3e3f";
        let table =
            RoutingTable::compile(&[route("10.0.0.0/8", a), route("10.1.0.0/16", b)]).unwrap();
        let meta = packet_meta(&v4([10, 1, 2, 3], [10, 1, 4, 5])).unwrap();
        assert_eq!(table.lookup(meta.destination).unwrap().via.to_string(), b);
        assert!(table.authorizes_source(Id::from_str(b).unwrap(), meta.source));
    }

    #[test]
    fn rejects_truncation_and_length_smuggling() {
        assert!(packet_meta(&[0x45; 19]).is_err());
        let mut packet = v4([1, 1, 1, 1], [2, 2, 2, 2]);
        packet[2..4].copy_from_slice(&21_u16.to_be_bytes());
        assert!(packet_meta(&packet).is_err());
    }

    #[test]
    fn shared_route_selection_vectors_use_metric_after_prefix_length() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testvectors/routing/selection-cases.json");
        let vectors: SelectionVectors =
            serde_json::from_slice(&fs::read(path).expect("read selection vectors"))
                .expect("decode selection vectors");
        let peers = [
            "101112131415161718191a1b1c1d1e1f",
            "202122232425262728292a2b2c2d2e2f",
            "303132333435363738393a3b3c3d3e3f",
            "404142434445464748494a4b4c4d4e4f",
        ];
        let mut by_peer = HashMap::new();
        let routes = vectors
            .routes
            .iter()
            .zip(peers)
            .map(|(route, peer)| {
                let peer_id = Id::from_str(peer).expect("selection peer ID");
                by_peer.insert(peer_id, route.id.clone());
                RouteConfig {
                    prefix: route.prefix,
                    via_node: peer.to_owned(),
                    metric: route.metric,
                    kind: RouteKind::Overlay,
                }
            })
            .collect::<Vec<_>>();
        let table = RoutingTable::compile(&routes).expect("compile selection vectors");
        for case in vectors.cases {
            let selected = table.lookup(case.destination).expect("selected route");
            assert_eq!(by_peer.get(&selected.via), Some(&case.expected_route_id));
        }
    }

    #[test]
    fn shared_semantic_vectors_exercise_production_routing_table() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testvectors/routing/semantic-cases.json");
        let vectors: SemanticVectors =
            serde_json::from_slice(&fs::read(path).expect("read semantic vectors"))
                .expect("decode semantic vectors");
        let ids = vectors
            .routes
            .iter()
            .map(|route| (Id::from_str(&route.next_hop).unwrap(), route.id.as_str()))
            .collect::<HashMap<_, _>>();
        let table = RoutingTable::compile(&semantic_configs(&vectors.routes))
            .expect("compile semantic vectors");

        for case in vectors.lookups {
            let selected = table.lookup(case.destination);
            if case.expected.as_deref() == Some("no_match") {
                assert!(selected.is_none(), "{} unexpectedly matched", case.name);
            } else {
                assert_eq!(
                    selected.and_then(|route| ids.get(&route.via).copied()),
                    case.expected_route_id.as_deref(),
                    "{}",
                    case.name
                );
            }
        }
        for case in vectors.source_authorization {
            let peer = Id::from_str(&case.peer).expect("source peer");
            assert_eq!(
                table.authorizes_source(peer, case.source),
                case.expected,
                "{}",
                case.name
            );
        }
        for case in vectors.invalid_sets {
            let error = RoutingTable::compile(&semantic_configs(&case.routes))
                .expect_err(&format!("{} unexpectedly compiled", case.name));
            let actual = match error.to_string().as_str() {
                "ambiguous equal-prefix/equal-metric route" => "ambiguous_route",
                "noncanonical route" | "IPv4-mapped IPv6 route" => "invalid_prefix",
                other => panic!("{} unexpected routing error {other}", case.name),
            };
            assert_eq!(actual, case.expected_error, "{}", case.name);
        }
    }
}
