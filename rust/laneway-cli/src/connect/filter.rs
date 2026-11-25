use std::{collections::HashSet, net::IpAddr};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use laneway_protocol::{
    Id,
    v1::{IpPrefix, NodeConfiguration, PolicyAction, RouteKind, TrafficSelector},
};

/// A host route bounded by the exact route issued by the controller.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct Selection {
    pub id: Id,
    pub prefix: IpNet,
}

pub(super) fn ip(raw: &[u8]) -> Result<IpAddr> {
    let address = match raw.len() {
        4 => IpAddr::from(<[u8; 4]>::try_from(raw)?),
        16 => IpAddr::from(<[u8; 16]>::try_from(raw)?),
        _ => bail!("controller returned an invalid IP address"),
    };
    ensure!(
        address.to_canonical() == address,
        "controller returned an IPv4-mapped IPv6 address"
    );
    Ok(address)
}

fn wire_prefix(prefix: &IpPrefix) -> Result<IpNet> {
    let prefix = IpNet::new(ip(&prefix.address)?, u8::try_from(prefix.prefix_length)?)?;
    ensure!(
        prefix == prefix.trunc(),
        "controller route has a noncanonical destination"
    );
    Ok(prefix)
}

pub(super) fn resolve_exit(
    configuration: &NodeConfiguration,
    selector: &str,
    local: Id,
) -> Result<Option<Id>> {
    if selector.is_empty() {
        return Ok(None);
    }
    let selected = match selector.parse::<Id>() {
        Ok(id) => Some(id),
        Err(_) => {
            let mut peers = configuration
                .peers
                .iter()
                .filter(|peer| peer.name == selector)
                .filter_map(|peer| Id::from_slice(&peer.node_id).ok());
            let selected = peers.next();
            ensure!(
                peers.next().is_none(),
                "exit name {selector:?} is ambiguous"
            );
            selected
        }
    };
    let selected = selected.filter(|id| *id != local).with_context(|| {
        format!("exit {selector:?} does not identify a different controller peer")
    })?;
    ensure!(
        exit_is_authorized(configuration, selected),
        "exit {selector:?} is not controller-authorized"
    );
    ensure!(
        configuration
            .routes
            .as_ref()
            .is_some_and(|snapshot| snapshot
                .routes
                .iter()
                .any(|route| route.kind() == RouteKind::Exit
                    && route.via_node_id == selected.as_bytes())),
        "exit {selector:?} has no approved exit route"
    );
    Ok(Some(selected))
}

fn exit_is_authorized(configuration: &NodeConfiguration, selected: Id) -> bool {
    configuration.exit_policy.as_ref().is_some_and(|policy| {
        policy
            .authorized_node_ids
            .iter()
            .any(|value| value == selected.as_bytes())
    })
}

pub(super) fn select(
    configuration: &NodeConfiguration,
    local: Id,
    requested: &[IpNet],
    selected_exit: Option<Id>,
    authorized_private_routes: bool,
) -> Result<Vec<Selection>> {
    let snapshot = configuration
        .routes
        .as_ref()
        .context("controller configuration is incomplete")?;
    let policy = if authorized_private_routes {
        Some(
            configuration
                .policy
                .as_ref()
                .context("controller configuration is incomplete")?,
        )
    } else {
        None
    };
    let mut selections = Vec::new();
    let mut seen = HashSet::new();
    let mut matched = HashSet::new();
    let mut has_exit = false;

    for route in &snapshot.routes {
        let kind = route.kind();
        if kind == RouteKind::Unspecified {
            continue;
        }
        let destination = wire_prefix(
            route
                .destination
                .as_ref()
                .context("controller route has no destination")?,
        )?;
        let via = Id::from_slice(&route.via_node_id)
            .context("controller route has invalid peer identity")?;
        let mut retain = |prefix| -> Result<()> {
            if seen.insert((prefix, via)) {
                selections.push(Selection {
                    id: Id::from_slice(&route.route_id)
                        .context("controller route has invalid ID")?,
                    prefix,
                });
            }
            Ok(())
        };
        match kind {
            RouteKind::Overlay => retain(destination)?,
            RouteKind::Subnet if via != local => {
                if let Some(policy) = policy {
                    if destination.prefix_len() == 0 {
                        continue;
                    }
                    for rule in &policy.rules {
                        if rule.action() != PolicyAction::Accept {
                            continue;
                        }
                        let Some(selector) = &rule.selector else {
                            continue;
                        };
                        if !source_matches(selector, &configuration.overlay_addresses, local)
                            || !id_matches(&selector.destination_node_ids, via)
                        {
                            continue;
                        }
                        if selector.destination_prefixes.is_empty() {
                            retain(destination)?;
                        }
                        for prefix in &selector.destination_prefixes {
                            let Ok(prefix) = wire_prefix(prefix) else {
                                continue;
                            };
                            if prefix.prefix_len() == 0 {
                                continue;
                            }
                            if let Some(intersection) = overlap(destination, prefix) {
                                retain(intersection)?;
                            }
                        }
                    }
                } else if requested.contains(&destination) {
                    retain(destination)?;
                    matched.insert(destination);
                }
            }
            RouteKind::Exit if Some(via) == selected_exit => {
                retain(destination)?;
                has_exit = true;
            }
            _ => {}
        }
    }

    if let Some(missing) = requested.iter().find(|prefix| !matched.contains(*prefix)) {
        bail!("requested route {missing} is no longer controller-authorized");
    }
    if let Some(selected) = selected_exit {
        ensure!(has_exit, "selected exit is no longer controller-authorized");
        ensure!(
            exit_is_authorized(configuration, selected),
            "selected exit was withdrawn from controller exit policy"
        );
    }
    Ok(selections)
}

fn id_matches(ids: &[Vec<u8>], id: Id) -> bool {
    ids.is_empty() || ids.iter().any(|value| value == id.as_bytes())
}

fn source_matches(selector: &TrafficSelector, overlays: &[Vec<u8>], local: Id) -> bool {
    id_matches(&selector.source_node_ids, local)
        && (selector.source_prefixes.is_empty()
            || selector
                .source_prefixes
                .iter()
                .filter_map(|prefix| wire_prefix(prefix).ok())
                .any(|prefix| {
                    overlays
                        .iter()
                        .filter_map(|raw| ip(raw).ok())
                        .any(|addr| prefix.contains(&addr))
                }))
}

pub(super) fn overlap(first: IpNet, second: IpNet) -> Option<IpNet> {
    if first.prefix_len() <= second.prefix_len() && first.contains(&second.addr()) {
        Some(second)
    } else if second.prefix_len() <= first.prefix_len() && second.contains(&first.addr()) {
        Some(first)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use laneway_protocol::v1::{
        ExitNodePolicy, NodePeer, PolicyRule, PolicySnapshot, Route, RouteSnapshot,
    };

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn prefix(value: &str) -> IpPrefix {
        let network: IpNet = value.parse().unwrap();
        let address = match network.addr() {
            IpAddr::V4(value) => value.octets().to_vec(),
            IpAddr::V6(value) => value.octets().to_vec(),
        };
        IpPrefix {
            address,
            prefix_length: u32::from(network.prefix_len()),
        }
    }

    fn route(kind: RouteKind, via: Id, route_id: Id, destination: &str) -> Route {
        Route {
            destination: Some(prefix(destination)),
            via_node_id: via.as_bytes().to_vec(),
            kind: kind as i32,
            route_id: route_id.as_bytes().to_vec(),
            ..Default::default()
        }
    }

    fn rules(source: Id, destination: Id, prefix_value: &str) -> PolicyRule {
        PolicyRule {
            action: PolicyAction::Accept as i32,
            selector: Some(TrafficSelector {
                source_node_ids: vec![source.as_bytes().to_vec()],
                source_prefixes: vec![prefix("100.96.0.0/24")],
                destination_node_ids: vec![destination.as_bytes().to_vec()],
                destination_prefixes: vec![prefix(prefix_value)],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn configuration() -> NodeConfiguration {
        NodeConfiguration {
            overlay_addresses: vec![vec![100, 96, 0, 10]],
            routes: Some(RouteSnapshot {
                routes: vec![
                    route(RouteKind::Overlay, id(2), id(10), "100.96.0.2/32"),
                    route(RouteKind::Subnet, id(2), id(11), "192.168.0.0/16"),
                    route(RouteKind::Subnet, id(1), id(12), "10.0.0.0/8"),
                    route(RouteKind::Exit, id(2), id(13), "0.0.0.0/0"),
                ],
                ..Default::default()
            }),
            policy: Some(PolicySnapshot {
                rules: vec![
                    rules(id(1), id(2), "192.168.8.0/24"),
                    rules(id(1), id(2), "192.168.9.0/24"),
                    rules(id(3), id(2), "192.168.10.0/24"),
                    rules(id(1), id(3), "192.168.11.0/24"),
                ],
                ..Default::default()
            }),
            exit_policy: Some(ExitNodePolicy {
                authorized_node_ids: vec![id(2).as_bytes().to_vec()],
            }),
            peers: vec![NodePeer {
                node_id: id(2).as_bytes().to_vec(),
                name: "gateway".to_owned(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn saved_remembered_routes_preserve_signed_route_ids_but_narrow_prefixes() {
        let snapshot = configuration();
        let routes = select(&snapshot, id(1), &[], None, true).unwrap();
        let describe = |route: Selection| (route.id, route.prefix.to_string());
        assert_eq!(
            routes.into_iter().map(describe).collect::<Vec<_>>(),
            vec![
                (id(10), "100.96.0.2/32".to_owned()),
                (id(11), "192.168.8.0/24".to_owned()),
                (id(11), "192.168.9.0/24".to_owned())
            ]
        );
        assert_eq!(select(&snapshot, id(1), &[], None, false).unwrap().len(), 1);
    }

    #[test]
    fn explicit_subnets_and_exit_are_rechecked_on_updates() {
        let mut snapshot = configuration();
        let requested = ["192.168.0.0/16".parse().unwrap()];
        let exit = resolve_exit(&snapshot, "gateway", id(1)).unwrap();
        assert_eq!(exit, Some(id(2)));
        assert_eq!(
            select(&snapshot, id(1), &requested, exit, false)
                .unwrap()
                .len(),
            3
        );
        assert!(
            select(
                &snapshot,
                id(1),
                &["192.168.8.0/24".parse().unwrap()],
                exit,
                false
            )
            .is_err()
        );
        snapshot
            .exit_policy
            .as_mut()
            .unwrap()
            .authorized_node_ids
            .clear();
        assert!(select(&snapshot, id(1), &requested, exit, false).is_err());
        snapshot
            .routes
            .as_mut()
            .unwrap()
            .routes
            .retain(|route| route.kind() != RouteKind::Subnet);
        assert!(select(&snapshot, id(1), &requested, None, false).is_err());
    }
}
