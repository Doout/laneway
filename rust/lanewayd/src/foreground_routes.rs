//! Restrict host route ownership without changing the authenticated traffic policy.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use ipnet::IpNet;
use laneway_protocol::{Id, policy::CompiledPolicy, v1::RouteKind};

use crate::{
    config::{ForegroundRoutes, MAX_FOREGROUND_ROUTES},
    controller::{Route, Snapshot},
};

pub(crate) fn select(
    scope: &ForegroundRoutes,
    snapshot: &Snapshot,
    local: Id,
) -> Result<Vec<Route>> {
    select_routes(
        scope,
        &snapshot.routes,
        &snapshot.policy,
        &snapshot.overlays,
        local,
    )
}

fn select_routes(
    scope: &ForegroundRoutes,
    routes: &[Route],
    policy: &CompiledPolicy,
    overlays: &[IpNet],
    local: Id,
) -> Result<Vec<Route>> {
    let mut selected = BTreeMap::<(IpNet, Id), Route>::new();
    let wanted: BTreeSet<_> = scope.requested.iter().copied().collect();
    let mut requested = wanted.clone();
    let mut insert = |route: &Route, prefix: IpNet| -> Result<()> {
        selected
            .entry((prefix, route.via))
            .and_modify(|prior| {
                if route.metric < prior.metric {
                    prior.metric = route.metric;
                }
            })
            .or_insert_with(|| Route {
                destination: prefix,
                ..route.clone()
            });
        ensure!(
            selected.len() <= MAX_FOREGROUND_ROUTES,
            "foreground route limit exceeded"
        );
        Ok(())
    };

    let permits: Vec<_> = if scope.policy_private {
        policy
            .rules()
            .iter()
            .filter(|rule| {
                rule.accepts()
                    && (rule.source_nodes().is_empty() || rule.source_nodes().contains(&local))
                    && (rule.source_prefixes().is_empty()
                        || overlays.iter().any(|overlay| {
                            rule.source_prefixes()
                                .iter()
                                .any(|prefix| prefix.contains(&overlay.addr()))
                        }))
            })
            .collect()
    } else {
        Vec::new()
    };
    for route in routes.iter().filter(|route| route.via != local) {
        match route.kind {
            RouteKind::Overlay => insert(route, route.destination)?,
            RouteKind::Subnet if route.destination.prefix_len() != 0 => {
                if wanted.contains(&route.destination) {
                    requested.remove(&route.destination);
                    insert(route, route.destination)?;
                }
                for rule in &permits {
                    if !rule.destination_nodes().is_empty()
                        && !rule.destination_nodes().contains(&route.via)
                    {
                        continue;
                    }
                    if rule.destination_prefixes().is_empty() {
                        insert(route, route.destination)?;
                        break;
                    }
                    for prefix in rule.destination_prefixes() {
                        if let Some(intersection) = intersection(route.destination, *prefix) {
                            insert(route, intersection)?;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(missing) = requested.first() {
        anyhow::bail!("requested route {missing} is no longer controller-authorized");
    }
    Ok(selected.into_values().collect())
}

fn intersection(route: IpNet, permit: IpNet) -> Option<IpNet> {
    if permit.prefix_len() == 0 {
        return None;
    }
    if route.contains(&permit) {
        Some(permit)
    } else if permit.contains(&route) {
        Some(route)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use laneway_protocol::v1::{
        IpPrefix, IpProtocol, PolicyAction, PolicyRule, PolicySnapshot, RouteAdvertisementMode,
        TrafficSelector,
    };

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn route(prefix: &str, via: u8, kind: RouteKind, metric: u32) -> Route {
        Route {
            id: id(via),
            destination: prefix.parse().unwrap(),
            via: id(via),
            kind,
            mode: RouteAdvertisementMode::Unspecified,
            metric,
        }
    }

    fn wire_prefix(prefix: &str) -> IpPrefix {
        let parsed: IpNet = prefix.parse().unwrap();
        let address = match parsed {
            IpNet::V4(v4) => v4.addr().octets().to_vec(),
            IpNet::V6(v6) => v6.addr().octets().to_vec(),
        };
        IpPrefix {
            address,
            prefix_length: u32::from(parsed.prefix_len()),
        }
    }

    fn policy() -> CompiledPolicy {
        let rule = |byte, source, destination, prefix, action| PolicyRule {
            rule_id: id(byte).as_bytes().to_vec(),
            action: action as i32,
            selector: Some(TrafficSelector {
                source_node_ids: vec![id(source).as_bytes().to_vec()],
                source_prefixes: vec![wire_prefix("100.96.0.0/24")],
                destination_node_ids: vec![id(destination).as_bytes().to_vec()],
                destination_prefixes: vec![wire_prefix(prefix)],
                ip_protocol: IpProtocol::Tcp as i32,
                ..Default::default()
            }),
            ..Default::default()
        };
        CompiledPolicy::compile(
            PolicySnapshot {
                network_id: id(7).as_bytes().to_vec(),
                configuration_epoch: 1,
                default_action: PolicyAction::Deny as i32,
                rules: vec![
                    rule(10, 1, 2, "10.20.1.0/24", PolicyAction::Accept),
                    rule(11, 1, 2, "10.20.2.0/24", PolicyAction::Deny),
                    rule(12, 3, 2, "10.20.3.0/24", PolicyAction::Accept),
                    rule(13, 1, 4, "10.20.4.0/24", PolicyAction::Accept),
                    rule(14, 1, 2, "2001:db8::/32", PolicyAction::Accept),
                ],
            },
            id(7),
            1,
        )
        .unwrap()
    }

    #[test]
    fn remembered_and_ephemeral_route_scopes_match_only_applicable_policy() {
        let routes = [
            route("100.96.0.1/32", 1, RouteKind::Overlay, 0),
            route("100.96.0.2/32", 2, RouteKind::Overlay, 0),
            route("10.20.0.0/16", 2, RouteKind::Subnet, 20),
            route("10.20.0.0/16", 2, RouteKind::Subnet, 10),
            route("10.20.1.0/24", 3, RouteKind::Subnet, 0),
            route("0.0.0.0/0", 2, RouteKind::Exit, 0),
            route("::/0", 2, RouteKind::Exit, 0),
        ];
        let local: IpNet = "100.96.0.1/32".parse().unwrap();
        let profile = ForegroundRoutes {
            policy_private: true,
            requested: vec![],
        };
        let policy = policy();
        let selected = select_routes(&profile, &routes, &policy, &[local], id(1)).unwrap();
        assert_eq!(
            selected,
            [
                route("10.20.1.0/24", 2, RouteKind::Subnet, 10),
                routes[1].clone()
            ]
        );
        let other_source = "100.96.1.1/32".parse().unwrap();
        assert_eq!(
            select_routes(&profile, &routes, &policy, &[other_source], id(1)).unwrap(),
            [routes[1].clone()]
        );
        let ephemeral = ForegroundRoutes {
            policy_private: false,
            requested: vec![],
        };
        assert_eq!(
            select_routes(&ephemeral, &routes, &policy, &[local], id(1)).unwrap(),
            [routes[1].clone()]
        );
    }

    #[test]
    fn explicit_route_requires_exact_remote_advertisement_on_each_snapshot() {
        let wanted = route("10.20.0.0/16", 2, RouteKind::Subnet, 10);
        let scoped = ForegroundRoutes {
            policy_private: false,
            requested: vec![wanted.destination],
        };
        assert_eq!(
            select_routes(
                &scoped,
                std::slice::from_ref(&wanted),
                &policy(),
                &[],
                id(1)
            )
            .unwrap(),
            [wanted]
        );
        let replacement = route("10.20.0.0/24", 2, RouteKind::Subnet, 10);
        let local_only = route("10.20.0.0/16", 1, RouteKind::Subnet, 10);
        assert!(
            select_routes(&scoped, &[replacement, local_only], &policy(), &[], id(1))
                .unwrap_err()
                .to_string()
                .contains("no longer controller-authorized")
        );
    }
}
