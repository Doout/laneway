use std::{collections::BTreeMap, net::IpAddr};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use laneway_protocol::{
    Id,
    v1::{
        IpPrefix, NodePeer, RelayEndpoint, RelayPeerAuthorization, Route, RouteAdvertisementMode,
        RouteKind,
    },
};
use rusqlite::{Connection, params};

const MAX_PEERS: usize = 65_536;
pub(super) const MAX_ROUTES: usize = 65_536;
const MAX_RELAYS: usize = 32;

pub(super) fn node_peers(db: &Connection, network: Id, now: i64) -> Result<Vec<NodePeer>> {
    let mut statement = db.prepare(
        "SELECT n.id,n.name,a.address,a6.address,n.enrollment_class,n.lease_expires_at,n.wireguard_public_key
         FROM nodes n LEFT JOIN overlay_addresses a ON a.id=(
           SELECT oa.id FROM overlay_addresses oa WHERE oa.node_id=n.id AND oa.network_id=n.network_id
           AND oa.released_at IS NULL AND length(oa.address)=4 ORDER BY oa.created_at DESC,oa.id DESC LIMIT 1)
         LEFT JOIN overlay_addresses a6 ON a6.id=(
           SELECT oa.id FROM overlay_addresses oa WHERE oa.node_id=n.id AND oa.network_id=n.network_id
           AND oa.released_at IS NULL AND length(oa.address)=16 ORDER BY oa.created_at DESC,oa.id DESC LIMIT 1)
         WHERE n.network_id=?1 AND n.revoked_at IS NULL AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?2)
         ORDER BY n.name,n.id LIMIT ?3",
    )?;
    let mut rows = statement.query(params![network.as_bytes().as_slice(), now, MAX_PEERS + 1])?;
    let mut peers = Vec::new();
    while let Some(row) = rows.next()? {
        ensure!(peers.len() < MAX_PEERS, "node peer directory exceeds limit");
        let id = Id::from_slice(&row.get::<_, Vec<u8>>(0)?)?;
        let name: String = row.get(1)?;
        let v4: Option<Vec<u8>> = row.get(2)?;
        let v6: Option<Vec<u8>> = row.get(3)?;
        let class: String = row.get(4)?;
        let lease: Option<i64> = row.get(5)?;
        let key: Option<Vec<u8>> = row.get(6)?;
        ensure!(
            matches!(class.as_str(), "durable" | "ephemeral" | "remembered")
                && (class == "ephemeral") == lease.is_some(),
            "invalid stored peer enrollment class or lease"
        );
        let v4 = v4.context("active node is missing IPv4 overlay")?;
        ensure!(
            unicast_overlay(&v4)?.is_ipv4(),
            "invalid stored IPv4 overlay"
        );
        let mut overlay_addresses = vec![v4];
        if let Some(address) = v6 {
            ensure!(
                unicast_overlay(&address)?.is_ipv6(),
                "invalid stored IPv6 overlay"
            );
            overlay_addresses.push(address);
        }
        let wireguard_public_key = key.unwrap_or_default();
        if !wireguard_public_key.is_empty() {
            ensure!(
                crate::enrollment::parse_wireguard(&wireguard_public_key)?.is_some(),
                "invalid stored WireGuard key"
            );
        }
        peers.push(NodePeer {
            node_id: id.as_bytes().to_vec(),
            name,
            overlay_addresses,
            wireguard_public_key,
        });
    }
    Ok(peers)
}

pub(super) fn overlay_routes(db: &Connection, network: Id, now: i64) -> Result<Vec<Route>> {
    let mut statement = db.prepare(
        "SELECT a.id,a.node_id,a.address,a.prefix_length FROM overlay_addresses a
         JOIN nodes n ON (n.id=a.node_id AND n.network_id=a.network_id)
         WHERE a.network_id=?1 AND a.released_at IS NULL AND n.revoked_at IS NULL
         AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?2)
         ORDER BY a.prefix_length DESC,a.address ASC,a.id ASC LIMIT ?3",
    )?;
    let mut rows = statement.query(params![network.as_bytes().as_slice(), now, MAX_ROUTES + 1])?;
    let mut routes = Vec::new();
    while let Some(row) = rows.next()? {
        ensure!(routes.len() < MAX_ROUTES, "overlay routes exceed limit");
        let address: Vec<u8> = row.get(2)?;
        let bits: u8 = row.get(3)?;
        let ip = unicast_overlay(&address)?;
        ensure!(
            bits == if ip.is_ipv4() { 32 } else { 128 },
            "stored overlay route must be a host prefix"
        );
        routes.push(Route {
            route_id: Id::from_slice(&row.get::<_, Vec<u8>>(0)?)?
                .as_bytes()
                .to_vec(),
            via_node_id: Id::from_slice(&row.get::<_, Vec<u8>>(1)?)?
                .as_bytes()
                .to_vec(),
            destination: Some(IpPrefix {
                address,
                prefix_length: bits.into(),
            }),
            kind: RouteKind::Overlay as i32,
            mode: RouteAdvertisementMode::Unspecified as i32,
            metric: 0,
        });
    }
    Ok(routes)
}

pub(super) fn approved_routes(db: &Connection, network: Id, now: i64) -> Result<Vec<Route>> {
    let mut statement = db.prepare(
        "SELECT r.id,r.node_id,r.prefix_address,r.prefix_length,r.kind,r.mode,r.metric
         FROM routes r JOIN nodes n ON (n.id=r.node_id AND n.network_id=r.network_id)
         WHERE r.network_id=?1 AND r.state='approved' AND (r.valid_until IS NULL OR r.valid_until>?2)
         AND n.revoked_at IS NULL AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?2)
         ORDER BY r.prefix_length DESC,r.metric ASC,r.id ASC LIMIT ?3",
    )?;
    let mut rows = statement.query(params![network.as_bytes().as_slice(), now, MAX_ROUTES + 1])?;
    let mut routes = Vec::new();
    while let Some(row) = rows.next()? {
        ensure!(routes.len() < MAX_ROUTES, "approved routes exceed limit");
        let address: Vec<u8> = row.get(2)?;
        let ip = decode_ip(&address)?;
        let bits: u8 = row.get(3)?;
        let prefix = IpNet::new(ip, bits)?;
        ensure!(prefix == prefix.trunc(), "noncanonical stored route prefix");
        let kind: String = row.get(4)?;
        let mode: String = row.get(5)?;
        let forwarding = match mode.as_str() {
            "none" => RouteAdvertisementMode::Unspecified,
            "nat" => RouteAdvertisementMode::Nat,
            "routed" => RouteAdvertisementMode::Routed,
            _ => bail!("invalid stored route mode"),
        };
        let kind = match kind.as_str() {
            "overlay"
                if forwarding == RouteAdvertisementMode::Unspecified
                    && prefix == IpNet::from(ip) =>
            {
                unicast_overlay(&address)?;
                RouteKind::Overlay
            }
            "subnet" if forwarding != RouteAdvertisementMode::Unspecified && bits != 0 => {
                RouteKind::Subnet
            }
            "exit" if forwarding != RouteAdvertisementMode::Unspecified && bits == 0 => {
                RouteKind::Exit
            }
            _ => bail!("invalid stored route kind or forwarding mode"),
        };
        routes.push(Route {
            route_id: Id::from_slice(&row.get::<_, Vec<u8>>(0)?)?
                .as_bytes()
                .to_vec(),
            via_node_id: Id::from_slice(&row.get::<_, Vec<u8>>(1)?)?
                .as_bytes()
                .to_vec(),
            destination: Some(IpPrefix {
                address,
                prefix_length: bits.into(),
            }),
            kind: kind as i32,
            mode: forwarding as i32,
            metric: row.get(6)?,
        });
    }
    Ok(routes)
}

pub(super) fn relay_peers(
    overlay: Vec<Route>,
    approved: Vec<Route>,
) -> Result<Vec<RelayPeerAuthorization>> {
    ensure!(
        overlay.len() + approved.len() <= MAX_ROUTES,
        "relay route directory exceeds limit"
    );
    let mut peers = BTreeMap::<Vec<u8>, RelayPeerAuthorization>::new();
    for route in overlay {
        let prefix = route
            .destination
            .context("overlay route is missing prefix")?;
        let peer =
            peers
                .entry(route.via_node_id.clone())
                .or_insert_with(|| RelayPeerAuthorization {
                    node_id: route.via_node_id,
                    ..Default::default()
                });
        peer.overlay_addresses.push(prefix.address.clone());
        peer.authorized_prefixes.push(prefix);
    }
    ensure!(
        peers.len() <= MAX_PEERS,
        "relay peer directory exceeds limit"
    );
    for peer in peers.values_mut() {
        peer.overlay_addresses.sort_unstable();
        peer.authorized_prefixes
            .sort_unstable_by(|a, b| a.address.cmp(&b.address));
    }
    for route in approved {
        if let Some(peer) = peers.get_mut(&route.via_node_id) {
            peer.authorized_prefixes.push(
                route
                    .destination
                    .context("approved route is missing prefix")?,
            );
        }
    }
    Ok(peers.into_values().collect())
}

pub(super) fn active_relays(db: &Connection, network: Id) -> Result<Vec<RelayEndpoint>> {
    let mut statement = db.prepare(
        "SELECT service_id,name,endpoint FROM relays
         WHERE network_id=?1 AND enabled=1 AND service_id IS NOT NULL ORDER BY id LIMIT ?2",
    )?;
    let mut rows = statement.query(params![network.as_bytes().as_slice(), MAX_RELAYS + 1])?;
    let mut relays = Vec::new();
    while let Some(row) = rows.next()? {
        ensure!(
            relays.len() < MAX_RELAYS,
            "active relay directory exceeds limit"
        );
        let service_id = Id::from_slice(&row.get::<_, Vec<u8>>(0)?)?
            .as_bytes()
            .to_vec();
        relays.push(RelayEndpoint {
            service_id,
            name: row.get(1)?,
            endpoint: row.get(2)?,
        });
    }
    Ok(relays)
}

fn decode_ip(address: &[u8]) -> Result<IpAddr> {
    let ip = match address.len() {
        4 => IpAddr::from(<[u8; 4]>::try_from(address)?),
        16 => IpAddr::from(<[u8; 16]>::try_from(address)?),
        _ => bail!("invalid stored IP address width"),
    };
    ensure!(ip.to_canonical() == ip, "IPv4-mapped stored IPv6 address");
    Ok(ip)
}

fn unicast_overlay(address: &[u8]) -> Result<IpAddr> {
    let ip = decode_ip(address)?;
    let link_local = match ip {
        IpAddr::V4(value) => value.is_link_local(),
        IpAddr::V6(value) => value.is_unicast_link_local(),
    };
    ensure!(
        !ip.is_unspecified()
            && !ip.is_multicast()
            && !ip.is_loopback()
            && !link_local
            && ip != IpAddr::from(std::net::Ipv4Addr::BROADCAST),
        "invalid stored overlay address"
    );
    Ok(ip)
}
