use super::{Grants, overlay_prefixes, read_id};
use crate::access_admin::service_ports::{self, ServiceProtocol};
use anyhow::{Result, ensure};
use laneway_protocol::{
    Id,
    policy::prefix_from_wire,
    v1::{IpPrefix, PortRange, RouteKind},
};
use rusqlite::{Row, Transaction};
use std::collections::HashMap;

impl Grants<'_> {
    pub(super) fn named(&mut self, tx: &Transaction<'_>) -> Result<()> {
        let mut stmt=tx.prepare("SELECT rg.id,r.target_kind,r.node_id,r.route_id,r.route_node_id,
            r.route_prefix_address,r.route_prefix_length,r.prefix_address,r.prefix_length,s.id,s.protocol,s.ports_sealed
            FROM access_resource_grants rg
            JOIN access_resources r ON r.id=rg.resource_id AND r.network_id=rg.network_id
            JOIN access_services s ON s.id=rg.service_id AND s.network_id=rg.network_id
            WHERE rg.network_id=?1 AND r.enabled=1 AND s.enabled=1 AND
            ((rg.subject_kind='user' AND rg.user_id=?2) OR (rg.subject_kind='team' AND rg.team_id IN
              (SELECT team_id FROM access_team_members WHERE network_id=?1 AND user_id=?2)))
            ORDER BY rg.id")?;
        let mut port_query = service_ports::prepare(tx)?;
        let routes: HashMap<_, _> = self
            .routes
            .iter()
            .map(|r| (r.route_id.as_slice(), r))
            .collect();
        let mut rows = stmt.query((self.net.as_bytes(), self.user.as_bytes()))?;
        while let Some(row) = rows.next()? {
            let id = read_id(row, 0)?;
            let service = read_id(row, 9)?;
            let protocol = ServiceProtocol::from_stored(&row.get::<_, String>(10)?)?;
            ensure!(row.get::<_, i64>(11)? == 1, "unsealed named service");
            let ports = service_ports::read(&mut port_query, service, protocol)?;
            let node: Option<Vec<u8>> = row.get(2)?;
            let route: Option<Vec<u8>> = row.get(3)?;
            let connector: Option<Vec<u8>> = row.get(4)?;
            let route_prefix = read_prefix(row, 5)?;
            let target_prefix = read_prefix(row, 7)?;
            let (node, prefixes) = match (
                row.get::<_, String>(1)?.as_str(),
                node,
                route,
                connector,
                route_prefix,
                target_prefix,
            ) {
                ("node", Some(node), None, None, None, None) => {
                    Id::from_slice(&node)?;
                    let Some(peer) = self.peers.get(node.as_slice()) else {
                        continue;
                    };
                    (node, overlay_prefixes(peer))
                }
                (
                    "prefix",
                    None,
                    Some(route_id),
                    Some(connector),
                    Some(route_prefix),
                    Some(target_prefix),
                ) => {
                    Id::from_slice(&route_id)?;
                    Id::from_slice(&connector)?;
                    let subnet = prefix_from_wire(route_prefix.clone())?;
                    let target = prefix_from_wire(target_prefix.clone())?;
                    ensure!(
                        subnet.prefix_len() > 0
                            && subnet.prefix_len() <= target.prefix_len()
                            && subnet.max_prefix_len() == target.max_prefix_len()
                            && subnet.contains(&target.addr()),
                        "invalid pinned resource prefix"
                    );
                    let Some(route) = routes.get(route_id.as_slice()) else {
                        continue;
                    };
                    if route.kind != RouteKind::Subnet as i32
                        || route.via_node_id != connector
                        || route.destination.as_ref() != Some(&route_prefix)
                    {
                        continue;
                    }
                    (connector, vec![target_prefix])
                }
                _ => anyhow::bail!("invalid named access grant target"),
            };
            let mut selector = self.selector(protocol.wire(), vec![node], prefixes);
            selector.destination_ports = ports
                .into_iter()
                .map(|p| PortRange {
                    first: u32::from(p.first),
                    last: u32::from(p.last),
                })
                .collect();
            self.allow(id, selector, "Managed named resource access grant")?;
        }
        Ok(())
    }
}

fn read_prefix(row: &Row<'_>, index: usize) -> Result<Option<IpPrefix>> {
    match (
        row.get::<_, Option<Vec<u8>>>(index)?,
        row.get::<_, Option<u32>>(index + 1)?,
    ) {
        (None, None) => Ok(None),
        (Some(address), Some(prefix_length)) => Ok(Some(IpPrefix {
            address,
            prefix_length,
        })),
        _ => anyhow::bail!("incomplete stored resource prefix"),
    }
}
