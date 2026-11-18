use super::{
    AccessError, Port, ResourceTarget, ServiceProtocol, Subject, conflict, epoch_reply, inventory,
    next_id, service_ports,
    subjects::{Editor, ResolvedSubject},
    validate_name,
};
use anyhow::{Result, ensure};
use laneway_protocol::{Id, policy::prefix_from_wire, v1::IpPrefix};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use std::net::IpAddr;

impl Editor<'_, '_> {
    pub(super) fn create_resource(&self, name: &str, target: ResourceTarget) -> Result<Value> {
        validate_name(name)?;
        let id = next_id()?;
        let kind = match target {
            ResourceTarget::Node(node) => {
                self.live_node(node)?;
                conflict(self.tx.execute(
                    "INSERT INTO access_resources
                    (id,network_id,name,target_kind,node_id,created_at,updated_at)
                    VALUES(?1,?2,?3,'node',?4,?5,?5)",
                    (
                        id.as_bytes(),
                        self.net.as_bytes(),
                        name,
                        node.as_bytes(),
                        self.now,
                    ),
                ))?;
                "node"
            }
            ResourceTarget::Prefix { route, prefix } => {
                ensure!(
                    prefix.prefix_len() > 0
                        && prefix.addr() == prefix.network()
                        && !matches!(prefix.addr(),IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some()),
                    AccessError::Invalid("invalid resource prefix")
                );
                // The route and its node are looked up in this transaction;
                // callers cannot supply an alternate connector or route prefix.
                let (connector, address, bits, kind) = self
                    .tx
                    .query_row(
                        "SELECT r.node_id,r.prefix_address,r.prefix_length,r.kind
                    FROM routes r JOIN nodes n ON n.id=r.node_id AND n.network_id=r.network_id
                    WHERE r.id=?1 AND r.network_id=?2 AND r.state='approved'
                    AND (r.valid_until IS NULL OR r.valid_until>?3) AND n.revoked_at IS NULL
                    AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?3)",
                        (route.as_bytes(), self.net.as_bytes(), self.now),
                        |r| {
                            Ok((
                                r.get::<_, [u8; 16]>(0)?,
                                r.get::<_, Vec<u8>>(1)?,
                                r.get::<_, u32>(2)?,
                                r.get::<_, String>(3)?,
                            ))
                        },
                    )
                    .optional()?
                    .ok_or(AccessError::Missing)?;
                let subnet = prefix_from_wire(IpPrefix {
                    address: address.clone(),
                    prefix_length: bits,
                })?;
                ensure!(
                    kind == "subnet"
                        && subnet.prefix_len() > 0
                        && subnet.prefix_len() <= prefix.prefix_len()
                        && subnet.contains(&prefix.addr()),
                    AccessError::Invalid(
                        "resource prefix must be inside its approved subnet route"
                    )
                );
                let connector = Id::new(connector)?;
                let resource_address = match prefix.addr() {
                    IpAddr::V4(v4) => v4.octets().to_vec(),
                    IpAddr::V6(v6) => v6.octets().to_vec(),
                };
                conflict(self.tx.execute("INSERT INTO access_resources
                    (id,network_id,name,target_kind,route_id,route_node_id,route_prefix_address,route_prefix_length,
                    prefix_address,prefix_length,created_at,updated_at)
                    VALUES(?1,?2,?3,'prefix',?4,?5,?6,?7,?8,?9,?10,?10)",
                    params![id.as_bytes(),self.net.as_bytes(),name,route.as_bytes(),connector.as_bytes(),address,bits,
                        resource_address,prefix.prefix_len(),self.now]))?;
                "prefix"
            }
        };
        self.record(
            "access_resource.create",
            "access_resource",
            id,
            json!({"target_kind":kind}),
        )?;
        inventory::named(self.tx, self.net, id, false)
    }

    pub(super) fn create_service(
        &self,
        name: &str,
        protocol: ServiceProtocol,
        ports: Vec<Port>,
    ) -> Result<Value> {
        validate_name(name)?;
        let ports = service_ports::canonical(protocol, ports)?;
        let id = next_id()?;
        conflict(self.tx.execute(
            "INSERT INTO access_services(id,network_id,name,protocol,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?5)",
            (id.as_bytes(),self.net.as_bytes(),name,protocol.name(),self.now)))?;
        let mut stmt = self.tx.prepare(
            "INSERT INTO access_service_ports(service_id,first_port,last_port) VALUES(?,?,?)",
        )?;
        for port in ports {
            stmt.execute((id.as_bytes(), port.first, port.last))?;
        }
        ensure!(self.tx.execute("UPDATE access_services SET ports_sealed=1 WHERE id=? AND network_id=? AND ports_sealed=0",
            (id.as_bytes(),self.net.as_bytes()))?==1,"could not seal staged port ranges");
        self.record(
            "access_service.create",
            "access_service",
            id,
            json!({"protocol":protocol.name()}),
        )?;
        inventory::named(self.tx, self.net, id, true)
    }

    pub(super) fn toggle_named(&self, id: Id, on: bool, is_service: bool) -> Result<Value> {
        let mut value = inventory::named(self.tx, self.net, id, is_service)?;
        if value["enabled"] != on {
            let (query, action, kind) = if is_service {
                (
                    "UPDATE access_services SET enabled=?,updated_at=? WHERE id=? AND network_id=?",
                    "access_service.update",
                    "access_service",
                )
            } else {
                (
                    "UPDATE access_resources SET enabled=?,updated_at=? WHERE id=? AND network_id=?",
                    "access_resource.update",
                    "access_resource",
                )
            };
            ensure!(
                self.tx
                    .execute(query, (on, self.now, id.as_bytes(), self.net.as_bytes()))?
                    == 1,
                AccessError::Missing
            );
            self.record(action, kind, id, json!({"enabled":on}))?;
            value["enabled"] = json!(on);
            value["updated_at_unix_seconds"] = json!(self.now);
        }
        Ok(value)
    }

    pub(super) fn resource_grant(
        &self,
        subject: Subject,
        resource: Id,
        service: Id,
    ) -> Result<Value> {
        let ResolvedSubject {
            id: subject_id,
            kind,
            user,
            team,
        } = self.resolve_subject(subject)?;
        self.require(
            "SELECT 1 FROM access_resources WHERE id=? AND network_id=? AND enabled=1",
            resource,
        )?;
        self.require("SELECT 1 FROM access_services WHERE id=? AND network_id=? AND enabled=1 AND ports_sealed=1",service)?;
        let id = next_id()?;
        conflict(self.tx.execute("INSERT INTO access_resource_grants(id,network_id,subject_kind,user_id,team_id,resource_id,service_id,created_at)
            VALUES(?,?,?,?,?,?,?,?)",
            params![id.as_bytes(),self.net.as_bytes(),kind,user.as_ref().map(Id::as_bytes),
                team.as_ref().map(Id::as_bytes),resource.as_bytes(),service.as_bytes(),self.now]))?;
        self.record(
            "access_resource_grant.create",
            "access_resource_grant",
            id,
            json!({"resource_id":resource.to_string(),"service_id":service.to_string()}),
        )?;
        Ok(
            json!({"grant_id":id.to_string(),"network_id":self.net.to_string(),"subject_kind":kind,
            "subject_id":subject_id.to_string(),"resource_id":resource.to_string(),"service_id":service.to_string(),
            "created_at_unix_seconds":self.now}),
        )
    }

    pub(super) fn delete_resource_grant(&self, id: Id) -> Result<Value> {
        ensure!(
            self.tx.execute(
                "DELETE FROM access_resource_grants WHERE id=? AND network_id=?",
                (id.as_bytes(), self.net.as_bytes())
            )? == 1,
            AccessError::Missing
        );
        Ok(epoch_reply(self.record(
            "access_resource_grant.delete",
            "access_resource_grant",
            id,
            json!({}),
        )?))
    }
}
