use super::{
    AccessError, row_id,
    service_ports::{self, ServiceProtocol},
};
use anyhow::{Result, ensure};
use laneway_protocol::{Id, policy::prefix_from_wire, v1::IpPrefix};
use rusqlite::{Row, Statement, Transaction};
use serde_json::{Value, json};

const RESOURCE_COLUMNS: &str = "id,name,target_kind,node_id,route_id,route_node_id,route_prefix_address,route_prefix_length,prefix_address,prefix_length,enabled,created_at,updated_at";
const SERVICE_COLUMNS: &str = "id,name,protocol,ports_sealed,enabled,created_at,updated_at";

pub(super) fn read(tx: &Transaction<'_>, net: Id) -> Result<Value> {
    let mut remaining = (4 << 20) - 256;
    let users = rows(
        tx,
        net,
        &mut remaining,
        "SELECT id,name,enabled,created_at,updated_at FROM access_users WHERE network_id=? ORDER BY name,id",
        |r| user(r, net),
    )?;
    let teams = rows(
        tx,
        net,
        &mut remaining,
        "SELECT id,name,created_at,updated_at FROM access_teams WHERE network_id=? ORDER BY name,id",
        |r| {
            Ok(
                json!({"team_id":row_id(r,0)?.to_string(),"network_id":net.to_string(),"name":r.get::<_,String>(1)?,
            "created_at_unix_seconds":r.get::<_,i64>(2)?,"updated_at_unix_seconds":r.get::<_,i64>(3)?}),
            )
        },
    )?;
    let memberships = rows(
        tx,
        net,
        &mut remaining,
        "SELECT team_id,user_id,created_at FROM access_team_members WHERE network_id=? ORDER BY team_id,user_id",
        |r| {
            Ok(
                json!({"team_id":row_id(r,0)?.to_string(),"user_id":row_id(r,1)?.to_string(),"network_id":net.to_string(),
            "created_at_unix_seconds":r.get::<_,i64>(2)?}),
            )
        },
    )?;
    let grants = rows(
        tx,
        net,
        &mut remaining,
        "SELECT id,subject_kind,user_id,team_id,target_kind,node_id,created_at FROM access_grants WHERE network_id=? ORDER BY created_at,id",
        |r| {
            let (kind, subject) = subject(r)?;
            let target: String = r.get(4)?;
            let node: Option<[u8; 16]> = r.get(5)?;
            ensure!(
                matches!(
                    (target.as_str(), node),
                    ("network", None) | ("node" | "exit", Some(_))
                ),
                "invalid grant target"
            );
            let mut result = json!({"grant_id":row_id(r,0)?.to_string(),"network_id":net.to_string(),
                "subject_kind":kind,"subject_id":subject.to_string(),"target_kind":target,"created_at_unix_seconds":r.get::<_,i64>(6)?});
            if let Some(node) = node {
                result["node_id"] = json!(Id::new(node)?.to_string())
            }
            Ok(result)
        },
    )?;
    let resources = rows(
        tx,
        net,
        &mut remaining,
        &format!(
            "SELECT {RESOURCE_COLUMNS} FROM access_resources WHERE network_id=? ORDER BY name,id"
        ),
        |r| resource(r, net),
    )?;
    let mut ports = service_ports::prepare(tx)?;
    let services = rows(
        tx,
        net,
        &mut remaining,
        &format!(
            "SELECT {SERVICE_COLUMNS} FROM access_services WHERE network_id=? ORDER BY name,id"
        ),
        |r| service(r, net, &mut ports),
    )?;
    let resource_grants = rows(
        tx,
        net,
        &mut remaining,
        "SELECT id,subject_kind,user_id,team_id,resource_id,service_id,created_at FROM access_resource_grants WHERE network_id=? ORDER BY created_at,id",
        |r| {
            let (kind, subject) = subject(r)?;
            Ok(
                json!({"grant_id":row_id(r,0)?.to_string(),"network_id":net.to_string(),
                "subject_kind":kind,"subject_id":subject.to_string(),"resource_id":row_id(r,4)?.to_string(),
                "service_id":row_id(r,5)?.to_string(),"created_at_unix_seconds":r.get::<_,i64>(6)?}),
            )
        },
    )?;
    Ok(
        json!({"users":users,"teams":teams,"memberships":memberships,"grants":grants,"resources":resources,
        "services":services,"resource_grants":resource_grants}),
    )
}

pub(super) fn named(tx: &Transaction<'_>, net: Id, id: Id, is_service: bool) -> Result<Value> {
    let (columns, table) = if is_service {
        (SERVICE_COLUMNS, "access_services")
    } else {
        (RESOURCE_COLUMNS, "access_resources")
    };
    let mut stmt = tx.prepare(&format!(
        "SELECT {columns} FROM {table} WHERE id=? AND network_id=?"
    ))?;
    let mut rows = stmt.query((id.as_bytes(), net.as_bytes()))?;
    let row = rows.next()?.ok_or(AccessError::Missing)?;
    if is_service {
        service(row, net, &mut service_ports::prepare(tx)?)
    } else {
        resource(row, net)
    }
}

fn service(r: &Row<'_>, net: Id, ports: &mut Statement<'_>) -> Result<Value> {
    let id = row_id(r, 0)?;
    let proto = ServiceProtocol::from_stored(&r.get::<_, String>(2)?)?;
    ensure!(r.get::<_, bool>(3)?, "unsealed service");
    Ok(
        json!({"service_id":id.to_string(),"network_id":net.to_string(),"name":r.get::<_,String>(1)?,
        "protocol":proto.name(),"ports":service_ports::read(ports,id,proto)?,"enabled":r.get::<_,bool>(4)?,
        "created_at_unix_seconds":r.get::<_,i64>(5)?,"updated_at_unix_seconds":r.get::<_,i64>(6)?}),
    )
}

fn rows(
    tx: &Transaction<'_>,
    net: Id,
    remaining: &mut usize,
    sql: &str,
    mut read: impl FnMut(&Row<'_>) -> Result<Value>,
) -> Result<Vec<Value>> {
    let mut stmt = tx.prepare(sql)?;
    let mut query = stmt.query([net.as_bytes()])?;
    let mut values = Vec::new();
    while let Some(r) = query.next()? {
        ensure!(values.len() < 16384, "too many managed inventory records");
        let value = read(r)?;
        let size = serde_json::to_vec(&value)?.len() + 1;
        ensure!(
            size <= *remaining,
            "managed inventory exceeds response limit"
        );
        *remaining -= size;
        values.push(value)
    }
    Ok(values)
}
fn subject(row: &Row<'_>) -> Result<(String, Id)> {
    let kind: String = row.get(1)?;
    let id = match kind.as_str() {
        "user" => row_id(row, 2)?,
        "team" => row_id(row, 3)?,
        _ => anyhow::bail!("invalid grant subject"),
    };
    Ok((kind, id))
}
pub(super) fn user(r: &Row<'_>, net: Id) -> Result<Value> {
    Ok(
        json!({"user_id":row_id(r,0)?.to_string(),"network_id":net.to_string(),"name":r.get::<_,String>(1)?,
        "enabled":r.get::<_,bool>(2)?,"created_at_unix_seconds":r.get::<_,i64>(3)?,"updated_at_unix_seconds":r.get::<_,i64>(4)?}),
    )
}
fn prefix(row: &Row<'_>, at: usize) -> Result<Option<ipnet::IpNet>> {
    match (
        row.get::<_, Option<Vec<u8>>>(at)?,
        row.get::<_, Option<u32>>(at + 1)?,
    ) {
        (None, None) => Ok(None),
        (Some(address), Some(prefix_length)) => Ok(Some(prefix_from_wire(IpPrefix {
            address,
            prefix_length,
        })?)),
        _ => anyhow::bail!("incomplete resource prefix"),
    }
}
fn resource(r: &Row<'_>, net: Id) -> Result<Value> {
    let kind: String = r.get(2)?;
    let node: Option<[u8; 16]> = r.get(3)?;
    let route: Option<[u8; 16]> = r.get(4)?;
    let connector: Option<[u8; 16]> = r.get(5)?;
    let subnet = prefix(r, 6)?;
    let target = prefix(r, 8)?;
    let mut value = json!({"resource_id":row_id(r,0)?.to_string(),"network_id":net.to_string(),"name":r.get::<_,String>(1)?,
        "target_kind":kind,"enabled":r.get::<_,bool>(10)?,"created_at_unix_seconds":r.get::<_,i64>(11)?,
        "updated_at_unix_seconds":r.get::<_,i64>(12)?});
    match (kind.as_str(), node, route, connector, subnet, target) {
        ("node", Some(node), None, None, None, None) => {
            value["node_id"] = json!(Id::new(node)?.to_string())
        }
        ("prefix", None, Some(route), Some(connector), Some(subnet), Some(target)) => {
            ensure!(
                subnet.prefix_len() > 0
                    && subnet.prefix_len() <= target.prefix_len()
                    && subnet.contains(&target.addr()),
                "invalid resource target"
            );
            Id::new(connector)?;
            value["route_id"] = json!(Id::new(route)?.to_string());
            // Go's compressed IPv6 and ipnet's canonical formatting agree for
            // binary network addresses (mapped IPv4 is rejected above).
            value["prefix"] = json!(target.to_string());
        }
        _ => return Err(anyhow::anyhow!("invalid resource kind or selector")),
    }
    Ok(value)
}
