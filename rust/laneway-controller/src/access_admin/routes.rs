//! Route lifecycle on the shared controller schema. Only approved routes
//! change the published configuration; pending advertisements remain private.
use super::{AccessError, Actor, audit, conflict, epoch_reply, next_id, row_id, subjects::Editor};
use crate::{
    SessionStore, check_snapshot,
    enrollment::{EnrollError, renewal::NodeCredential},
    enrollment_tokens::{EXIT, ROUTER},
};
use anyhow::{Result, ensure};
use ipnet::IpNet;
use laneway_protocol::{Id, policy::prefix_from_wire, v1::IpPrefix};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{net::IpAddr, sync::LazyLock};

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteKind {
    Subnet,
    Exit,
}
impl RouteKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Subnet => "subnet",
            Self::Exit => "exit",
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    Nat,
    Routed,
}
impl RouteMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Nat => "nat",
            Self::Routed => "routed",
        }
    }
}

pub struct RouteSpec {
    pub prefix: IpNet,
    pub mode: RouteMode,
    pub metric: u32,
}
pub enum NodeRouteRequest {
    Advertise(RouteSpec, RouteKind, Option<i64>),
    Withdraw(Id),
}

static FORBIDDEN: LazyLock<[IpNet; 8]> = LazyLock::new(|| {
    [
        "0.0.0.0/32",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "::/128",
        "::1/128",
        "fe80::/10",
        "ff00::/8",
    ]
    .map(|prefix| prefix.parse().expect("constant prefix"))
});
impl RouteSpec {
    fn validate(&self, kind: RouteKind) -> Result<()> {
        let prefix = self.prefix;
        ensure!(
            prefix == prefix.trunc()
                && !matches!(prefix.addr(), IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
                && if matches!(kind, RouteKind::Exit) {
                    prefix.prefix_len() == 0
                } else {
                    prefix.prefix_len() > 0
                        && !FORBIDDEN.iter().any(|other| {
                            prefix.contains(&other.addr()) || other.contains(&prefix.addr())
                        })
                },
            AccessError::Invalid("invalid route prefix")
        );
        ensure!(
            self.metric <= 1_000_000,
            AccessError::Invalid("route metric exceeds 1000000")
        );
        Ok(())
    }
    fn address(&self) -> Vec<u8> {
        match self.prefix.addr() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        }
    }
}

const COLUMNS: &str = "id,network_id,node_id,prefix_address,prefix_length,kind,mode,metric,state,valid_until,created_at,approved_at,withdrawn_at";
#[derive(Serialize)]
struct RouteRecord {
    route_id: String,
    network_id: String,
    node_id: String,
    prefix: String,
    kind: String,
    mode: String,
    metric: u32,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    valid_until_unix_seconds: Option<i64>,
    created_at_unix_seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_at_unix_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    withdrawn_at_unix_seconds: Option<i64>,
}
fn route(row: &rusqlite::Row<'_>) -> Result<RouteRecord> {
    let prefix = prefix_from_wire(IpPrefix {
        address: row.get(3)?,
        prefix_length: row.get(4)?,
    })?;
    Ok(RouteRecord {
        route_id: row_id(row, 0)?.to_string(),
        network_id: row_id(row, 1)?.to_string(),
        node_id: row_id(row, 2)?.to_string(),
        prefix: prefix.to_string(),
        kind: row.get(5)?,
        mode: row.get(6)?,
        metric: row.get(7)?,
        state: row.get(8)?,
        valid_until_unix_seconds: row.get(9)?,
        created_at_unix_seconds: row.get(10)?,
        approved_at_unix_seconds: row.get(11)?,
        withdrawn_at_unix_seconds: row.get(12)?,
    })
}
fn required_capability(kind: &str) -> i64 {
    match kind {
        "subnet" => ROUTER as i64,
        "exit" => EXIT as i64,
        _ => 0, // stored overlay routes from the legacy controller
    }
}

impl Editor<'_, '_> {
    pub(super) fn list_routes(&self, limit: usize) -> Result<Value> {
        self.route_epoch()?; // distinguish an empty inventory from a missing network
        let mut stmt = self.tx.prepare(&format!(
            "SELECT {COLUMNS} FROM routes WHERE network_id=? ORDER BY created_at DESC,id DESC LIMIT ?"
        ))?;
        let mut rows = stmt.query(params![self.net.as_bytes(), i64::try_from(limit)?])?;
        let mut routes = Vec::new();
        while let Some(row) = rows.next()? {
            routes.push(route(row)?);
        }
        Ok(json!({"routes":routes}))
    }

    fn route_epoch(&self) -> Result<i64> {
        Ok(self
            .tx
            .query_row(
                "SELECT configuration_epoch FROM networks WHERE id=?",
                [self.net.as_bytes()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(AccessError::Missing)?)
    }

    fn one_route(&self, id: Id) -> Result<RouteRecord> {
        let mut stmt = self.tx.prepare(&format!(
            "SELECT {COLUMNS} FROM routes WHERE id=? AND network_id=?"
        ))?;
        let mut rows = stmt.query(params![id.as_bytes(), self.net.as_bytes()])?;
        route(rows.next()?.ok_or(AccessError::Missing)?)
    }

    fn advertise(
        &self,
        node: Id,
        spec: &RouteSpec,
        kind: RouteKind,
        expiry: Option<i64>,
    ) -> Result<Id> {
        let id = next_id()?;
        conflict(self.tx.execute(
            "INSERT INTO routes(id,network_id,node_id,prefix_address,prefix_length,kind,mode,metric,state,valid_until,created_at)
             VALUES(?,?,?,?,?,?,?,?,'advertised',?,?)",
            params![id.as_bytes(), self.net.as_bytes(), node.as_bytes(), spec.address(), spec.prefix.prefix_len(),
                kind.as_str(), spec.mode.as_str(), spec.metric, expiry, self.now],
        ))?;
        audit(
            self.tx,
            self.net,
            &self.actor,
            self.now,
            "route.advertise",
            ("route", id),
            json!({"prefix":spec.prefix.to_string()}),
        )?;
        Ok(id)
    }

    pub(super) fn approve_route(&self, id: Id) -> Result<i64> {
        let (state, valid, kind, caps): (String, Option<i64>, String, i64) = self
            .tx
            .query_row(
                "SELECT r.state,r.valid_until,r.kind,n.enabled_capabilities FROM routes r
             JOIN nodes n ON n.id=r.node_id AND n.network_id=r.network_id
             WHERE r.id=? AND r.network_id=? AND n.revoked_at IS NULL",
                params![id.as_bytes(), self.net.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
            .ok_or(AccessError::Missing)?;
        let required = required_capability(&kind);
        ensure!(
            state == "advertised"
                && valid.is_none_or(|expiry| expiry > self.now)
                && caps & required == required,
            AccessError::Conflict
        );
        let ambiguous: bool = self.tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM routes candidate JOIN routes requested ON requested.id=?1
             WHERE candidate.network_id=requested.network_id AND candidate.id<>?1
             AND candidate.prefix_address=requested.prefix_address AND candidate.prefix_length=requested.prefix_length
             AND candidate.metric=requested.metric AND candidate.state='approved')",
            [id.as_bytes()], |row| row.get(0),
        )?;
        ensure!(!ambiguous, AccessError::Conflict);
        self.tx.execute(
            "UPDATE routes SET state='approved',approved_at=? WHERE id=?",
            params![self.now, id.as_bytes()],
        )?;
        self.record("route.approve", "route", id, json!({}))
    }

    pub(super) fn withdraw_route(&self, id: Id, owner: Option<Id>) -> Result<i64> {
        let (net, node, state): ([u8; 16], [u8; 16], String) = self
            .tx
            .query_row(
                "SELECT network_id,node_id,state FROM routes WHERE id=?",
                [id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or(AccessError::Missing)?;
        if let Some(owner) = owner {
            ensure!(
                owner.as_bytes() == &node && self.net.as_bytes() == &net,
                EnrollError::Denied
            );
        } else {
            ensure!(self.net.as_bytes() == &net, AccessError::Missing);
        }
        ensure!(state != "withdrawn", AccessError::Conflict);
        self.tx.execute(
            "UPDATE routes SET state='withdrawn',withdrawn_at=? WHERE id=?",
            params![self.now, id.as_bytes()],
        )?;
        if state == "approved" {
            self.record("route.withdraw", "route", id, json!({}))
        } else {
            audit(
                self.tx,
                self.net,
                &self.actor,
                self.now,
                "route.withdraw",
                ("route", id),
                json!({}),
            )?;
            self.route_epoch()
        }
    }

    pub(super) fn assign_route(&self, node: Id, spec: RouteSpec) -> Result<(Value, bool)> {
        spec.validate(RouteKind::Subnet)?;
        let caps: i64 = self.tx.query_row(
            "SELECT enabled_capabilities FROM nodes WHERE id=? AND network_id=? AND revoked_at IS NULL",
            params![node.as_bytes(), self.net.as_bytes()], |row| row.get(0),
        ).optional()?.ok_or(AccessError::Missing)?;
        let existing = self.assignment_candidate(node, &spec)?;
        if caps & ROUTER as i64 == 0 {
            let updated = caps | ROUTER as i64;
            self.tx.execute(
                "UPDATE nodes SET enabled_capabilities=? WHERE id=?",
                params![updated, node.as_bytes()],
            )?;
            self.record(
                "node.capabilities.set",
                "node",
                node,
                json!({"capabilities":updated}),
            )?;
        }
        let (id, state, created) = match existing {
            Some((id, state)) => (id, state, false),
            None => (
                self.advertise(node, &spec, RouteKind::Subnet, None)?,
                String::from("advertised"),
                true,
            ),
        };
        if state == "advertised" {
            self.approve_route(id)?;
        }
        Ok((serde_json::to_value(self.one_route(id)?)?, created))
    }
    fn assignment_candidate(&self, node: Id, spec: &RouteSpec) -> Result<Option<(Id, String)>> {
        let mut stmt = self.tx.prepare(
            "SELECT id,node_id,kind,mode,metric,state FROM routes WHERE network_id=?
             AND prefix_address=? AND prefix_length=? AND state IN ('advertised','approved') LIMIT 2"
        )?;
        let mut rows = stmt.query(params![
            self.net.as_bytes(),
            spec.address(),
            spec.prefix.prefix_len()
        ])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let id = row_id(row, 0)?;
        let state = row.get(5)?;
        ensure!(
            row_id(row, 1)? == node
                && row.get_ref(2)?.as_str()? == "subnet"
                && row.get_ref(3)?.as_str()? == spec.mode.as_str()
                && row.get::<_, u32>(4)? == spec.metric
                && rows.next()?.is_none(),
            AccessError::Conflict
        );
        Ok(Some((id, state)))
    }
}

impl SessionStore {
    pub fn node_route(
        &mut self,
        peer: &NodeCredential,
        request: Result<NodeRouteRequest>,
    ) -> Result<Value> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now = tx.query_row("SELECT unixepoch()", [], |row| row.get(0))?;
        let bound = peer.binding(&tx, now)?;
        let editor = Editor {
            tx: &tx,
            net: peer.net,
            actor: Actor {
                kind: "node",
                id: peer.node,
            },
            now,
        };
        let result = match request? {
            NodeRouteRequest::Advertise(spec, kind, expiry) => {
                spec.validate(kind)?;
                ensure!(
                    expiry.is_none_or(|expiry| expiry > now),
                    AccessError::Invalid("route already expired")
                );
                let required = required_capability(kind.as_str());
                ensure!(
                    bound.capabilities & required == required,
                    AccessError::Invalid("node lacks route capability")
                );
                let id = editor.advertise(peer.node, &spec, kind, expiry)?;
                serde_json::to_value(editor.one_route(id)?)?
            }
            NodeRouteRequest::Withdraw(id) => {
                epoch_reply(editor.withdraw_route(id, Some(peer.node))?)
            }
        };
        tx.commit()?;
        Ok(result)
    }
}
