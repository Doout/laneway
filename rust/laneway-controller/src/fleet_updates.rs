//! Transactional fleet plans and authenticated workload claims; never executes updates.
use crate::{
    SessionStore,
    access_admin::{AccessError, Actor, audit},
    check_snapshot,
    enrollment::renewal::NodeCredential,
    schema,
};
use anyhow::{Result, ensure};
use laneway_protocol::{
    Id,
    fleet_updates::{Create, Outcome, Poll, Report, valid_version},
};
use rusqlite::{OptionalExtension, Row, Transaction, TransactionBehavior, params};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::HashSet;

#[derive(Serialize)]
struct Plan {
    id: String,
    version: String,
    component: String,
    channel: String,
    state: String,
    created_at_unix_seconds: i64,
    updated_at_unix_seconds: i64,
    targets: Option<Vec<Target>>,
}

impl Plan {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            version: row.get(1)?,
            component: row.get(2)?,
            channel: row.get(3)?,
            state: row.get(4)?,
            created_at_unix_seconds: row.get(5)?,
            updated_at_unix_seconds: row.get(6)?,
            targets: None,
        })
    }
}

#[derive(Serialize)]
struct Target {
    node_id: String,
    canary: bool,
    state: String,
    previous_version: String,
    observed_version: String,
    detail: String,
    updated_at_unix_seconds: i64,
}

fn require_fleet(tx: &Transaction<'_>) -> Result<()> {
    ensure!(schema::is_fleet(tx)?, AccessError::Missing);
    Ok(())
}

pub(crate) fn inventory(tx: &Transaction<'_>, net: Id, limit: usize) -> Result<Value> {
    require_fleet(tx)?;
    ensure!(
        (1..=1000).contains(&limit),
        AccessError::Invalid("invalid limit")
    );
    let limit = limit as i64;
    let mut plans = tx.prepare(
        "SELECT lower(hex(id)),version,component,channel,state,created_at,updated_at
         FROM fleet_updates WHERE network_id=? ORDER BY created_at DESC,id DESC LIMIT ?",
    )?;
    let mut targets = tx.prepare(
        "SELECT lower(hex(node_id)),canary,state,previous_version,observed_version,detail,updated_at
         FROM fleet_update_targets WHERE network_id=? AND update_id=? ORDER BY canary DESC,node_id",
    )?;
    let mut values = Vec::new();
    for plan in plans.query_map((net.as_bytes(), limit), Plan::read)? {
        let mut plan = plan?;
        let id: Id = plan.id.parse()?;
        let rows = targets.query_map((net.as_bytes(), id.as_bytes()), |row| {
            Ok(Target {
                node_id: row.get(0)?,
                canary: row.get(1)?,
                state: row.get(2)?,
                previous_version: row.get(3)?,
                observed_version: row.get(4)?,
                detail: row.get(5)?,
                updated_at_unix_seconds: row.get(6)?,
            })
        })?;
        plan.targets = Some(rows.collect::<rusqlite::Result<_>>()?);
        values.push(plan);
    }
    let mut stmt = tx.prepare(
        "SELECT lower(hex(n.id)),COALESCE(a.component,''),COALESCE(a.channel,''),COALESCE(a.version,''),
                COALESCE(a.last_polled_at,0)
         FROM nodes n LEFT JOIN fleet_update_agents a ON a.node_id=n.id
         WHERE n.network_id=? AND n.revoked_at IS NULL AND n.enrollment_class<>'ephemeral'
         ORDER BY n.id LIMIT ?",
    )?;
    let agents = stmt
        .query_map((net.as_bytes(), limit), |row| {
            Ok(json!({
                "node_id": row.get::<_, String>(0)?,
                "component": row.get::<_, String>(1)?,
                "channel": row.get::<_, String>(2)?,
                "version": row.get::<_, String>(3)?,
                "last_polled_at_unix_seconds": row.get::<_, i64>(4)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!({"fleet_updates": values, "agents": agents}))
}

fn active_node(tx: &Transaction<'_>, net: Id, node: Id) -> Result<()> {
    let active: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM nodes WHERE id=? AND network_id=? AND revoked_at IS NULL
         AND enrollment_class<>'ephemeral')",
        (node.as_bytes(), net.as_bytes()),
        |row| row.get(0),
    )?;
    ensure!(active, AccessError::Missing);
    Ok(())
}

pub(crate) fn create(
    tx: &Transaction<'_>,
    net: Id,
    actor: &Actor,
    now: i64,
    request: Create,
) -> Result<Value> {
    require_fleet(tx)?;
    let count = request.node_ids.len();
    ensure!(
        valid_version(&request.version)
            && (1..=200).contains(&count)
            && (1..=count).contains(&request.canary_count),
        AccessError::Invalid("stable release version and 1–200 targets with canaries required")
    );
    let id = super::access_admin::next_id()?;
    let component = request.component.as_str();
    let channel = request.channel.as_str();
    let mut targets = Vec::with_capacity(count);
    let mut seen = HashSet::with_capacity(count);
    for (index, raw) in request.node_ids.iter().enumerate() {
        let node: Id = raw
            .parse()
            .map_err(|_| AccessError::Invalid("invalid node ID"))?;
        ensure!(seen.insert(node), AccessError::Invalid("duplicate node"));
        active_node(tx, net, node)?;
        let busy: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM fleet_update_targets t JOIN fleet_updates u ON u.id=t.update_id
             WHERE t.node_id=? AND (t.state='running' OR (t.state='pending' AND u.state IN ('canary','rollout','paused'))))",
            [node.as_bytes()],
            |row| row.get(0),
        )?;
        ensure!(!busy, AccessError::Conflict);
        targets.push((node, index < request.canary_count));
    }
    tx.execute(
        "INSERT INTO fleet_updates(id,network_id,version,component,channel,target_count,canary_count,state,created_at,updated_at)
         VALUES(?,?,?,?,?,?,?,'canary',?,?)",
        params![id.as_bytes(), net.as_bytes(), &request.version, component, channel, count as i64, request.canary_count as i64, now, now],
    )?;
    let mut output = Vec::with_capacity(count);
    for (node, canary) in targets {
        tx.execute(
            "INSERT INTO fleet_update_targets(update_id,network_id,node_id,canary,state,updated_at)
             VALUES(?,?,?,?,'pending',?)",
            params![id.as_bytes(), net.as_bytes(), node.as_bytes(), canary, now],
        )?;
        output.push(Target {
            node_id: node.to_string(),
            canary,
            state: "pending".into(),
            previous_version: String::new(),
            observed_version: String::new(),
            detail: String::new(),
            updated_at_unix_seconds: now,
        });
    }
    audit(
        tx,
        net,
        actor,
        now,
        "fleet_update.create",
        ("fleet_update", id),
        serde_json::to_value(&request)?,
    )?;
    Ok(serde_json::to_value(Plan {
        id: id.to_string(),
        version: request.version,
        component: component.into(),
        channel: channel.into(),
        state: "canary".into(),
        created_at_unix_seconds: now,
        updated_at_unix_seconds: now,
        targets: Some(output),
    })?)
}

pub(crate) fn advance(
    tx: &Transaction<'_>,
    net: Id,
    actor: &Actor,
    now: i64,
    id: Id,
    cancel: bool,
) -> Result<()> {
    require_fleet(tx)?;
    let (state, canaries): (String, i64) = tx
        .query_row(
            "SELECT state,canary_count FROM fleet_updates WHERE id=? AND network_id=?",
            (id.as_bytes(), net.as_bytes()),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(AccessError::Missing)?;
    let (next, action) = if cancel {
        ensure!(
            !matches!(state.as_str(), "complete" | "cancelled"),
            AccessError::Conflict
        );
        ("cancelled", "fleet_update.cancel")
    } else {
        ensure!(state == "canary", AccessError::Conflict);
        let healthy: i64 = tx.query_row(
            "SELECT count(*) FROM fleet_update_targets WHERE update_id=? AND canary=1 AND state='healthy'",
            [id.as_bytes()], |row| row.get(0),
        )?;
        ensure!(healthy == canaries, AccessError::Conflict);
        ("rollout", "fleet_update.promote")
    };
    tx.execute(
        "UPDATE fleet_updates SET state=?,updated_at=? WHERE id=?",
        (next, now, id.as_bytes()),
    )?;
    audit(tx, net, actor, now, action, ("fleet_update", id), json!({}))
}

fn workload(tx: &Transaction<'_>, peer: &NodeCredential, node: &str, net: &str) -> Result<i64> {
    check_snapshot(tx)?;
    require_fleet(tx)?;
    let now: i64 = tx.query_row("SELECT unixepoch()", [], |row| row.get(0))?;
    peer.binding(tx, now)?;
    active_node(tx, peer.net, peer.node)?;
    ensure!(
        node == peer.node.to_string() && net == peer.net.to_string(),
        AccessError::Invalid("updater runtime identity does not match authenticated node")
    );
    Ok(now)
}

impl SessionStore {
    /// Atomically record updater presence and claim at most one matching plan.
    pub fn poll_fleet_update(&mut self, peer: &NodeCredential, poll: Poll) -> Result<Value> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = workload(&tx, peer, &poll.runtime_node_id, &poll.runtime_network_id)?;
        ensure!(
            valid_version(&poll.current_version),
            AccessError::Invalid("invalid current version")
        );
        let component = poll.component.as_str();
        let channel = poll.channel.as_str();
        tx.execute(
            "INSERT INTO fleet_update_agents(node_id,component,channel,version,last_polled_at) VALUES(?,?,?,?,?)
             ON CONFLICT(node_id) DO UPDATE SET component=excluded.component,channel=excluded.channel,
                version=excluded.version,last_polled_at=excluded.last_polled_at",
            (peer.node.as_bytes(), component, channel, &poll.current_version, now),
        )?;
        let plan = tx.query_row(
            "SELECT lower(hex(u.id)),u.version,u.component,u.channel,u.state,u.created_at,u.updated_at
             FROM fleet_updates u JOIN fleet_update_targets t ON u.id=t.update_id
             WHERE t.node_id=?1 AND u.network_id=?2 AND u.component=?3 AND u.channel=?4 AND t.state='pending'
               AND (u.state='rollout' OR (u.state='canary' AND t.canary=1))
               AND NOT EXISTS(SELECT 1 FROM fleet_update_targets WHERE node_id=?1 AND state='running')
             ORDER BY u.created_at,u.id LIMIT 1",
            (peer.node.as_bytes(), peer.net.as_bytes(), component, channel),
            Plan::read,
        ).optional()?;
        if let Some(plan) = &plan {
            let id: Id = plan.id.parse()?;
            let claimed = tx.execute(
                "UPDATE fleet_update_targets SET state='running',previous_version=?,updated_at=?
                 WHERE update_id=? AND node_id=? AND state='pending'",
                (
                    &poll.current_version,
                    now,
                    id.as_bytes(),
                    peer.node.as_bytes(),
                ),
            )?;
            ensure!(claimed == 1, AccessError::Conflict);
            audit(
                &tx,
                peer.net,
                &Actor {
                    kind: "node",
                    id: peer.node,
                },
                now,
                "fleet_update.claim",
                ("fleet_update", id),
                json!({}),
            )?;
        }
        tx.commit()?;
        Ok(json!({"update": plan}))
    }

    /// Accept terminal evidence only from the target's own live TLS identity.
    pub fn report_fleet_update(
        &mut self,
        peer: &NodeCredential,
        id: Id,
        report: Report,
    ) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = workload(
            &tx,
            peer,
            &report.runtime_node_id,
            &report.runtime_network_id,
        )?;
        ensure!(
            report.detail.len() <= 512
                && !report.detail.contains(['\0', '\r', '\n'])
                && (report.observed_version.is_empty() || valid_version(&report.observed_version)),
            AccessError::Invalid("invalid update evidence")
        );
        let (state, version, previous, observed): (String, String, String, String) = tx
            .query_row(
                "SELECT t.state,u.version,t.previous_version,t.observed_version
             FROM fleet_update_targets t JOIN fleet_updates u ON t.update_id=u.id
             WHERE u.id=? AND u.network_id=? AND t.node_id=?",
                (id.as_bytes(), peer.net.as_bytes(), peer.node.as_bytes()),
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?
            .ok_or(AccessError::Missing)?;
        if state == report.state.as_str() && observed == report.observed_version {
            return Ok(tx.commit()?);
        }
        ensure!(state == "running", AccessError::Conflict);
        match report.state {
            Outcome::Healthy => ensure!(
                report.observed_version == version,
                AccessError::Invalid("healthy result must report target version")
            ),
            Outcome::RolledBack => ensure!(
                report.observed_version == previous,
                AccessError::Invalid("rollback must report previous version")
            ),
            Outcome::Failed => {}
        }
        tx.execute(
            "UPDATE fleet_update_targets SET state=?,observed_version=?,detail=?,updated_at=? WHERE update_id=? AND node_id=?",
            params![report.state.as_str(), &report.observed_version, &report.detail, now, id.as_bytes(), peer.node.as_bytes()],
        )?;
        if report.state == Outcome::Healthy {
            tx.execute(
                "UPDATE fleet_updates SET state=CASE WHEN (SELECT count(*) FROM fleet_update_targets
                 WHERE update_id=?1 AND state='healthy')=target_count THEN 'complete' ELSE state END,
                 updated_at=?2 WHERE id=?1 AND state NOT IN ('cancelled','paused')",
                (id.as_bytes(), now),
            )?;
        } else {
            tx.execute(
                "UPDATE fleet_updates SET state='paused',updated_at=? WHERE id=? AND state NOT IN ('cancelled','complete')",
                (now, id.as_bytes()),
            )?;
        }
        audit(
            &tx,
            peer.net,
            &Actor {
                kind: "node",
                id: peer.node,
            },
            now,
            "fleet_update.result",
            ("fleet_update", id),
            serde_json::to_value(&report)?,
        )?;
        Ok(tx.commit()?)
    }
}
