//! Retain only the latest, short-lived observations from authenticated nodes.
use crate::{
    SessionStore, access_admin::AccessError, check_snapshot, enrollment::renewal::NodeCredential,
    schema,
};
use anyhow::{Result, ensure};
use laneway_protocol::{
    Id,
    topology::{MAX_PEERS, MAX_REPORT_BYTES, Peer, Report, TTL_SECONDS},
};
use rusqlite::{Transaction, TransactionBehavior};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::HashSet;

impl SessionStore {
    /// Accept one bounded report, rechecking the exact live TLS credential.
    pub fn record_topology(&mut self, sender: &NodeCredential, report: Report) -> Result<()> {
        ensure!(
            report.peers.len() <= MAX_PEERS && (report.enabled || report.peers.is_empty()),
            AccessError::Invalid("invalid topology report size or opt-in")
        );
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        ensure!(schema::is_fleet(&tx)?, AccessError::Missing);
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |row| row.get(0))?;
        sender.binding(&tx, now)?;
        let mut seen = HashSet::new();
        let mut stmt = tx.prepare(
            "SELECT EXISTS(SELECT 1 FROM nodes WHERE id=?1 AND network_id=?2 AND revoked_at IS NULL
             AND (enrollment_class<>'ephemeral' OR lease_expires_at>?3))",
        )?;
        for peer in &report.peers {
            let peer = peer.check(now).map_err(AccessError::Invalid)?;
            ensure!(
                peer != sender.node && seen.insert(peer),
                AccessError::Invalid("self or duplicate topology peer")
            );
            let active: bool = stmt
                .query_row((peer.as_bytes(), sender.net.as_bytes(), now), |row| {
                    row.get(0)
                })?;
            ensure!(active, AccessError::Missing);
        }
        drop(stmt);
        // Never accumulate history. The interval is an independent bound on
        // authenticated reporters, not on the incoming network transport.
        tx.execute("DELETE FROM node_topology WHERE expires_at<=?", [now])?;
        if report.enabled {
            let recent: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM node_topology WHERE node_id=?1 AND observed_at>?2)",
                (sender.node.as_bytes(), now - 15),
                |row| row.get(0),
            )?;
            ensure!(!recent, AccessError::Conflict);
            let peers = serde_json::to_string(&report.peers)?;
            ensure!(
                peers.len() <= MAX_REPORT_BYTES,
                AccessError::Invalid("topology report exceeds limit")
            );
            tx.execute(
                "INSERT INTO node_topology (node_id,observed_at,expires_at,peers_json) VALUES (?1,?2,?3,?4)
                 ON CONFLICT(node_id) DO UPDATE SET observed_at=excluded.observed_at,expires_at=excluded.expires_at,peers_json=excluded.peers_json",
                (sender.node.as_bytes(), now, now + TTL_SECONDS, peers),
            )?;
        } else {
            tx.execute(
                "DELETE FROM node_topology WHERE node_id=?",
                [sender.node.as_bytes()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Remove expired reports from fleet storage even without further traffic.
    pub fn prune_topology(&mut self) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        if schema::is_fleet(&tx)? {
            tx.execute(
                "DELETE FROM node_topology WHERE expires_at<=unixepoch()",
                [],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[derive(Serialize)]
struct Edge {
    node_id: String,
    network_id: String,
    expires_at_unix_seconds: i64,
    #[serde(flatten)]
    peer: Peer,
}

pub(crate) fn inventory(tx: &Transaction<'_>, net: Id, limit: usize, now: i64) -> Result<Value> {
    ensure!(schema::is_fleet(tx)?, AccessError::Missing);
    ensure!(
        (1..=1000).contains(&limit),
        AccessError::Invalid("invalid limit")
    );
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?)",
        [net.as_bytes()],
        |row| row.get(0),
    )?;
    ensure!(exists, AccessError::Missing);
    // Filter stale contacts and inactive identities before the edge limit;
    // empty reporters cannot consume the caller's result budget.
    let mut stmt = tx.prepare(
        "SELECT n.id,t.expires_at,j.value FROM node_topology t JOIN nodes n ON n.id=t.node_id
         JOIN json_each(t.peers_json) j JOIN nodes peer ON peer.id=unhex(json_extract(j.value,'$.peer_id'))
         AND peer.network_id=n.network_id
         WHERE n.network_id=?1 AND t.expires_at>?2 AND n.revoked_at IS NULL AND peer.revoked_at IS NULL
         AND (n.enrollment_class<>'ephemeral' OR n.lease_expires_at>?2)
         AND (peer.enrollment_class<>'ephemeral' OR peer.lease_expires_at>?2)
         AND json_extract(j.value,'$.last_contact_unix_seconds')>?3
         AND json_extract(j.value,'$.last_contact_unix_seconds')<=?2+5
         ORDER BY n.id,peer.id LIMIT ?4",
    )?;
    let mut rows = stmt.query((net.as_bytes(), now, now - TTL_SECONDS, limit as i64 + 1))?;
    let mut edges = Vec::new();
    let net = net.to_string();
    while let Some(row) = rows.next()? {
        let node = Id::new(row.get(0)?)?;
        let peer: Peer = serde_json::from_str(row.get_ref(2)?.as_str()?)?;
        ensure!(
            peer.check(now).map_err(AccessError::Invalid)? != node,
            "stored self topology edge"
        );
        edges.push(Edge {
            node_id: node.to_string(),
            network_id: net.clone(),
            expires_at_unix_seconds: row.get(1)?,
            peer,
        });
    }
    let limited = edges.len() > limit;
    edges.truncate(limit);
    Ok(json!({"edges":edges,"limited":limited,"retention_seconds":TTL_SECONDS}))
}
