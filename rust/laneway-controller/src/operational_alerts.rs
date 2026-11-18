//! Reconcile operational incidents from durable evidence and record transitions in an outbox.
use crate::{
    SessionStore,
    access_admin::{AccessError, Actor, audit, next_id},
    check_snapshot, schema,
};
use anyhow::{Result, ensure};
use laneway_protocol::Id;
use rusqlite::{OptionalExtension, Row, Transaction, TransactionBehavior, params};
use serde::Serialize;
use serde_json::{Value, json};

const ALERT_COLUMNS: &str = "id,lower(hex(network_id)),lower(hex(node_id)),kind,state,summary,remediation_path,opened_at,updated_at,acknowledged_at";
const MAX_ATTEMPTS: i64 = 5;
const EVENT_VALID: &str =
    "length(id)=32 AND id NOT GLOB '*[^0-9a-f]*' AND id<>'00000000000000000000000000000000'
     AND CASE WHEN length(CAST(payload AS BLOB)) BETWEEN 1 AND 16384 AND json_valid(payload)
       THEN json_extract(payload,'$.event_id') IS id ELSE 0 END";

#[derive(Serialize)]
struct Alert {
    alert_id: String,
    network_id: String,
    node_id: String,
    kind: String,
    state: String,
    summary: String,
    remediation_path: String,
    opened_at: i64,
    updated_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    acknowledged_at: Option<i64>,
}

impl Alert {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            alert_id: row.get(0)?,
            network_id: row.get(1)?,
            node_id: row.get(2)?,
            kind: row.get(3)?,
            state: row.get(4)?,
            summary: row.get(5)?,
            remediation_path: row.get(6)?,
            opened_at: row.get(7)?,
            updated_at: row.get(8)?,
            acknowledged_at: row.get(9)?,
        })
    }

    fn event(&self, tx: &Transaction<'_>) -> Result<()> {
        #[derive(Serialize)]
        struct Event<'a> {
            event_id: &'a str,
            created_at: i64,
            alert: &'a Alert,
        }
        let id = next_id()?.to_string();
        let payload = serde_json::to_string(&Event {
            event_id: &id,
            created_at: self.updated_at,
            alert: self,
        })?;
        tx.execute(
            "INSERT INTO operational_alert_events(id,alert_id,payload,created_at) VALUES(?,?,?,?)",
            (&id, &self.alert_id, payload, self.updated_at),
        )?;
        Ok(())
    }
}

pub(crate) fn inventory(tx: &Transaction<'_>, net: Id) -> Result<Value> {
    ensure!(schema::is_fleet(tx)?, AccessError::Missing);
    let found: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?)",
        [net.as_bytes()],
        |r| r.get(0),
    )?;
    ensure!(found, AccessError::Missing);
    let mut stmt = tx.prepare(&format!(
        "SELECT {ALERT_COLUMNS} FROM operational_alerts WHERE network_id=?
         ORDER BY state='resolved',updated_at DESC,id LIMIT 500"
    ))?;
    let values = stmt
        .query_map([net.as_bytes()], Alert::read)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!({"alerts": values}))
}

pub(crate) fn acknowledge(
    tx: &Transaction<'_>,
    net: Id,
    actor: &Actor,
    now: i64,
    id: Id,
) -> Result<()> {
    ensure!(schema::is_fleet(tx)?, AccessError::Missing);
    let mut alert = tx
        .query_row(
            &format!("SELECT {ALERT_COLUMNS} FROM operational_alerts WHERE id=? AND network_id=?"),
            (id.to_string(), net.as_bytes()),
            Alert::read,
        )
        .optional()?
        .ok_or(AccessError::Missing)?;
    if alert.state != "open" {
        return Ok(());
    }
    alert.state = "acknowledged".into();
    alert.acknowledged_at = Some(now);
    alert.updated_at = now;
    tx.execute("UPDATE operational_alerts SET state='acknowledged',updated_at=?1,acknowledged_at=?1 WHERE id=?2",
        (now, &alert.alert_id))?;
    alert.event(tx)?;
    audit(
        tx,
        net,
        actor,
        now,
        "alert.acknowledged",
        ("operational_alert", id),
        json!({}),
    )
}

struct Evidence {
    node: [u8; 16],
    network: [u8; 16],
    revoked: bool,
    lease: Option<i64>,
    report_expires: Option<i64>,
    exit: Option<String>,
    certificate: Option<i64>,
    terminal_update: Option<String>,
}

impl Evidence {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            node: row.get(0)?,
            network: row.get(1)?,
            revoked: row.get(2)?,
            lease: row.get(3)?,
            report_expires: row.get(4)?,
            exit: row.get(5)?,
            certificate: row.get(6)?,
            terminal_update: row.get(7)?,
        })
    }

    fn conditions(&self, now: i64) -> [(&'static str, &'static str, Option<bool>); 4] {
        let inactive = self.revoked || self.lease.is_some_and(|expiry| expiry <= now);
        let offline = self
            .report_expires
            .map(|expiry| expiry <= now.saturating_sub(120));
        let credentials = self
            .certificate
            .map(|expiry| expiry <= now.saturating_add(7 * 86_400));
        let exit = self
            .exit
            .as_deref()
            .filter(|s| *s != "unknown" && self.report_expires.is_some_and(|expiry| expiry > now))
            .map(|s| s == "unavailable");
        let update = self.terminal_update.as_deref().map(|s| s != "healthy");
        let active = |evidence| if inactive { Some(false) } else { evidence };
        [
            (
                "node_offline",
                "Node status reports stopped; check the node service and its controller connectivity.",
                active(offline),
            ),
            (
                "credentials_expiring",
                "Node certificate expires within seven days or has expired; restore connectivity and renew credentials.",
                active(credentials),
            ),
            (
                "exit_unavailable",
                "Selected exit is unavailable; inspect its node and choose a healthy exit.",
                active(exit),
            ),
            (
                "update_failed",
                "Managed update failed or rolled back; inspect the update results before retrying.",
                active(update),
            ),
        ]
    }
}

fn reconcile(tx: &Transaction<'_>, now: i64) -> Result<()> {
    let rows = {
        let mut stmt = tx.prepare(
            "SELECT n.id,n.network_id,n.revoked_at IS NOT NULL,n.lease_expires_at,e.expires_at,e.selected_exit_state,
                (SELECT MAX(c.not_after) FROM certificates c WHERE c.node_id=n.id AND c.network_id=n.network_id
                 AND c.revoked_at IS NULL AND c.not_before<=?1),
                (SELECT t.state FROM fleet_update_targets t WHERE t.node_id=n.id AND t.network_id=n.network_id
                 AND t.state IN ('healthy','rolled_back','failed')
                 ORDER BY t.updated_at DESC,t.state='healthy',t.update_id DESC LIMIT 1)
             FROM nodes n LEFT JOIN endpoint_status_latest e ON e.node_id=n.id AND e.network_id=n.network_id",
        )?;
        stmt.query_map([now], Evidence::read)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut find = tx.prepare(&format!(
        "SELECT {ALERT_COLUMNS} FROM operational_alerts WHERE node_id=? AND kind=?"
    ))?;
    for row in rows {
        let node = Id::new(row.node)?;
        let network = Id::new(row.network)?;
        for (kind, summary, active) in row.conditions(now) {
            let Some(active) = active else { continue };
            let existing = find
                .query_row((node.as_bytes(), kind), Alert::read)
                .optional()?;
            let mut alert = match existing {
                Some(alert) if alert.network_id != network.to_string() => {
                    // Evidence from a new placement cannot change an alert
                    // in the old network. The placement lifecycle owns it.
                    continue;
                }
                Some(alert) if active == (alert.state != "resolved") => continue,
                Some(alert) => alert,
                None if !active => continue,
                None => {
                    let alert = Alert {
                        alert_id: next_id()?.to_string(),
                        network_id: network.to_string(),
                        node_id: node.to_string(),
                        kind: kind.into(),
                        state: "open".into(),
                        summary: summary.into(),
                        remediation_path: format!("/nodes/{node}"),
                        opened_at: now,
                        updated_at: now,
                        acknowledged_at: None,
                    };
                    tx.execute(
                        "INSERT INTO operational_alerts(id,network_id,node_id,kind,state,summary,remediation_path,opened_at,updated_at)
                         VALUES(?1,?2,?3,?4,'open',?5,?6,?7,?7)",
                        params![&alert.alert_id, network.as_bytes(), node.as_bytes(), kind, summary, &alert.remediation_path, now],
                    )?;
                    alert.event(tx)?;
                    continue;
                }
            };
            alert.updated_at = now;
            alert.state = if active { "open" } else { "resolved" }.into();
            if active {
                alert.opened_at = now;
                alert.acknowledged_at = None;
            }
            tx.execute(
                "UPDATE operational_alerts SET state=?,opened_at=?,updated_at=?,acknowledged_at=? WHERE id=?",
                (&alert.state, alert.opened_at, now, alert.acknowledged_at, &alert.alert_id),
            )?;
            alert.event(tx)?;
        }
    }
    Ok(())
}

/// One bounded, durably reserved webhook attempt.
pub struct Delivery {
    /// The original event ID, unchanged on retries.
    pub id: String,
    /// Stored JSON bytes to sign and send without reserialization.
    pub payload: String,
    attempts: i64,
}

fn backoff(attempts: i64) -> i64 {
    if attempts < MAX_ATTEMPTS {
        30 * (1 << attempts)
    } else {
        8
    }
}

impl SessionStore {
    /// Reports whether this database has been explicitly migrated for fleet operations.
    pub fn operational_alerts_available(&mut self) -> Result<bool> {
        let tx = self.db.transaction()?;
        check_snapshot(&tx)?;
        let enabled = schema::is_fleet(&tx)?;
        tx.commit()?;
        Ok(enabled)
    }

    /// Check endpoint reports, certificates, exit selection, and terminal fleet outcomes.
    pub fn reconcile_operational_alerts(&mut self) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        if schema::is_fleet(&tx)? {
            let now = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
            reconcile(&tx, now)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Discard disabled deliveries, or reserve one before performing network I/O.
    pub fn reserve_operational_delivery(&mut self, enabled: bool) -> Result<Option<Delivery>> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        if !schema::is_fleet(&tx)? {
            return Ok(None);
        }
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        // A crash may consume the final reservation. A malformed imported
        // payload is never emitted or allowed to block the rest of the queue.
        tx.execute(
            &format!("UPDATE operational_alert_events SET delivery_state='failed',next_attempt_at=?1
             WHERE id IN (SELECT id FROM operational_alert_events WHERE delivery_state='pending' AND next_attempt_at<=?1
               AND (attempts NOT BETWEEN 0 AND 4 OR NOT ({EVENT_VALID})) LIMIT 20)"),
            [now],
        )?;
        if !enabled {
            tx.execute(
                "UPDATE operational_alert_events SET delivery_state='disabled',next_attempt_at=?1
                 WHERE id IN (SELECT id FROM operational_alert_events WHERE delivery_state='pending' AND next_attempt_at<=?1
                 ORDER BY created_at,id LIMIT 20)",
                [now],
            )?;
            tx.commit()?;
            return Ok(None);
        }
        let next = tx.query_row(
            &format!("SELECT id,payload,attempts FROM operational_alert_events
             WHERE delivery_state='pending' AND next_attempt_at<=?1 AND attempts BETWEEN 0 AND 4 AND ({EVENT_VALID})
             ORDER BY created_at,id LIMIT 1"),
            [now],
            |row| Ok(Delivery { id: row.get(0)?, payload: row.get(1)?, attempts: row.get::<_, i64>(2)? + 1 }),
        ).optional()?;
        if let Some(event) = &next {
            tx.execute(
                "UPDATE operational_alert_events SET attempts=?,next_attempt_at=? WHERE id=?",
                (event.attempts, now + backoff(event.attempts), &event.id),
            )?;
        }
        tx.commit()?;
        Ok(next)
    }

    /// Complete a reservation; failure after the fifth attempt is terminal.
    pub fn finish_operational_delivery(&mut self, event: &Delivery, delivered: bool) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        ensure!(schema::is_fleet(&tx)?, AccessError::Missing);
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        let (state, next) = if delivered {
            ("delivered", now)
        } else if event.attempts >= MAX_ATTEMPTS {
            ("failed", now)
        } else {
            ("pending", now + backoff(event.attempts))
        };
        tx.execute(
            "UPDATE operational_alert_events SET delivery_state=?,next_attempt_at=?
             WHERE id=? AND delivery_state='pending' AND attempts=?",
            (state, next, &event.id, event.attempts),
        )?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    const NETWORK: [u8; 16] = [1; 16];
    const NODE: [u8; 16] = [2; 16];

    fn fixture() -> Result<SessionStore> {
        let db = Connection::open_in_memory()?;
        db.execute_batch("
            PRAGMA foreign_keys=ON;
            CREATE TABLE schema_versions(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
            WITH RECURSIVE v(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM v WHERE i<19)
              INSERT INTO schema_versions SELECT i,1 FROM v;
            CREATE TABLE networks(id BLOB PRIMARY KEY);
            CREATE TABLE nodes(id BLOB PRIMARY KEY,network_id BLOB NOT NULL,revoked_at INTEGER,lease_expires_at INTEGER,UNIQUE(network_id,id));
            CREATE TABLE certificates(id BLOB PRIMARY KEY,node_id BLOB,network_id BLOB,not_before INTEGER,not_after INTEGER,revoked_at INTEGER);
            CREATE TABLE endpoint_status_latest(node_id BLOB PRIMARY KEY,network_id BLOB,expires_at INTEGER,selected_exit_state TEXT);
            CREATE TABLE audit_events(id BLOB,network_id BLOB,actor_kind TEXT,actor_id BLOB,action TEXT,target_type TEXT,target_id BLOB,details_json TEXT,created_at INTEGER);
        ")?;
        db.execute_batch(include_str!("../schema/fleet-v19.sql"))?;
        db.execute("INSERT INTO networks VALUES(?)", [&NETWORK])?;
        db.execute("INSERT INTO nodes VALUES(?,?,NULL,NULL)", (&NODE, &NETWORK))?;
        Ok(SessionStore { db })
    }

    fn set_report(store: &SessionStore, expiry: i64, exit: &str) -> Result<()> {
        store.db.execute(
            "INSERT OR REPLACE INTO endpoint_status_latest VALUES(?,?,?,?)",
            (&NODE, &NETWORK, expiry, exit),
        )?;
        Ok(())
    }

    #[test]
    fn transitions_are_atomic_and_only_known_evidence_resolves() -> Result<()> {
        let mut store = fixture()?;
        let now: i64 = store.db.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        store.reconcile_operational_alerts()?;
        let events = |s: &SessionStore| -> Result<i64> {
            Ok(s.db
                .query_row("SELECT count(*) FROM operational_alert_events", [], |r| {
                    r.get(0)
                })?)
        };
        assert_eq!(events(&store)?, 0);
        set_report(&store, now + 300, "unavailable")?;
        store.db.execute_batch(
            "CREATE TEMP TRIGGER fail_event BEFORE INSERT ON operational_alert_events
            BEGIN SELECT raise(ABORT,'fixture write failure'); END",
        )?;
        assert!(store.reconcile_operational_alerts().is_err());
        let count: i64 =
            store
                .db
                .query_row("SELECT count(*) FROM operational_alerts", [], |r| r.get(0))?;
        assert_eq!(count, 0, "alert cannot commit without its event");
        store.db.execute_batch("DROP TRIGGER fail_event")?;
        store.reconcile_operational_alerts()?;
        store.reconcile_operational_alerts()?;
        assert_eq!(events(&store)?, 1);
        let id_text: String = store
            .db
            .query_row("SELECT id FROM operational_alerts", [], |r| r.get(0))?;
        let id: Id = id_text.parse()?;
        let net = Id::new(NETWORK)?;
        let actor = Actor {
            kind: "administrator",
            id: Id::new([8; 16])?,
        };
        {
            let tx = store.db.transaction()?;
            acknowledge(&tx, net, &actor, now, id)?;
            acknowledge(&tx, net, &actor, now, id)?;
            tx.commit()?;
        }
        let state = |s: &SessionStore| -> Result<(String, Option<i64>)> {
            Ok(s.db.query_row(
                "SELECT state,acknowledged_at FROM operational_alerts WHERE id=?",
                [&id_text],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        };
        assert_eq!(state(&store)?, ("acknowledged".into(), Some(now)));
        assert_eq!(events(&store)?, 2);
        set_report(&store, now - 180, "ready")?;
        store.reconcile_operational_alerts()?;
        assert_eq!(state(&store)?, ("acknowledged".into(), Some(now)));
        assert_eq!(
            events(&store)?,
            3,
            "stale report creates offline alert only"
        );
        set_report(&store, now + 180, "unknown")?;
        store.reconcile_operational_alerts()?;
        assert_eq!(state(&store)?, ("acknowledged".into(), Some(now)));
        assert_eq!(
            events(&store)?,
            4,
            "fresh report resolves offline but not unknown exit"
        );
        set_report(&store, now + 180, "ready")?;
        store.reconcile_operational_alerts()?;
        assert_eq!(state(&store)?, ("resolved".into(), Some(now)));
        set_report(&store, now + 180, "unavailable")?;
        store.reconcile_operational_alerts()?;
        assert_eq!(state(&store)?, ("open".into(), None));
        store.db.execute("UPDATE nodes SET revoked_at=?1", [now])?;
        store.reconcile_operational_alerts()?;
        assert_eq!(state(&store)?, ("resolved".into(), None));
        assert_eq!(events(&store)?, 7);
        Ok(())
    }

    #[test]
    fn durable_attempts_retry_same_bytes_and_exhaust_after_five_reservations() -> Result<()> {
        let mut store = fixture()?;
        let now: i64 = store.db.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        set_report(&store, now + 300, "unavailable")?;
        store.reconcile_operational_alerts()?;
        let first = store.reserve_operational_delivery(true)?.unwrap();
        assert_eq!(first.attempts, 1);
        assert!(store.reserve_operational_delivery(true)?.is_none());
        let row = |s: &SessionStore| -> Result<(i64, String, i64)> {
            Ok(s.db.query_row("SELECT attempts,delivery_state,next_attempt_at FROM operational_alert_events WHERE id=?",
                [&first.id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?)
        };
        assert!(row(&store)?.2 >= now + 60);
        for attempt in 2..=5 {
            store
                .db
                .execute("UPDATE operational_alert_events SET next_attempt_at=0", [])?;
            let reserved = store.reserve_operational_delivery(true)?.unwrap();
            assert_eq!(reserved.attempts, attempt);
            assert_eq!(reserved.id, first.id);
            assert_eq!(reserved.payload, first.payload);
            // Simulate restart without a confirmed result from any send.
        }
        store.finish_operational_delivery(&first, true)?;
        assert_eq!(
            row(&store)?.1,
            "pending",
            "a stale completion cannot change a newer reservation"
        );
        store
            .db
            .execute("UPDATE operational_alert_events SET next_attempt_at=0", [])?;
        assert!(store.reserve_operational_delivery(true)?.is_none());
        assert_eq!((row(&store)?.0, row(&store)?.1), (5, "failed".into()));

        set_report(&store, now + 300, "ready")?;
        store.reconcile_operational_alerts()?;
        assert!(store.reserve_operational_delivery(false)?.is_none());
        assert!(store.reserve_operational_delivery(true)?.is_none());
        let count: i64 = store.db.query_row(
            "SELECT count(*) FROM operational_alert_events
            WHERE delivery_state='disabled' AND attempts=0",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(count, 1);
        Ok(())
    }
}
