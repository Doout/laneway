//! Device authority edits share the same transaction as route withdrawal and
//! the snapshot epoch. Certificate-only revocation leaves the node enrolled.
use super::{AccessError, row_id, subjects::Editor};
use crate::enrollment_tokens::{EXIT, ROUTER};
use anyhow::{Result, ensure};
use laneway_protocol::Id;
use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Serialize)]
struct Certificate {
    certificate_id: String,
    network_id: String,
    node_id: String,
    serial: String,
    not_before_unix_seconds: i64,
    not_after_unix_seconds: i64,
    created_at_unix_seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at_unix_seconds: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    revocation_reason: String,
}

impl Editor<'_, '_> {
    pub(super) fn certificates(&self, limit: usize) -> Result<Value> {
        ensure!(
            (1..=1000).contains(&limit),
            AccessError::Invalid("invalid limit")
        );
        self.current_epoch()?;
        let mut stmt = self.tx.prepare(
            "SELECT id,node_id,serial,not_before,not_after,created_at,revoked_at,revocation_reason
             FROM certificates WHERE network_id=? ORDER BY created_at,id LIMIT ?",
        )?;
        let mut rows = stmt.query((self.net.as_bytes(), limit as i64))?;
        let network_id = self.net.to_string();
        let mut result = Vec::new();
        while let Some(r) = rows.next()? {
            result.push(Certificate {
                certificate_id: row_id(r, 0)?.to_string(),
                network_id: network_id.clone(),
                node_id: row_id(r, 1)?.to_string(),
                serial: hex::encode(r.get::<_, Vec<u8>>(2)?),
                not_before_unix_seconds: r.get(3)?,
                not_after_unix_seconds: r.get(4)?,
                created_at_unix_seconds: r.get(5)?,
                revoked_at_unix_seconds: r.get(6)?,
                revocation_reason: r.get(7)?,
            });
        }
        Ok(json!({"certificates":result}))
    }

    pub(super) fn revoke_certificate(&self, serial: &[u8], reason: &str) -> Result<i64> {
        validate_reason(reason)?;
        ensure!(
            (1..=32).contains(&serial.len()) && serial[0] != 0,
            AccessError::Invalid("invalid certificate serial")
        );
        let (id, revoked): ([u8; 16], Option<i64>) = self
            .tx
            .query_row(
                "SELECT id,revoked_at FROM certificates WHERE network_id=? AND serial=?",
                (self.net.as_bytes(), serial),
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(AccessError::Missing)?;
        ensure!(revoked.is_none(), AccessError::Conflict);
        self.tx.execute(
            "UPDATE certificates SET revoked_at=?,revocation_reason=? WHERE id=?",
            params![self.now, reason, id],
        )?;
        self.record(
            "certificate.revoke",
            "certificate",
            Id::new(id)?,
            json!({"reason":reason}),
        )
    }

    pub(super) fn revoke_node(&self, id: Id, reason: &str) -> Result<i64> {
        validate_reason(reason)?;
        let revoked: Option<i64> = self
            .tx
            .query_row(
                "SELECT revoked_at FROM nodes WHERE id=? AND network_id=?",
                (id.as_bytes(), self.net.as_bytes()),
                |r| r.get(0),
            )
            .optional()?
            .ok_or(AccessError::Missing)?;
        ensure!(revoked.is_none(), AccessError::Conflict);
        self.tx.execute(
            "UPDATE nodes SET revoked_at=? WHERE id=?",
            (self.now, id.as_bytes()),
        )?;
        self.tx.execute(
            "UPDATE certificates SET revoked_at=?,revocation_reason=? WHERE node_id=? AND revoked_at IS NULL",
            params![self.now,reason,id.as_bytes()],
        )?;
        self.tx.execute(
            "UPDATE overlay_addresses SET released_at=? WHERE node_id=? AND released_at IS NULL",
            (self.now, id.as_bytes()),
        )?;
        self.withdraw_node_routes(id, None)?;
        self.record("node.revoke", "node", id, json!({"reason":reason}))
    }

    pub(super) fn set_node_capabilities(&self, id: Id, capabilities: u64) -> Result<i64> {
        ensure!(
            capabilities & !(ROUTER | EXIT) == 0,
            AccessError::Invalid("unsupported node policy capabilities")
        );
        let current: i64 = self.tx.query_row(
            "SELECT enabled_capabilities FROM nodes WHERE id=? AND network_id=? AND revoked_at IS NULL",
            (id.as_bytes(),self.net.as_bytes()), |r| r.get(0),
        ).optional()?.ok_or(AccessError::Missing)?;
        if current == capabilities as i64 {
            return self.current_epoch();
        }
        self.tx.execute(
            "UPDATE nodes SET enabled_capabilities=? WHERE id=?",
            (capabilities as i64, id.as_bytes()),
        )?;
        for (kind, required) in [("subnet", ROUTER), ("exit", EXIT)] {
            if capabilities & required == 0 {
                self.withdraw_node_routes(id, Some(kind))?;
            }
        }
        self.record(
            "node.capabilities.set",
            "node",
            id,
            json!({"capabilities":capabilities}),
        )
    }

    fn withdraw_node_routes(&self, id: Id, kind: Option<&str>) -> Result<()> {
        self.tx.execute(
            "UPDATE routes SET state='withdrawn',withdrawn_at=?1 WHERE node_id=?2
             AND state IN ('advertised','approved') AND (?3 IS NULL OR kind=?3)",
            params![self.now, id.as_bytes(), kind],
        )?;
        Ok(())
    }
}

fn validate_reason(reason: &str) -> Result<()> {
    ensure!(
        !reason.is_empty() && reason.len() <= 1024 && reason.trim() == reason,
        AccessError::Invalid("invalid revocation reason")
    );
    Ok(())
}
