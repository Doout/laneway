use super::{audit, bump};
use anyhow::Result;
use laneway_protocol::Id;
use rusqlite::{Transaction, params};
use serde_json::json;
use std::collections::BTreeSet;

// Matches Go's independently committed, bounded pre-enrollment maintenance.
// Later rejection of an invitation cannot resurrect expired authorization.
pub(super) fn expire(tx: &Transaction<'_>, now: i64) -> Result<()> {
    let mut select=tx.prepare("SELECT id,network_id,lease_expires_at FROM nodes WHERE enrollment_class='ephemeral' AND revoked_at IS NULL AND lease_expires_at<=? ORDER BY lease_expires_at,id LIMIT 1024")?;
    let rows = select
        .query_map([now], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, [u8; 16]>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(select);
    let mut affected = BTreeSet::new();
    for (node, net, lease) in rows {
        let node = Id::new(node)?;
        let net = Id::new(net)?;
        tx.execute("UPDATE nodes SET revoked_at=?,name=substr(name,1,210)||'~expired~'||lower(hex(id)) WHERE id=?", (now,node.as_bytes()))?;
        for sql in [
            "UPDATE ephemeral_exit_sessions SET terminated_at=? WHERE node_id=? AND terminated_at IS NULL",
            "UPDATE overlay_addresses SET released_at=? WHERE node_id=? AND released_at IS NULL",
            "UPDATE certificates SET revoked_at=?,revocation_reason='ephemeral lease expired' WHERE node_id=? AND revoked_at IS NULL",
            "UPDATE routes SET state='withdrawn',withdrawn_at=? WHERE node_id=? AND state IN ('advertised','approved')",
        ] {
            tx.execute(sql, (now, node.as_bytes()))?;
        }
        audit(
            tx,
            net,
            None,
            "ephemeral.expire",
            ("node", node),
            json!({"lease_expires_at":lease}),
            now,
        )?;
        affected.insert(net);
    }
    for net in affected {
        bump(tx, net)?
    }
    let cutoff = now - 7 * 86400;
    tx.execute("DELETE FROM nodes WHERE id IN (SELECT id FROM nodes WHERE enrollment_class='ephemeral' AND revoked_at IS NOT NULL AND lease_expires_at<=? ORDER BY lease_expires_at,id LIMIT 1024)",[cutoff])?;
    tx.execute("DELETE FROM enrollment_tokens WHERE id IN (SELECT id FROM enrollment_tokens WHERE enrollment_class='ephemeral' AND expires_at<=? ORDER BY expires_at,id LIMIT 1024)",[cutoff])?;
    Ok(())
}

pub(super) fn expire_routes(tx: &Transaction<'_>, net: Id, now: i64) -> Result<()> {
    let expired = {
        let mut rows=tx.prepare("UPDATE routes SET state='withdrawn',withdrawn_at=?1
            WHERE network_id=?2 AND id IN (SELECT id FROM routes WHERE network_id=?2 AND state='approved'
              AND valid_until<=?1 ORDER BY valid_until,id LIMIT 1024) RETURNING id")?;
        rows.query_map(params![now, net.as_bytes()], |r| r.get::<_, [u8; 16]>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if !expired.is_empty() {
        bump(tx, net)?
    }
    for id in expired {
        audit(
            tx,
            net,
            None,
            "route.expire",
            ("route", Id::new(id)?),
            json!({"reason":"expired"}),
            now,
        )?
    }
    Ok(())
}

pub(super) fn expire_exits(tx: &Transaction<'_>, now: i64) -> Result<()> {
    let exits = {
        let mut rows = tx.prepare(
            "SELECT node_id,network_id,generation,revoke_at FROM ephemeral_exit_sessions
            WHERE terminated_at IS NULL AND revoke_at<=? ORDER BY revoke_at,node_id LIMIT 1024",
        )?;
        rows.query_map([now], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, [u8; 16]>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut affected = BTreeSet::new();
    for (node, net, generation, revoke_at) in exits {
        for sql in [
            "UPDATE ephemeral_exit_sessions SET terminated_at=? WHERE node_id=? AND terminated_at IS NULL",
            "UPDATE nodes SET revoked_at=?, name=substr(name,1,207)||'~expired-exit~'||lower(hex(id)) WHERE id=? AND revoked_at IS NULL",
            "UPDATE overlay_addresses SET released_at=? WHERE node_id=? AND released_at IS NULL",
            "UPDATE certificates SET revoked_at=?,revocation_reason='ephemeral Exit heartbeat expired' WHERE node_id=? AND revoked_at IS NULL",
            "UPDATE routes SET state='withdrawn',withdrawn_at=? WHERE node_id=? AND state IN ('advertised','approved')",
        ] {
            tx.execute(sql, (now, node))?;
        }
        let net = Id::new(net)?;
        audit(
            tx,
            net,
            None,
            "ephemeral_exit.lease.revoke",
            ("node", Id::new(node)?),
            json!({"generation":generation,"revoke_at":revoke_at}),
            now,
        )?;
        affected.insert(net);
    }
    for net in affected {
        bump(tx, net)?
    }
    Ok(())
}
