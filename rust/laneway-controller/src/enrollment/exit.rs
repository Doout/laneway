use super::{EnrollError, audit, new_id};
use anyhow::{Result, ensure};
use laneway_protocol::Id;
use rusqlite::{Transaction, params};
use serde_json::json;

pub(super) fn grant(
    tx: &Transaction<'_>,
    net: Id,
    node: Id,
    lease: Option<i64>,
    now: i64,
) -> Result<u64> {
    let mut metrics=tx.prepare("SELECT DISTINCT metric FROM routes WHERE network_id=? AND state='approved' AND prefix_address=x'00000000' AND prefix_length=0 AND metric>=100 ORDER BY metric")?;
    let mut metric = 100i64;
    for n in metrics.query_map([net.as_bytes()], |r| r.get::<_, i64>(0))? {
        if n? != metric {
            break;
        }
        metric += 1;
    }
    ensure!(metric <= 1_000_000, EnrollError::Conflict);
    let route = new_id()?;
    tx.execute("INSERT INTO routes(id,network_id,node_id,prefix_address,prefix_length,kind,mode,metric,state,valid_until,created_at,approved_at)
        VALUES(?1,?2,?3,x'00000000',0,'exit','nat',?4,'approved',?5,?6,?6)",params![route.as_bytes(),net.as_bytes(),node.as_bytes(),metric,lease,now])?;
    audit(
        tx,
        net,
        None,
        "route.invited_exit.approve",
        ("route", route),
        json!({"prefix":"0.0.0.0/0","metric":metric}),
        now,
    )?;
    if lease.is_none() {
        return Ok(0);
    }
    let mut bytes = [0; 8];
    getrandom::fill(&mut bytes)?;
    let generation = (i64::from_be_bytes(bytes) & i64::MAX).max(1);
    tx.execute("INSERT INTO ephemeral_exit_sessions(node_id,network_id,generation,last_heartbeat_at,suspect_at,revoke_at,created_at) VALUES(?1,?2,?3,?4,?5,?6,?4)",params![node.as_bytes(),net.as_bytes(),generation,now,now+20,now+60])?;
    Ok(generation as u64)
}
