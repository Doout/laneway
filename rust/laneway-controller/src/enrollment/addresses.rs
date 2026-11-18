use super::EnrollError;
use anyhow::{Result, ensure};
use laneway_protocol::Id;
use rusqlite::{Transaction, params};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// The caller holds an immediate transaction. A released address stays reserved
// while its former owner has any unrevoked, unexpired certificate.
pub(super) fn allocate(tx: &Transaction<'_>, net: Id, node: Id, now: i64) -> Result<Vec<IpAddr>> {
    let (base,bits,cursor,base6,bits6,cursor6) = tx.query_row(
        "SELECT ipv4_address,ipv4_prefix_length,next_ipv4,ipv6_address,ipv6_prefix_length,next_ipv6 FROM networks WHERE id=?",
        [net.as_bytes()], |r| Ok((r.get::<_,[u8;4]>(0)?,r.get::<_,u32>(1)?,r.get::<_,i64>(2)?,r.get::<_,Option<[u8;16]>>(3)?,r.get::<_,Option<u32>>(4)?,r.get::<_,i64>(5)?)))?;
    ensure!((8..=30).contains(&bits) && cursor > 0, "invalid IPv4 pool");
    let v4 = Pool::V4(u32::from_be_bytes(base));
    let mut result =
        vec![v4.claim(tx, net, node, now, cursor as u64, (1u64 << (32 - bits)) - 2)?];
    match (base6, bits6) {
        (None, None) => {}
        (Some(b), Some(n)) if (64..=120).contains(&n) && cursor6 > 0 => {
            let usable = (u128::MAX >> n).min(i64::MAX as u128) as u64;
            result.push(Pool::V6(u128::from_be_bytes(b)).claim(
                tx,
                net,
                node,
                now,
                cursor6 as u64,
                usable,
            )?);
        }
        _ => anyhow::bail!("invalid IPv6 pool"),
    }
    Ok(result)
}

enum Pool {
    V4(u32),
    V6(u128),
}
impl Pool {
    fn claim(
        &self,
        tx: &Transaction<'_>,
        net: Id,
        node: Id,
        now: i64,
        cursor: u64,
        usable: u64,
    ) -> Result<IpAddr> {
        let start = if cursor > usable { 1 } else { cursor };
        let mut offset = start;
        let mut claim=tx.prepare_cached("INSERT INTO overlay_addresses(id,network_id,node_id,address,prefix_length,created_at)
            VALUES(randomblob(16),?1,?2,?3,?4,?5)
            ON CONFLICT(network_id,address) DO UPDATE SET id=excluded.id,node_id=excluded.node_id,prefix_length=excluded.prefix_length,created_at=excluded.created_at,released_at=NULL
            WHERE released_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM certificates c WHERE c.node_id=overlay_addresses.node_id AND c.not_after>?5 AND c.revoked_at IS NULL)")?;
        loop {
            let address = match self {
                Self::V4(base) => IpAddr::V4(Ipv4Addr::from(
                    base.checked_add(u32::try_from(offset)?)
                        .ok_or_else(|| anyhow::anyhow!("invalid IPv4 pool"))?,
                )),
                Self::V6(base) => IpAddr::V6(Ipv6Addr::from(
                    base.checked_add(u128::from(offset))
                        .ok_or_else(|| anyhow::anyhow!("invalid IPv6 pool"))?,
                )),
            };
            let bytes = match address {
                IpAddr::V4(v) => v.octets().to_vec(),
                IpAddr::V6(v) => v.octets().to_vec(),
            };
            let next = if offset == usable { 1 } else { offset + 1 };
            if claim.execute(params![
                net.as_bytes(),
                node.as_bytes(),
                bytes,
                (bytes.len() * 8) as i64,
                now
            ])? == 1
            {
                tx.execute(
                    match self {
                        Self::V4(_) => "UPDATE networks SET next_ipv4=? WHERE id=?",
                        Self::V6(_) => "UPDATE networks SET next_ipv6=? WHERE id=?",
                    },
                    (i64::try_from(next)?, net.as_bytes()),
                )?;
                return Ok(address);
            }
            if next == start {
                return Err(EnrollError::PoolExhausted.into());
            }
            offset = next;
        }
    }
}
