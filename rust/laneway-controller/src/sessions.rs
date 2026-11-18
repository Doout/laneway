//! Browser-session inventory for the active controller. Unlike local inventory,
//! an authenticated read slides the idle deadline and may record an expiry.
use crate::{InventoryList, check_snapshot, nodes::read_nodes, open_existing, read_networks};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use laneway_protocol::Id;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid administrator session")]
    Invalid,
    #[error("administrator session expired")]
    Expired,
    #[error("network access denied")]
    Denied,
}

#[derive(Debug, Error)]
pub enum ListError {
    #[error("invalid network_id")]
    NetworkId,
    #[error("limit must be an integer from 1 through 1000")]
    Limit,
    #[error("record not found")]
    Missing,
}

pub struct SessionReply<T = InventoryList> {
    pub list: T,
    pub id: Id,
    pub idle: i64,
    pub absolute: i64,
}

/// Opens only an existing database. Nothing here can create a principal or
/// grant a permission. Session-owned operations must not use local inventory.
pub struct SessionStore {
    pub(crate) db: Connection,
}

struct StoredSession {
    id: [u8; 16],
    principal: [u8; 16],
    credential: [u8; 16],
    last_seen: i64,
    idle: i64,
    absolute: i64,
}

fn check_network(tx: &Transaction<'_>, principal: Id, network: Id) -> Result<()> {
    let allowed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM administrator_principal_networks WHERE principal_id=?1 AND network_id=?2)",
        (principal.as_bytes(),network.as_bytes()), |r|r.get(0))?;
    ensure!(allowed, SessionError::Denied);
    Ok(())
}

impl SessionStore {
    pub fn check_database(path: &Path) -> Result<()> {
        let mut store = Self::open(path)?;
        let tx = store.db.transaction()?;
        check_snapshot(&tx)?;
        tx.commit()?;
        Ok(())
    }
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            db: open_existing(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?,
        })
    }

    pub fn inventory(
        &mut self,
        token: &str,
        query: Result<(Option<Id>, usize), ListError>,
    ) -> Result<SessionReply> {
        self.with_session(token, true, |tx, principal, _, all, _| {
            // Match Go management middleware: authenticate before reporting a
            // malformed resource identifier or list limit, without touching it.
            let (network, limit) = query?;
            ensure!((1..=1000).contains(&limit), ListError::Limit);
            let restricted = (!all).then_some(principal);
            if let (Some(principal), Some(network)) = (restricted, network) {
                check_network(tx, principal, network)?;
            }
            Ok(match network {
                None => InventoryList::Networks(read_networks(
                    tx,
                    limit,
                    restricted.map(crate::Scope::Browser),
                )?),
                Some(id) => InventoryList::Nodes(read_nodes(tx, id, limit)?),
            })
        })
    }

    pub fn view(
        &mut self,
        token: &str,
        csrf: Option<&str>,
    ) -> Result<SessionReply<serde_json::Value>> {
        self.with_session(token, true, |tx, principal, session, all, _| {
            crate::browser::session_view(tx, principal, session, all, csrf)
        })
    }

    pub fn network(
        &mut self,
        token: &str,
        id: Result<Id, ListError>,
    ) -> Result<SessionReply<crate::Network>> {
        self.with_session(token, true, |tx, principal, _, all, _| {
            let id = id?;
            if !all {
                check_network(tx, principal, id)?
            }
            crate::read_network(tx, id)
        })
    }

    pub(crate) fn with_session<T>(
        &mut self,
        token: &str,
        touch: bool,
        read: impl FnOnce(&Transaction<'_>, Id, Id, bool, i64) -> Result<T>,
    ) -> Result<SessionReply<T>> {
        let digest = session_digest(token)?;
        // Acquire the write lock before reading the clock or permissions. A
        // revocation and a read have an unambiguous order, including in WAL.
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        let StoredSession { id, principal, credential, last_seen, idle, absolute } = tx.query_row(
            "SELECT id,principal_id,credential_id,last_seen_at,idle_expires_at,absolute_expires_at
             FROM administrator_sessions WHERE token_hash=?1 AND revoked_at IS NULL",
            [&digest], |r| Ok(StoredSession { id:r.get(0)?, principal:r.get(1)?, credential:r.get(2)?,
                last_seen:r.get(3)?, idle:r.get(4)?, absolute:r.get(5)? }))
            .optional()?.ok_or(SessionError::Invalid)?;
        let principal = Id::new(principal)?;
        let session_id = Id::new(id)?;
        Id::new(credential)?;
        ensure!(now >= last_seen, SessionError::Invalid);
        if now >= idle || now >= absolute {
            retire(&tx, &id, now, "administrator.session.expire", "expired")?;
            tx.commit()?;
            return Err(SessionError::Expired.into());
        }
        // All three browser roles can list networks and read nodes. Do not
        // reuse this policy for operations with different role requirements.
        let all: Option<bool> = tx
            .query_row(
                "SELECT p.all_networks FROM administrator_principals p
             JOIN administrator_credentials c ON c.principal_id=p.id
             WHERE p.id=?1 AND c.id=?2 AND c.credential_type='password'
               AND c.revoked_at IS NULL AND p.enabled=1 AND p.disabled_at IS NULL
               AND p.role IN ('owner','operator','auditor')
               AND (p.role <> 'owner' OR p.all_networks=1)
               AND (p.all_networks=0 OR NOT EXISTS (
                   SELECT 1 FROM administrator_principal_networks g WHERE g.principal_id=p.id))",
                (principal.as_bytes(), &credential),
                |r| r.get(0),
            )
            .optional()?;
        let Some(all) = all else {
            retire(
                &tx,
                &id,
                now,
                "administrator.session.revoke",
                "credential invalidated",
            )?;
            tx.commit()?;
            return Err(SessionError::Invalid.into());
        };
        let list = read(&tx, principal, session_id, all, now)?;
        // Only a successful authorized read can extend the idle deadline.
        let idle = if touch {
            tx.query_row(
                "UPDATE administrator_sessions SET last_seen_at=?1,
                 idle_expires_at=min(?1+idle_lifetime_seconds,absolute_expires_at)
                 WHERE id=?2 AND revoked_at IS NULL RETURNING idle_expires_at",
                (now, &id),
                |r| r.get(0),
            )
            .optional()?
            .ok_or(SessionError::Invalid)?
        } else {
            idle
        };
        tx.commit()?;
        Ok(SessionReply {
            list,
            id: session_id,
            idle,
            absolute,
        })
    }
}

pub(crate) fn session_digest(token: &str) -> Result<[u8; 32], SessionError> {
    secret_digest(b"laneway-admin-session-v1\0", token)
}

pub(crate) fn csrf_digest(token: &str) -> Result<[u8; 32], SessionError> {
    secret_digest(b"laneway-admin-csrf-v1\0", token)
}

fn secret_digest(prefix: &[u8], token: &str) -> Result<[u8; 32], SessionError> {
    let mut decoded = zeroize::Zeroizing::new([0; 32]);
    if token.len() != 43 || URL_SAFE_NO_PAD.decode_slice(token, &mut *decoded) != Ok(decoded.len())
    {
        return Err(SessionError::Invalid);
    }
    Ok(Sha256::new()
        .chain_update(prefix)
        .chain_update(token.as_bytes())
        .finalize()
        .into())
}

fn retire(tx: &Transaction<'_>, id: &[u8; 16], now: i64, action: &str, reason: &str) -> Result<()> {
    ensure!(
        tx.execute(
            "UPDATE administrator_sessions SET revoked_at=?1,revocation_reason=?2
        WHERE id=?3 AND revoked_at IS NULL",
            (now, reason, id)
        )? == 1,
        SessionError::Invalid
    );
    let detail = serde_json::json!({"reason": reason}).to_string();
    tx.execute("INSERT INTO audit_events(id,actor_kind,action,target_type,target_id,details_json,created_at)
        VALUES(randomblob(16),'system',?1,'administrator_session',?2,?3,?4)",(action,id,detail,now))?;
    Ok(())
}
