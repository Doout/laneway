//! Network and global audit reads against the Go-compatible SQLite schema.
use crate::{
    ListError, RootCredential, SessionError, SessionReply, SessionStore, bearer, check_snapshot,
    open_existing, sessions::check_network,
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use laneway_protocol::{ID_LEN, Id};
use rusqlite::{OpenFlags, Row, Transaction, params_from_iter, types::Value as SqlValue};
use serde::Serialize;
use serde_json::value::RawValue;
use std::path::Path;

const ID_START: usize = 2;
const TIME_START: usize = ID_START + ID_LEN;
const EVENT_START: usize = TIME_START + 8;
const CURSOR_LEN: usize = EVENT_START + ID_LEN;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CursorError {
    #[error("cursor is not a valid opaque audit cursor")]
    Invalid,
    #[error("cursor does not belong to this audit scope")]
    Scope,
}

#[derive(Debug)]
pub struct Cursor {
    id: Id,
    created_at: i64,
    network: Option<Id>,
}
impl Cursor {
    pub fn decode(raw: &str, network: Option<Id>) -> Result<Self, CursorError> {
        // 42 bytes encode to exactly 56 characters with raw URL-safe base64.
        if raw.len() != 56 {
            return Err(CursorError::Invalid);
        }
        let mut bytes = [0; CURSOR_LEN];
        let size = URL_SAFE_NO_PAD
            .decode_slice(raw, &mut bytes)
            .map_err(|_| CursorError::Invalid)?;
        if size != CURSOR_LEN || bytes[0] != 1 || URL_SAFE_NO_PAD.encode(bytes) != raw {
            return Err(CursorError::Invalid);
        }
        let expected = network.as_ref().map_or([0; ID_LEN], |id| *id.as_bytes());
        if bytes[1] != u8::from(network.is_some()) || bytes[ID_START..TIME_START] != expected {
            return Err(CursorError::Scope);
        }
        let created_at = i64::from_be_bytes(bytes[TIME_START..EVENT_START].try_into().unwrap());
        let id = Id::from_slice(&bytes[EVENT_START..]).map_err(|_| CursorError::Invalid)?;
        if created_at < 0 {
            return Err(CursorError::Invalid);
        }
        Ok(Self {
            id,
            created_at,
            network,
        })
    }
    fn encode(&self) -> String {
        let mut bytes = [0; CURSOR_LEN];
        bytes[0] = 1;
        if let Some(network) = &self.network {
            bytes[1] = 1;
            bytes[ID_START..TIME_START].copy_from_slice(network.as_bytes());
        }
        bytes[TIME_START..EVENT_START].copy_from_slice(&self.created_at.to_be_bytes());
        bytes[EVENT_START..].copy_from_slice(self.id.as_bytes());
        URL_SAFE_NO_PAD.encode(bytes)
    }
}

pub struct AuditQuery {
    pub network: Option<Id>,
    pub limit: usize,
    pub before: Option<Cursor>,
    pub paged: bool,
}

#[derive(Serialize)]
pub struct AuditPage {
    events: Vec<AuditEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct AuditEvent {
    event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_id: Option<String>,
    actor_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_node_id: Option<String>,
    action: String,
    target_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_id: Option<String>,
    details: Box<RawValue>,
    created_at_unix_seconds: i64,
}

fn optional_id(raw: Option<[u8; ID_LEN]>) -> Result<Option<String>> {
    Ok(raw.map(Id::new).transpose()?.map(|id| id.to_string()))
}

fn read_event(row: &Row<'_>, event: Id, created_at: i64) -> Result<AuditEvent> {
    let actor_kind: String = row.get(2)?;
    let actor_id = optional_id(row.get(3)?)?;
    let needs_id = match actor_kind.as_str() {
        "node" | "administrator" | "service_principal" | "recovery_grant" => true,
        "system" | "unauthenticated" | "legacy_unknown" => false,
        _ => anyhow::bail!("invalid audit actor kind"),
    };
    ensure!(actor_id.is_some() == needs_id, "invalid audit actor");
    Ok(AuditEvent {
        event_id: event.to_string(),
        network_id: optional_id(row.get(1)?)?,
        actor_node_id: (actor_kind == "node").then(|| actor_id.clone()).flatten(),
        actor_kind,
        actor_id,
        action: row.get(4)?,
        target_type: row.get(5)?,
        target_id: optional_id(row.get(6)?)?,
        // Keep the exact JSON numbers and data stored by either controller.
        details: RawValue::from_string(row.get(7)?)?,
        created_at_unix_seconds: created_at,
    })
}

fn page(tx: &Transaction<'_>, request: AuditQuery) -> Result<AuditPage> {
    let AuditQuery {
        network,
        limit,
        before,
        paged,
    } = request;
    ensure!((1..=1000).contains(&limit), ListError::Limit);
    ensure!(
        before
            .as_ref()
            .is_none_or(|cursor| cursor.network == network),
        CursorError::Scope
    );
    let mut sql = String::from(
        "SELECT id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at FROM audit_events",
    );
    let mut args = Vec::new();
    if let Some(network) = network {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?)",
            [network.as_bytes()],
            |row| row.get(0),
        )?;
        ensure!(exists, ListError::Missing);
        sql.push_str(" WHERE network_id=?");
        args.push(SqlValue::Blob(network.as_bytes().to_vec()));
    }
    if let Some(cursor) = before {
        sql.push_str(if network.is_some() { " AND" } else { " WHERE" });
        sql.push_str(" (created_at,id)<(?,?)");
        args.push(SqlValue::Integer(cursor.created_at));
        args.push(SqlValue::Blob(cursor.id.as_bytes().to_vec()));
    }
    sql.push_str(" ORDER BY created_at DESC,id DESC LIMIT ?");
    args.push(SqlValue::Integer(limit as i64 + i64::from(paged)));
    let mut stmt = tx.prepare(&sql)?;
    let mut rows = stmt.query(params_from_iter(args))?;
    let mut events = Vec::new();
    let mut last = None;
    while events.len() < limit {
        let Some(row) = rows.next()? else { break };
        let id = Id::new(row.get(0)?)?;
        let created_at = row.get(8)?;
        events.push(read_event(row, id, created_at)?);
        last = Some(Cursor {
            id,
            created_at,
            network,
        });
    }
    let next_cursor = if paged && rows.next()?.is_some() {
        last.map(|key| key.encode())
    } else {
        None
    };
    Ok(AuditPage {
        events,
        next_cursor,
    })
}

impl SessionStore {
    pub fn audit(
        &mut self,
        token: &str,
        request: Result<AuditQuery>,
    ) -> Result<SessionReply<AuditPage>> {
        self.with_session(token, true, |tx, principal, _, all, _| {
            let query = request?;
            if let Some(network) = query.network {
                if !all { check_network(tx, principal, network)?; }
            } else {
                let owner: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM administrator_principals WHERE id=? AND role='owner')",
                    [principal.as_bytes()], |row| row.get(0),
                )?;
                ensure!(owner, SessionError::Denied);
            }
            page(tx, query)
        })
    }
}

pub fn bearer_audit(
    database: &Path,
    header: &str,
    root: Option<&RootCredential>,
    request: Result<AuditQuery>,
) -> Result<AuditPage> {
    let mut db = open_existing(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let tx = db.transaction()?;
    check_snapshot(&tx)?;
    let actor = bearer::authenticate(&tx, header, root)?;
    let query = request?;
    let op = if query.network.is_some() {
        "audit.read"
    } else {
        "audit.read_global"
    };
    actor.authorize(&tx, op, query.network)?;
    let reply = page(&tx, query)?;
    tx.commit()?;
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_rejects_invalid_sort_keys_and_scopes() {
        let network = Id::new([1; ID_LEN]).unwrap();
        let encoded = Cursor {
            id: Id::new([2; ID_LEN]).unwrap(),
            created_at: 17,
            network: Some(network),
        }
        .encode();
        assert_eq!(
            Cursor::decode(&encoded, Some(network)).unwrap().created_at,
            17
        );
        assert_eq!(
            Cursor::decode(&encoded, None).unwrap_err(),
            CursorError::Scope
        );

        let bytes = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        for (offset, value) in [(0, 2), (TIME_START, 128)] {
            let mut invalid = bytes.clone();
            invalid[offset] = value;
            assert_eq!(
                Cursor::decode(&URL_SAFE_NO_PAD.encode(invalid), Some(network)).unwrap_err(),
                CursorError::Invalid
            );
        }
        let mut invalid = bytes;
        invalid[EVENT_START..].fill(0);
        assert_eq!(
            Cursor::decode(&URL_SAFE_NO_PAD.encode(invalid), Some(network)).unwrap_err(),
            CursorError::Invalid
        );
    }
}
