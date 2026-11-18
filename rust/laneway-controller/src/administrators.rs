//! Administrator inventory and durable markers for external root-token rotation.
use crate::{
    ListError, RootCredential, SessionError, SessionReply, SessionStore, bearer, check_snapshot,
    open_existing, recovery::valid_username,
};
use anyhow::{Result, ensure};
use laneway_protocol::Id;
use rusqlite::{OpenFlags, OptionalExtension, Row, Transaction, params};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum AdministratorError {
    #[error("invalid {0}")]
    Id(&'static str),
    #[error("username must be one canonical administrator username")]
    Username,
    #[error("request conflicts with controller state")]
    Conflict,
}

#[derive(Clone, Copy)]
pub enum Rotation {
    Begin,
    Complete,
}

impl SessionStore {
    pub fn record_root_rotation(
        &mut self,
        header: &str,
        root: Option<&RootCredential>,
        id: Result<Id, AdministratorError>,
        phase: Rotation,
    ) -> Result<()> {
        // The operator replaces the protected token and restarts the service.
        // Both phases authenticate the credential loaded by that process.
        self.root_write(header, root, |tx, actor, now| {
            let id = id?;
            let key = id.as_bytes();
            let existing: Option<(i64, bool)> = tx.query_row(
                "SELECT begun_at,completed_at IS NOT NULL FROM administrator_root_token_rotations
                 WHERE rotation_id=?1",
                [key], |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional()?;
            let (at, action) = match (phase, existing) {
                (Rotation::Begin, Some(_)) | (Rotation::Complete, Some((_, true))) => return Ok(()),
                (Rotation::Complete, None) => return Err(AdministratorError::Conflict.into()),
                (Rotation::Begin, None) => (now, "administrator.root_token.rotate.begin"),
                (Rotation::Complete, Some((begun, false))) => {
                    (now.max(begun), "administrator.root_token.rotate.complete")
                }
            };
            let event: [u8; 16] = tx.query_row(
                "INSERT INTO audit_events(id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
                 VALUES(randomblob(16),'service_principal',?1,?2,'root_administrator_token_rotation',?3,?4,?5)
                 RETURNING id",
                params![actor.as_bytes(), action, key, serde_json::json!({"rotation_id": id.to_string()}).to_string(), at],
                |row| row.get(0),
            )?;
            match phase {
                Rotation::Begin => {
                    tx.execute(
                        "INSERT INTO administrator_root_token_rotations(rotation_id,begin_audit_event_id,begun_at)
                         VALUES(?1,?2,?3)", params![key, event, at],
                    )?;
                }
                Rotation::Complete => {
                    ensure!(tx.execute(
                        "UPDATE administrator_root_token_rotations SET complete_audit_event_id=?2,completed_at=?3
                         WHERE rotation_id=?1 AND completed_at IS NULL AND complete_audit_event_id IS NULL",
                        params![key, event, at],
                    )? == 1, AdministratorError::Conflict);
                }
            }
            Ok(())
        })
    }
}

pub enum Read {
    List(Result<usize, ListError>),
    Username(Result<String, AdministratorError>),
    Principal(Result<Id, AdministratorError>),
    Sessions(Result<Id, AdministratorError>, Result<usize, ListError>),
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum Inventory {
    List { administrators: Vec<Principal> },
    Principal(Principal),
    Sessions { sessions: Vec<Session> },
}

#[derive(Serialize)]
pub struct Principal {
    principal_id: String,
    username: String,
    role: String,
    enabled: bool,
    all_networks: bool,
    network_ids: Vec<String>,
    created_at_unix_seconds: i64,
    updated_at_unix_seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    disabled_at_unix_seconds: Option<i64>,
    password_updated_at_unix_seconds: i64,
}

#[derive(Serialize)]
pub struct Session {
    session_id: String,
    principal_id: String,
    state: &'static str,
    current: bool,
    created_at_unix_seconds: i64,
    last_seen_at_unix_seconds: i64,
    idle_lifetime_seconds: i64,
    maximum_sessions: u32,
    idle_expires_at_unix_seconds: i64,
    absolute_expires_at_unix_seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at_unix_seconds: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    revocation_reason: String,
}

pub fn bearer_inventory(
    database: &Path,
    header: &str,
    root: Option<&RootCredential>,
    request: Read,
) -> Result<Inventory> {
    let mut db = open_existing(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let tx = db.transaction()?;
    check_snapshot(&tx)?;
    bearer::authenticate(&tx, header, root)?.require_root()?;
    let now = tx.query_row("SELECT unixepoch()", [], |row| row.get(0))?;
    let inventory = read(&tx, request, None, now)?;
    tx.commit()?;
    Ok(inventory)
}

impl SessionStore {
    pub fn administrator_inventory(
        &mut self,
        token: &str,
        request: Read,
    ) -> Result<SessionReply<Inventory>> {
        self.with_session(token, false, |tx, actor, session, _, now| {
            let owner: bool = tx.query_row(
                "SELECT role='owner' FROM administrator_principals WHERE id=?1",
                [actor.as_bytes()],
                |row| row.get(0),
            )?;
            ensure!(
                owner && !matches!(request, Read::Username(_)),
                SessionError::Denied
            );
            read(tx, request, Some(session), now)
        })
    }
}

fn read(tx: &Transaction<'_>, request: Read, current: Option<Id>, now: i64) -> Result<Inventory> {
    let setup: bool = tx.query_row(
        "SELECT bootstrap_completed_at IS NOT NULL FROM administrator_auth_state WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    match request {
        Read::List(limit) => {
            let limit = checked_limit(limit?)?;
            let ids = if setup {
                tx.prepare(
                    "SELECT id FROM administrator_principals ORDER BY created_at,id LIMIT ?1",
                )?
                .query_map([limit], |row| row.get::<_, [u8; 16]>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
            } else {
                Vec::new()
            };
            let administrators = ids
                .into_iter()
                .map(|id| principal(tx, Id::new(id)?))
                .collect::<Result<_>>()?;
            Ok(Inventory::List { administrators })
        }
        Read::Username(username) => {
            let username = username?;
            ensure!(valid_username(&username), AdministratorError::Username);
            let id = if setup {
                tx.query_row(
                    "SELECT id FROM administrator_principals WHERE username=?1",
                    [username],
                    |row| row.get::<_, [u8; 16]>(0),
                )
                .optional()?
                .map(Id::new)
                .transpose()?
            } else {
                None
            };
            let administrators = match id.map(|id| principal(tx, id)).transpose() {
                Ok(value) => value.into_iter().collect(),
                Err(err) if matches!(err.downcast_ref::<ListError>(), Some(ListError::Missing)) => {
                    Vec::new()
                }
                Err(err) => return Err(err),
            };
            Ok(Inventory::List { administrators })
        }
        Read::Principal(id) => {
            let id = id?;
            ensure!(setup, ListError::Missing);
            Ok(Inventory::Principal(principal(tx, id)?))
        }
        Read::Sessions(id, limit) => {
            let id = id?;
            let limit = checked_limit(limit?)?;
            let sessions = if setup {
                principal(tx, id)?;
                tx.prepare(
                    "SELECT id,created_at,last_seen_at,idle_lifetime_seconds,maximum_sessions,
                            idle_expires_at,absolute_expires_at,revoked_at,revocation_reason
                     FROM administrator_sessions WHERE principal_id=?1
                     ORDER BY created_at DESC,id DESC LIMIT ?2",
                )?
                .query_map(params![id.as_bytes(), limit], |row| {
                    session(row, id, current, now)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
            } else {
                Vec::new()
            };
            Ok(Inventory::Sessions { sessions })
        }
    }
}

fn checked_limit(limit: usize) -> Result<i64> {
    ensure!((1..=1000).contains(&limit), ListError::Limit);
    Ok(limit as i64)
}

fn principal(tx: &Transaction<'_>, id: Id) -> Result<Principal> {
    let mut result = tx.query_row(
        "SELECT p.username,p.role,p.enabled,p.all_networks,p.created_at,p.updated_at,p.disabled_at,c.created_at
         FROM administrator_principals p
         JOIN administrator_credentials c ON c.principal_id=p.id AND c.credential_type='password' AND c.revoked_at IS NULL
         WHERE p.id=?1",
        [id.as_bytes()],
        |row| Ok(Principal {
            principal_id: id.to_string(),
            username: row.get(0)?,
            role: row.get(1)?,
            enabled: row.get(2)?,
            all_networks: row.get(3)?,
            network_ids: Vec::new(),
            created_at_unix_seconds: row.get(4)?,
            updated_at_unix_seconds: row.get(5)?,
            disabled_at_unix_seconds: row.get(6)?,
            password_updated_at_unix_seconds: row.get(7)?,
        }),
    ).optional()?.ok_or(ListError::Missing)?;
    result.network_ids = tx.prepare(
        "SELECT network_id FROM administrator_principal_networks WHERE principal_id=?1 ORDER BY network_id",
    )?.query_map([id.as_bytes()], |row| row.get::<_, [u8;16]>(0))?
        .map(|raw| Ok(Id::new(raw?)?.to_string()))
        .collect::<Result<_>>()?;
    Ok(result)
}

fn session(
    row: &Row<'_>,
    principal: Id,
    current: Option<Id>,
    now: i64,
) -> rusqlite::Result<Session> {
    let raw = row.get::<_, [u8; 16]>(0)?;
    let id = Id::new(raw).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(err))
    })?;
    let idle = row.get(5)?;
    let absolute = row.get(6)?;
    let revoked: Option<i64> = row.get(7)?;
    let state = if revoked.is_some() {
        "revoked"
    } else if now >= idle || now >= absolute {
        "expired"
    } else {
        "active"
    };
    Ok(Session {
        session_id: id.to_string(),
        principal_id: principal.to_string(),
        current: Some(id) == current,
        state,
        created_at_unix_seconds: row.get(1)?,
        last_seen_at_unix_seconds: row.get(2)?,
        idle_lifetime_seconds: row.get(3)?,
        maximum_sessions: row.get(4)?,
        idle_expires_at_unix_seconds: idle,
        absolute_expires_at_unix_seconds: absolute,
        revoked_at_unix_seconds: revoked,
        revocation_reason: row.get(8)?,
    })
}
