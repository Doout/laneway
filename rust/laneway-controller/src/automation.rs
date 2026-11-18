//! Management of immutable automation identities and their bounded credentials.
use crate::{
    ListError, RootCredential, SessionError, SessionReply, SessionStore,
    administrators::{AdministratorError, Caller},
    bearer, check_snapshot, open_existing,
    recovery::{AuditActor, valid_username},
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use laneway_protocol::Id;
use rusqlite::{ErrorCode, OpenFlags, OptionalExtension, Row, Transaction, params};
use serde::Serialize;
use serde_json::json;
use std::path::Path;
use zeroize::Zeroizing;

pub struct Spec {
    pub name: String,
    pub all_networks: bool,
    pub network_ids: Vec<Id>,
    pub permissions: Vec<String>,
}

pub enum Read {
    Principals(i64),
    Tokens { principal: Id, limit: i64 },
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum Inventory {
    Principals { service_principals: Vec<Principal> },
    Tokens { tokens: Vec<Token> },
}

pub enum Write {
    Create(Spec),
    Disable(Id),
    Issue {
        principal: Id,
        label: String,
        expires: i64,
    },
    Revoke {
        token: Id,
        reason: String,
    },
}

pub enum Written {
    Principal(Principal),
    Issued {
        token: Token,
        bearer: Zeroizing<String>,
    },
    Empty,
}

pub struct Change {
    pub result: Written,
    pub session: Option<(Id, i64, i64)>,
}

#[derive(Serialize)]
pub struct Principal {
    pub principal_id: String,
    name: String,
    enabled: bool,
    all_networks: bool,
    network_ids: Vec<String>,
    permissions: Vec<String>,
    created_at_unix_seconds: i64,
    updated_at_unix_seconds: i64,
}

#[derive(Serialize)]
pub struct Token {
    pub token_id: String,
    principal_id: String,
    label: String,
    state: &'static str,
    created_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at_unix_seconds: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    revocation_reason: String,
}

pub fn bearer_inventory(
    database: &Path,
    header: &str,
    root: Option<&RootCredential>,
    read: Result<Read>,
) -> Result<Inventory> {
    let mut db = open_existing(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let tx = db.transaction()?;
    check_snapshot(&tx)?;
    bearer::authenticate(&tx, header, root)?.require_root()?;
    let now = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
    let result = inventory(&tx, read?, now)?;
    tx.commit()?;
    Ok(result)
}

impl SessionStore {
    pub fn read_automation(
        &mut self,
        session: &str,
        read: Result<Read>,
    ) -> Result<SessionReply<Inventory>> {
        self.with_session(session, false, |tx, actor, _, _, now| {
            let owner: bool = tx.query_row(
                "SELECT role='owner' FROM administrator_principals WHERE id=?1",
                [actor.as_bytes()],
                |r| r.get(0),
            )?;
            ensure!(owner, SessionError::Denied);
            inventory(tx, read?, now)
        })
    }

    pub fn write_automation(&mut self, caller: Caller<'_>, write: Write) -> Result<Change> {
        let (result, session) =
            self.administrator_operation(caller, |tx, actor, _, now| match write {
                Write::Create(spec) => Ok(Written::Principal(create(tx, &actor, spec, now)?)),
                Write::Issue {
                    principal,
                    label,
                    expires,
                } => issue(tx, &actor, principal, label, expires, now),
                Write::Disable(id) => {
                    disable(tx, &actor, id, now)?;
                    Ok(Written::Empty)
                }
                Write::Revoke { token, reason } => {
                    revoke(tx, &actor, token, &reason, now)?;
                    Ok(Written::Empty)
                }
            })?;
        Ok(Change { result, session })
    }
}

// None means this authority is not delegable at all. A mixed global/scoped
// credential may call both kinds of operations, but scoped ones need a scope.
fn authority(op: &str) -> Option<bool> {
    Some(match op {
        "network.create" | "bootstrap_bundle.create" | "audit.read_global" => false,
        "network.list" | "network.read" | "enrollment.issue" | "node.read" | "node.manage"
        | "route.read" | "route.manage" | "acl.read" | "acl.manage" | "relay.read"
        | "relay.manage" | "certificate.read" | "certificate.revoke" | "audit.read" => true,
        _ => return None,
    })
}

fn valid_authority(all: bool, scoped: bool, permissions: &[String]) -> bool {
    if permissions.is_empty() || (all && scoped) {
        return false;
    }
    let mut requires_scope = false;
    for op in permissions {
        let Some(network) = authority(op) else {
            return false;
        };
        requires_scope |= network;
    }
    requires_scope == (all || scoped)
}

fn principal(tx: &Transaction<'_>, id: Id) -> Result<Principal> {
    let mut principal = tx.query_row(
        "SELECT name,enabled,all_networks,created_at,updated_at FROM automation_service_principals WHERE id=?1",
        [id.as_bytes()], |r| Ok(Principal {
            principal_id: id.to_string(), name: r.get(0)?, enabled: r.get(1)?, all_networks: r.get(2)?,
            network_ids: Vec::new(), permissions: Vec::new(), created_at_unix_seconds: r.get(3)?, updated_at_unix_seconds: r.get(4)?,
        }),
    ).optional()?.ok_or(ListError::Missing)?;
    principal.network_ids = tx.prepare(
        "SELECT network_id FROM automation_service_principal_networks WHERE principal_id=?1 ORDER BY network_id",
    )?.query_map([id.as_bytes()], |r| r.get::<_, [u8; 16]>(0))?
        .map(|raw| Ok(Id::new(raw?)?.to_string())).collect::<Result<_>>()?;
    principal.permissions = tx.prepare(
        "SELECT operation FROM automation_service_principal_permissions WHERE principal_id=?1 ORDER BY operation",
    )?.query_map([id.as_bytes()], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    ensure!(
        valid_username(&principal.name)
            && valid_authority(
                principal.all_networks,
                !principal.network_ids.is_empty(),
                &principal.permissions,
            ),
        "corrupt automation principal"
    );
    Ok(principal)
}

fn id_column(row: &Row<'_>, index: usize) -> rusqlite::Result<String> {
    let raw = row.get::<_, [u8; 16]>(index)?;
    Id::new(raw).map(|id| id.to_string()).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Blob, Box::new(e))
    })
}

fn token(row: &Row<'_>, now: i64) -> rusqlite::Result<Token> {
    let revoked = row.get::<_, Option<i64>>(5)?;
    let expires: i64 = row.get(4)?;
    Ok(Token {
        token_id: id_column(row, 0)?,
        principal_id: id_column(row, 1)?,
        label: row.get(2)?,
        state: if revoked.is_some() {
            "revoked"
        } else if expires <= now {
            "expired"
        } else {
            "active"
        },
        created_at_unix_seconds: row.get(3)?,
        expires_at_unix_seconds: expires,
        revoked_at_unix_seconds: revoked,
        revocation_reason: row.get(6)?,
    })
}

fn inventory(tx: &Transaction<'_>, read: Read, now: i64) -> Result<Inventory> {
    match read {
        Read::Principals(limit) => {
            ensure!((1..=1000).contains(&limit), ListError::Limit);
            let ids = tx.prepare(
                "SELECT id FROM automation_service_principals ORDER BY enabled DESC,created_at DESC,id DESC LIMIT ?1",
            )?.query_map([limit], |r| r.get::<_, [u8;16]>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(Inventory::Principals {
                service_principals: ids
                    .into_iter()
                    .map(|raw| principal(tx, Id::new(raw)?))
                    .collect::<Result<_>>()?,
            })
        }
        Read::Tokens {
            principal: id,
            limit,
        } => {
            ensure!((1..=1000).contains(&limit), ListError::Limit);
            principal(tx, id)?;
            let tokens = tx.prepare(
                "SELECT id,principal_id,label,created_at,expires_at,revoked_at,revocation_reason
                 FROM automation_service_access_tokens WHERE principal_id=?1
                 ORDER BY CASE WHEN revoked_at IS NOT NULL THEN 2 WHEN expires_at<=?2 THEN 1 ELSE 0 END,
                   created_at DESC,id DESC LIMIT ?3",
            )?.query_map(params![id.as_bytes(), now, limit], |r| token(r, now))?
                .collect::<rusqlite::Result<_>>()?;
            Ok(Inventory::Tokens { tokens })
        }
    }
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut bytes = Zeroizing::new([0; N]);
    getrandom::fill(bytes.as_mut_slice())
        .map_err(|_| anyhow::anyhow!("automation randomness unavailable"))?;
    Ok(bytes)
}

fn insert(result: rusqlite::Result<usize>) -> Result<()> {
    match result {
        Ok(1) => Ok(()),
        Ok(_) => Err(AdministratorError::Conflict.into()),
        Err(err) if err.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) => {
            Err(AdministratorError::Conflict.into())
        }
        Err(err) => Err(err.into()),
    }
}

fn create(tx: &Transaction<'_>, actor: &AuditActor, mut spec: Spec, now: i64) -> Result<Principal> {
    ensure!(
        valid_username(&spec.name)
            && valid_authority(
                spec.all_networks,
                !spec.network_ids.is_empty(),
                &spec.permissions
            ),
        AdministratorError::Invalid
    );
    spec.network_ids
        .sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    spec.permissions.sort_unstable();
    ensure!(
        spec.network_ids.windows(2).all(|p| p[0] != p[1])
            && spec.permissions.windows(2).all(|p| p[0] != p[1]),
        AdministratorError::Invalid
    );
    let setup: bool = tx.query_row(
        "SELECT bootstrap_completed_at IS NOT NULL FROM administrator_auth_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    ensure!(setup, AdministratorError::Conflict);
    for network in &spec.network_ids {
        let known: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
            [network.as_bytes()],
            |r| r.get(0),
        )?;
        ensure!(known, AdministratorError::Invalid);
    }
    let id = Id::new(*random::<16>()?)?;
    insert(tx.execute(
        "INSERT INTO automation_service_principals(id,name,all_networks,created_at,updated_at)
         VALUES(?1,?2,?3,?4,?4)",
        params![id.as_bytes(), spec.name, spec.all_networks, now],
    ))?;
    for network in &spec.network_ids {
        tx.execute(
            "INSERT INTO automation_service_principal_networks(principal_id,network_id,created_at)
            VALUES(?1,?2,?3)",
            params![id.as_bytes(), network.as_bytes(), now],
        )?;
    }
    for operation in &spec.permissions {
        tx.execute("INSERT INTO automation_service_principal_permissions(principal_id,operation,created_at)
            VALUES(?1,?2,?3)", params![id.as_bytes(), operation, now])?;
    }
    let result = principal(tx, id)?;
    actor.write(tx, "service_principal.create", "service_principal", Some(*id.as_bytes()),
        json!({"name": result.name, "all_networks": result.all_networks, "network_ids": result.network_ids,
               "permissions": result.permissions}), now)?;
    Ok(result)
}

fn valid_label(label: &str, max: usize) -> bool {
    (1..=max).contains(&label.len()) && label == label.trim() && !label.contains('\0')
}

fn issue(
    tx: &Transaction<'_>,
    actor: &AuditActor,
    id: Id,
    label: String,
    expires: i64,
    now: i64,
) -> Result<Written> {
    ensure!(
        valid_label(&label, 64) && expires > now && expires <= now.saturating_add(365 * 86400),
        AdministratorError::Invalid
    );
    ensure!(principal(tx, id)?.enabled, ListError::Missing);
    let token = Id::new(*random::<16>()?)?;
    let secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(random::<32>()?.as_slice()));
    let digest = bearer::automation_digest(token, &secret);
    insert(tx.execute(
        "INSERT INTO automation_service_access_tokens(id,principal_id,label,token_hash,created_at,expires_at)
         VALUES(?1,?2,?3,?4,?5,?6)", params![token.as_bytes(), id.as_bytes(), label, digest, now, expires],
    ))?;
    actor.write(
        tx,
        "service_access_token.issue",
        "service_access_token",
        Some(*token.as_bytes()),
        json!({"label": label, "expires_at_unix_seconds": expires}),
        now,
    )?;
    let bearer = Zeroizing::new(format!("lnw_spat_v1.{token}.{}", secret.as_str()));
    Ok(Written::Issued {
        token: Token {
            token_id: token.to_string(),
            principal_id: id.to_string(),
            label,
            state: "active",
            created_at_unix_seconds: now,
            expires_at_unix_seconds: expires,
            revoked_at_unix_seconds: None,
            revocation_reason: String::new(),
        },
        bearer,
    })
}

fn revoke(tx: &Transaction<'_>, actor: &AuditActor, id: Id, reason: &str, now: i64) -> Result<()> {
    ensure!(valid_label(reason, 256), AdministratorError::Invalid);
    let (created, revoked): (i64, bool) = tx.query_row(
        "SELECT created_at,revoked_at IS NOT NULL FROM automation_service_access_tokens WHERE id=?1",
        [id.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional()?.ok_or(ListError::Missing)?;
    ensure!(!revoked, AdministratorError::Conflict);
    let now = now.max(created);
    tx.execute(
        "UPDATE automation_service_access_tokens SET revoked_at=?2,revocation_reason=?3 WHERE id=?1 AND revoked_at IS NULL",
        params![id.as_bytes(), now, reason],
    )?;
    actor.write(
        tx,
        "service_access_token.revoke",
        "service_access_token",
        Some(*id.as_bytes()),
        json!({"reason": reason}),
        now,
    )
}

fn disable(tx: &Transaction<'_>, actor: &AuditActor, id: Id, now: i64) -> Result<()> {
    let principal = principal(tx, id)?;
    ensure!(principal.enabled, AdministratorError::Conflict);
    let now = now.max(principal.updated_at_unix_seconds);
    tx.execute(
        "UPDATE automation_service_principals SET enabled=0,updated_at=?2,disabled_at=?2 WHERE id=?1 AND enabled=1",
        params![id.as_bytes(), now],
    )?;
    let revoked = tx.execute(
        "UPDATE automation_service_access_tokens SET revoked_at=max(created_at,?2),revocation_reason='service principal disabled'
         WHERE principal_id=?1 AND revoked_at IS NULL", params![id.as_bytes(), now],
    )?;
    actor.write(
        tx,
        "service_principal.disable",
        "service_principal",
        Some(*id.as_bytes()),
        json!({"revoked_tokens": revoked}),
        now,
    )
}
