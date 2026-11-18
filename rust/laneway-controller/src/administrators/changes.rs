//! Password work runs outside this module. Recheck the actor, role and
//! browser CSRF within the same write transaction as each durable change.
use super::{AdministratorError, Principal, principal};
use crate::{
    ListError, RootCredential, SessionStore,
    management_write::verify_browser_write,
    password::PasswordHash,
    recovery::{AuditActor, insert_password, valid_username},
};
use anyhow::{Result, ensure};
use laneway_protocol::Id;
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::json;
use std::collections::HashSet;

pub enum Caller<'a> {
    Browser {
        token: &'a str,
        csrf: Option<&'a str>,
    },
    Bearer {
        header: &'a str,
        root: Option<&'a RootCredential>,
    },
}

#[derive(PartialEq, Eq)]
pub struct Access {
    pub role: String,
    pub all_networks: bool,
    pub networks: Vec<Id>,
}

pub enum Change {
    Create {
        username: String,
        access: Access,
        password: PasswordHash,
    },
    Update {
        id: Id,
        access: Option<Access>,
        enabled: Option<bool>,
    },
    ReplacePassword {
        id: Id,
        password: PasswordHash,
    },
    RevokeSession {
        session: Id,
        reason: String,
    },
}

pub struct Changed {
    pub principal: Option<Principal>,
    pub session: Option<SessionMetadata>,
    pub clear_cookies: bool,
}

type SessionMetadata = (Id, i64, i64);

impl Principal {
    pub fn id(&self) -> &str {
        &self.principal_id
    }
}

impl SessionStore {
    pub(crate) fn administrator_operation<T>(
        &mut self,
        caller: Caller<'_>,
        run: impl FnOnce(&Transaction<'_>, AuditActor, Option<(Id, Id)>, i64) -> Result<T>,
    ) -> Result<(T, Option<SessionMetadata>)> {
        match caller {
            Caller::Bearer { header, root } => self
                .root_write(header, root, |tx, principal, now| {
                    run(
                        tx,
                        AuditActor("service_principal", Some(*principal.as_bytes())),
                        None,
                        now,
                    )
                })
                .map(|result| (result, None)),
            Caller::Browser { token, csrf } => {
                let result =
                    self.with_session(token, false, |tx, principal, session, _, now| {
                        verify_browser_write(tx, session, csrf, false)?;
                        let result = run(
                            tx,
                            AuditActor("administrator", Some(*principal.as_bytes())),
                            Some((principal, session)),
                            now,
                        )?;
                        let live = tx.query_row(
                            "SELECT revoked_at IS NULL FROM administrator_sessions WHERE id=?1",
                            [session.as_bytes()],
                            |row| row.get::<_, bool>(0),
                        )?;
                        Ok((result, live))
                    })?;
                let (value, live) = result.list;
                Ok((
                    value,
                    live.then_some((result.id, result.idle, result.absolute)),
                ))
            }
        }
    }

    // Do not allocate an Argon2 worker for an unauthorized caller. Repeat
    // authorization even after a successful preflight: privileges may change.
    pub fn check_administrator_change(&mut self, caller: Caller<'_>) -> Result<()> {
        self.administrator_operation(caller, |_, _, _, _| Ok(()))
            .map(|_| ())
    }

    pub fn change_administrator(&mut self, caller: Caller<'_>, change: Change) -> Result<Changed> {
        let ((principal, clear_cookies), session) = self.administrator_operation(caller, |tx, actor, browser, now| {
            let setup: bool = tx.query_row(
                "SELECT bootstrap_completed_at IS NOT NULL FROM administrator_auth_state WHERE singleton=1",
                [], |row| row.get(0),
            )?;
            ensure!(setup, AdministratorError::Conflict);
            match change {
                Change::Create { username, access, password } => {
                    Ok((Some(create(tx, &actor, &username, access, &password, now)?), false))
                }
                Change::Update { id, access, enabled } => {
                    Ok((Some(update(tx, &actor, id, access, enabled, now)?), false))
                }
                Change::ReplacePassword { id, password } => {
                    replace_password(tx, &actor, id, &password, now)?;
                    Ok((None, browser.is_some_and(|(principal, _)| principal == id)))
                }
                Change::RevokeSession { session, reason } => {
                    revoke_family(tx, &actor, session, &reason, now)?;
                    Ok((None, browser.is_some_and(|(_, current)| current == session)))
                }
            }
        })?;
        Ok(Changed {
            principal,
            session,
            clear_cookies,
        })
    }
}

impl Access {
    fn normalize(mut self, tx: &Transaction<'_>) -> Result<Self> {
        ensure!(
            matches!(self.role.as_str(), "owner" | "operator" | "auditor"),
            AdministratorError::Invalid
        );
        ensure!(
            self.role != "owner" || self.all_networks,
            AdministratorError::Invalid
        );
        ensure!(
            !self.all_networks || self.networks.is_empty(),
            AdministratorError::Invalid
        );
        self.networks
            .sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        ensure!(
            self.networks.windows(2).all(|pair| pair[0] != pair[1]),
            AdministratorError::Invalid
        );
        for scope in &self.networks {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
                [scope.as_bytes()],
                |row| row.get(0),
            )?;
            ensure!(exists, AdministratorError::Invalid);
        }
        Ok(self)
    }

    fn insert_scopes(&self, tx: &Transaction<'_>, id: Id, now: i64) -> Result<()> {
        for network in &self.networks {
            tx.execute(
                "INSERT INTO administrator_principal_networks(principal_id,network_id,created_at) VALUES(?1,?2,?3)",
                params![id.as_bytes(), network.as_bytes(), now],
            )?;
        }
        Ok(())
    }

    fn audit(&self, enabled: bool, explicit: bool) -> serde_json::Value {
        let ids = (explicit || !self.networks.is_empty()).then(|| {
            self.networks
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        });
        json!({"Role": self.role, "Enabled": enabled, "AllNetworks": self.all_networks, "NetworkIDs": ids})
    }
}

fn create(
    tx: &Transaction<'_>,
    actor: &AuditActor,
    username: &str,
    access: Access,
    password: &PasswordHash,
    now: i64,
) -> Result<Principal> {
    ensure!(valid_username(username), AdministratorError::Invalid);
    let access = access.normalize(tx)?;
    let duplicate: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM administrator_principals WHERE username=?1)",
        [username],
        |row| row.get(0),
    )?;
    ensure!(!duplicate, AdministratorError::Conflict);
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw)
        .map_err(|_| anyhow::anyhow!("administrator identity generation failed"))?;
    let id = Id::new(raw)?;
    tx.execute(
        "INSERT INTO administrator_principals(id,username,role,all_networks,enabled,created_at,updated_at)
         VALUES(?1,?2,?3,?4,1,?5,?5)",
        params![raw, username, access.role, access.all_networks, now],
    )?;
    access.insert_scopes(tx, id, now)?;
    insert_password(tx, raw, password, now)?;
    actor.write(
        tx,
        "administrator.create",
        "administrator",
        Some(raw),
        json!({
            "before": {"Role": "", "Enabled": false, "AllNetworks": false, "NetworkIDs": null},
            "after": access.audit(true, true),
        }),
        now,
    )?;
    principal(tx, id)
}

struct ActiveSessions {
    ids: Vec<Id>,
    at: i64,
}

impl ActiveSessions {
    fn load(tx: &Transaction<'_>, id: Id, record: &Principal, now: i64) -> Result<Self> {
        let mut result = Self {
            ids: Vec::new(),
            at: now
                .max(record.created_at_unix_seconds)
                .max(record.updated_at_unix_seconds)
                .max(record.password_updated_at_unix_seconds),
        };
        let mut stmt = tx.prepare(
            "SELECT id,max(created_at,last_seen_at) FROM administrator_sessions
             WHERE principal_id=?1 AND revoked_at IS NULL ORDER BY created_at,id",
        )?;
        let mut rows = stmt.query([id.as_bytes()])?;
        while let Some(row) = rows.next()? {
            result.ids.push(Id::new(row.get(0)?)?);
            result.at = result.at.max(row.get(1)?);
        }
        Ok(result)
    }

    fn revoke(self, tx: &Transaction<'_>, actor: &AuditActor, reason: &str) -> Result<()> {
        for id in self.ids {
            revoke_session(tx, actor, id, reason, self.at)?;
        }
        Ok(())
    }
}

fn revoke_session(
    tx: &Transaction<'_>,
    actor: &AuditActor,
    id: Id,
    reason: &str,
    at: i64,
) -> Result<()> {
    ensure!(tx.execute(
        "UPDATE administrator_sessions SET revoked_at=?2,revocation_reason=?3 WHERE id=?1 AND revoked_at IS NULL",
        params![id.as_bytes(), at, reason],
    )? == 1, AdministratorError::Conflict);
    actor.write(
        tx,
        "administrator.session.revoke",
        "administrator_session",
        Some(*id.as_bytes()),
        json!({"reason": reason}),
        at,
    )
}

fn update(
    tx: &Transaction<'_>,
    actor: &AuditActor,
    id: Id,
    access: Option<Access>,
    enabled: Option<bool>,
    now: i64,
) -> Result<Principal> {
    ensure!(
        access.is_some() || enabled.is_some(),
        AdministratorError::Invalid
    );
    let record = principal(tx, id)?;
    let before = Access {
        role: record.role.clone(),
        all_networks: record.all_networks,
        networks: record
            .network_ids
            .iter()
            .map(|n| n.parse())
            .collect::<Result<_, _>>()?,
    };
    let explicit = access.is_some();
    let after = access.map(|value| value.normalize(tx)).transpose()?;
    let after = after.as_ref().unwrap_or(&before);
    let enabled = enabled.unwrap_or(record.enabled);
    if &before == after && enabled == record.enabled {
        return Ok(record);
    }
    if before.role == "owner" && record.enabled && (after.role != "owner" || !enabled) {
        let owners: i64 = tx.query_row(
            "SELECT count(*) FROM administrator_principals WHERE role='owner' AND enabled=1",
            [],
            |row| row.get(0),
        )?;
        ensure!(owners > 1, AdministratorError::Conflict);
    }
    let sessions = ActiveSessions::load(tx, id, &record, now)?;
    let at = sessions.at;
    tx.execute(
        "DELETE FROM administrator_principal_networks WHERE principal_id=?1",
        [id.as_bytes()],
    )?;
    ensure!(tx.execute(
        "UPDATE administrator_principals SET role=?2,all_networks=?3,enabled=?4,updated_at=?5,disabled_at=?6 WHERE id=?1",
        params![id.as_bytes(), after.role, after.all_networks, enabled, at, (!enabled).then_some(at)],
    )? == 1, ListError::Missing);
    after.insert_scopes(tx, id, at)?;
    actor.write(
        tx,
        "administrator.access.update",
        "administrator",
        Some(*id.as_bytes()),
        json!({
            "before": before.audit(record.enabled, false),
            "after": after.audit(enabled, explicit),
        }),
        at,
    )?;
    sessions.revoke(tx, actor, "administrator access changed")?;
    principal(tx, id)
}

fn replace_password(
    tx: &Transaction<'_>,
    actor: &AuditActor,
    id: Id,
    password: &PasswordHash,
    now: i64,
) -> Result<()> {
    let record = principal(tx, id)?;
    let sessions = ActiveSessions::load(tx, id, &record, now)?;
    let at = sessions.at;
    ensure!(tx.execute(
        "UPDATE administrator_credentials SET revoked_at=?2,revocation_reason='password replaced'
         WHERE principal_id=?1 AND credential_type='password' AND revoked_at IS NULL",
        params![id.as_bytes(), at],
    )? == 1, AdministratorError::Conflict);
    insert_password(tx, *id.as_bytes(), password, at)?;
    tx.execute(
        "UPDATE administrator_principals SET updated_at=?2 WHERE id=?1",
        params![id.as_bytes(), at],
    )?;
    sessions.revoke(tx, actor, "password replaced")?;
    actor.write(
        tx,
        "administrator.password.replace",
        "administrator",
        Some(*id.as_bytes()),
        json!({}),
        at,
    )
}

fn revoke_family(
    tx: &Transaction<'_>,
    actor: &AuditActor,
    start: Id,
    reason: &str,
    now: i64,
) -> Result<()> {
    ensure!(
        (1..=256).contains(&reason.len()),
        AdministratorError::Invalid
    );
    let mut seen = HashSet::new();
    let mut current = Some(start);
    let mut owner = None;
    while let Some(id) = current {
        ensure!(
            seen.insert(id),
            "corrupt administrator session rotation cycle"
        );
        let (principal, revoked, at): ([u8; 16], bool, i64) = tx
            .query_row(
                "SELECT principal_id,revoked_at IS NOT NULL,max(created_at,last_seen_at)
             FROM administrator_sessions WHERE id=?1",
                [id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or(ListError::Missing)?;
        ensure!(
            *owner.get_or_insert(principal) == principal,
            "cross-principal administrator session family"
        );
        if !revoked {
            revoke_session(tx, actor, id, reason, now.max(at))?;
        }
        current = tx
            .query_row(
                "SELECT id FROM administrator_sessions WHERE previous_session_id=?1",
                [id.as_bytes()],
                |row| row.get::<_, [u8; 16]>(0),
            )
            .optional()?
            .map(Id::new)
            .transpose()?;
    }
    Ok(())
}
