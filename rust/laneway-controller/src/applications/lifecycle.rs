//! Management of registered applications. State changes and their audit
//! events share a transaction with credential and installation revocation.
use super::{
    application,
    secrets::{Purpose, id, new_secret},
};
use crate::{
    ListError, SessionStore,
    administrators::{AdministratorError, Caller},
    recovery::AuditActor,
};
use anyhow::{Result, ensure};
use laneway_protocol::Id;
use rusqlite::{Transaction, params};
use serde_json::json;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub enum Action {
    RotateSecret,
    Disable,
    Delete,
}

pub struct Outcome {
    pub secret: Option<Zeroizing<String>>,
    pub session: Option<(Id, i64, i64)>,
}

impl SessionStore {
    pub fn change_registered_application(
        &mut self,
        caller: Caller<'_>,
        app: Result<Id>,
        action: Action,
    ) -> Result<Outcome> {
        let (secret, session) = self.administrator_operation(caller, |tx, actor, _, now| {
            let id = app?;
            let registered = application(tx, id)?;
            let secret = match action {
                Action::RotateSecret => {
                    ensure!(registered.enabled, ListError::Missing);
                    Some(rotate(tx, &actor, id, now)?)
                }
                Action::Disable => {
                    ensure!(registered.enabled, ListError::Missing);
                    disable(tx, &actor, id, now.max(registered.updated_at_unix_seconds))?;
                    None
                }
                Action::Delete => {
                    ensure!(!registered.enabled, AdministratorError::Conflict);
                    delete(tx, &actor, id, now)?;
                    None
                }
            };
            Ok(secret)
        })?;
        Ok(Outcome { secret, session })
    }
}

fn revoke_secrets(tx: &Transaction<'_>, app: Id, now: i64) -> Result<()> {
    tx.execute(
        "UPDATE registered_application_credentials SET revoked_at=max(created_at,?2)
        WHERE application_id=?1 AND revoked_at IS NULL",
        params![app.as_bytes(), now],
    )?;
    Ok(())
}

fn rotate(
    tx: &Transaction<'_>,
    actor: &AuditActor,
    app: Id,
    now: i64,
) -> Result<Zeroizing<String>> {
    let key = id()?;
    let (secret, hash) = new_secret(Purpose::Client, key)?;
    revoke_secrets(tx, app, now)?;
    tx.execute(
        "INSERT INTO registered_application_credentials(id,application_id,secret_hash,created_at)
        VALUES(?1,?2,?3,?4)",
        params![key.as_bytes(), app.as_bytes(), hash, now],
    )?;
    actor.write(
        tx,
        "application.client_secret_rotate",
        "application",
        Some(*app.as_bytes()),
        json!({}),
        now,
    )?;
    Ok(secret)
}

fn disable(tx: &Transaction<'_>, actor: &AuditActor, app: Id, now: i64) -> Result<()> {
    ensure!(
        tx.execute(
            "UPDATE registered_applications SET enabled=0,updated_at=?2,disabled_at=?2
        WHERE id=?1 AND enabled=1",
            params![app.as_bytes(), now]
        )? == 1,
        ListError::Missing
    );
    revoke_secrets(tx, app, now)?;
    // Resolve the service identities before disabling the installation rows.
    // These are the identities checked by the regular bearer middleware.
    tx.execute("UPDATE automation_service_principals SET enabled=0,updated_at=max(updated_at,?2),disabled_at=max(created_at,?2)
        WHERE enabled=1 AND id IN (SELECT service_principal_id FROM application_installations
            WHERE application_id=?1 AND enabled=1)",params![app.as_bytes(),now])?;
    tx.execute("UPDATE automation_service_access_tokens SET revoked_at=max(created_at,?2),revocation_reason='registered application disabled'
        WHERE revoked_at IS NULL AND principal_id IN (SELECT service_principal_id FROM application_installations
            WHERE application_id=?1 AND enabled=1)",params![app.as_bytes(),now])?;
    tx.execute("UPDATE application_installations SET enabled=0,updated_at=max(updated_at,?2),revoked_at=max(created_at,?2)
        WHERE application_id=?1 AND enabled=1",params![app.as_bytes(),now])?;
    tx.execute("UPDATE application_refresh_token_families SET revoked_at=max(created_at,?2),revocation_reason='registered application disabled'
        WHERE application_id=?1 AND revoked_at IS NULL",params![app.as_bytes(),now])?;
    actor.write(
        tx,
        "application.disable",
        "application",
        Some(*app.as_bytes()),
        json!({}),
        now,
    )
}

fn delete(tx: &Transaction<'_>, actor: &AuditActor, app: Id, now: i64) -> Result<()> {
    tx.execute(
        "DELETE FROM application_installations WHERE application_id=?1",
        [app.as_bytes()],
    )?;
    ensure!(
        tx.execute(
            "DELETE FROM registered_applications WHERE id=?1 AND enabled=0",
            [app.as_bytes()]
        )? == 1,
        ListError::Missing
    );
    // Bearer identity rows and audit events are retained. The schema cascades
    // the disabled application's private manifest, codes and credentials.
    actor.write(
        tx,
        "application.delete",
        "application",
        Some(*app.as_bytes()),
        json!({}),
        now,
    )
}
