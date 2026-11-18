//! Network approval, installation identity, and one-time authorization codes.
use super::{
    Registered, application, callback, normalize_scopes,
    secrets::{Purpose, challenge_valid, id, new_secret},
};
use crate::{
    ListError, RootCredential, SessionError, SessionReply, SessionStore,
    administrators::{AdministratorError, Caller},
    bearer, check_snapshot,
    management_write::verify_browser_write,
    open_existing,
    sessions::check_network,
};
use anyhow::{Result, ensure};
use laneway_protocol::Id;
use rusqlite::{OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;
use serde_json::json;
use std::path::Path;
use zeroize::Zeroizing;

struct Pending {
    app: Id,
    application: Registered,
    redirect: String,
    state: String,
    scopes: Vec<String>,
    challenge: String,
    created: i64,
    expires: i64,
}

#[derive(Serialize)]
pub struct Review {
    request_id: String,
    application: Registered,
    redirect_uri: String,
    scopes: Vec<String>,
    expires_at_unix_seconds: i64,
}

#[derive(Serialize)]
pub struct Installations {
    application_installations: Vec<Installation>,
}

#[derive(Serialize)]
struct Installation {
    installation_id: String,
    application_id: String,
    network_id: String,
    service_principal_id: String,
    scopes: Vec<String>,
    enabled: bool,
    created_at_unix_seconds: i64,
    updated_at_unix_seconds: i64,
}

pub enum Action {
    Approve {
        network: Id,
        request: Id,
        scopes: Vec<String>,
    },
    Cancel {
        network: Id,
        request: Id,
    },
    Revoke(Id),
}

pub struct Outcome {
    pub redirect: Option<Zeroizing<String>>,
    pub session: Option<(Id, i64, i64)>,
}

fn pending(tx: &Transaction<'_>, request: Id) -> Result<Pending> {
    let data = tx.query_row("SELECT application_id,redirect_uri,state,scopes_json,pkce_challenge,created_at,expires_at
        FROM application_authorization_requests WHERE id=?1 AND consumed_at IS NULL",
        [request.as_bytes()],
        |r| Ok((r.get::<_,[u8;16]>(0)?,r.get(1)?,r.get(2)?,r.get::<_,String>(3)?,r.get(4)?,r.get(5)?,r.get(6)?)),
    ).optional()?.ok_or(ListError::Missing)?;
    let app = Id::new(data.0)?;
    Ok(Pending {
        app,
        application: application(tx, app)?,
        redirect: data.1,
        state: data.2,
        scopes: serde_json::from_str(&data.3)?,
        challenge: data.4,
        created: data.5,
        expires: data.6,
    })
}

fn subset(candidate: &[String], ceiling: &[String]) -> bool {
    candidate.iter().all(|scope| ceiling.contains(scope))
}

impl SessionStore {
    pub fn start_application_authorization(
        &mut self,
        client: &str,
        redirect: &str,
        scopes: Vec<String>,
        state: &str,
        challenge: &str,
    ) -> Result<Id> {
        let scopes = normalize_scopes(scopes)?;
        ensure!(
            (1..=1024).contains(&state.len())
                && !state.contains('\0')
                && challenge_valid(challenge),
            AdministratorError::Invalid
        );
        let app: Id = client
            .strip_prefix("lnw_client_v1.")
            .ok_or(SessionError::Invalid)?
            .parse()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let registered = application(&tx, app)?;
        ensure!(
            registered.enabled
                && registered.client_id == client
                && registered
                    .manifest
                    .redirect_uris
                    .iter()
                    .any(|uri| uri == redirect)
                && subset(&scopes, &registered.manifest.scopes),
            SessionError::Invalid
        );
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        let request = id()?;
        tx.execute("DELETE FROM application_authorization_requests WHERE id IN (
            SELECT id FROM application_authorization_requests WHERE expires_at<=?1 ORDER BY expires_at,id LIMIT 100)",[now])?;
        tx.execute("DELETE FROM application_authorization_codes WHERE id IN (
            SELECT id FROM application_authorization_codes WHERE expires_at<=?1 ORDER BY expires_at,id LIMIT 100)",[now])?;
        tx.execute(
            "INSERT INTO application_authorization_requests
            (id,application_id,redirect_uri,state,scopes_json,pkce_challenge,created_at,expires_at)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                request.as_bytes(),
                app.as_bytes(),
                redirect,
                state,
                serde_json::to_string(&scopes)?,
                challenge,
                now,
                now + 600
            ],
        )?;
        tx.commit()?;
        Ok(request)
    }

    pub fn change_application_installation(
        &mut self,
        caller: Caller<'_>,
        action: Action,
    ) -> Result<Outcome> {
        match caller {
            Caller::Bearer { header, root } => self
                .root_write(header, root, |tx, actor, now| {
                    change(
                        tx,
                        action,
                        None,
                        Audit {
                            actor,
                            kind: "service_principal",
                        },
                        now,
                    )
                })
                .map(|redirect| Outcome {
                    redirect,
                    session: None,
                }),
            Caller::Browser { token, csrf } => {
                let reply = self.with_session(token, false, |tx, actor, session, all, now| {
                    // Operators can delegate all five OAuth scopes only on their
                    // own networks. Auditors cannot mutate installations.
                    verify_browser_write(tx, session, csrf, true)?;
                    change(
                        tx,
                        action,
                        Some(all),
                        Audit {
                            actor,
                            kind: "administrator",
                        },
                        now,
                    )
                })?;
                Ok(Outcome {
                    redirect: reply.list,
                    session: Some((reply.id, reply.idle, reply.absolute)),
                })
            }
        }
    }

    pub fn list_application_installations(
        &mut self,
        token: &str,
        query: Result<(Id, i64)>,
    ) -> Result<SessionReply<Installations>> {
        self.with_session(token, false, |tx, actor, _, all, _| {
            let (network, limit) = query?;
            if !all {
                check_network(tx, actor, network)?;
            }
            inventory(tx, network, limit)
        })
    }
}

pub fn read_request(database: &Path, request: Id) -> Result<Review> {
    let mut db = open_existing(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let tx = db.transaction()?;
    check_snapshot(&tx)?;
    let p = pending(&tx, request)?;
    let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
    ensure!(p.application.enabled && now < p.expires, ListError::Missing);
    let review = Review {
        request_id: request.to_string(),
        application: p.application,
        redirect_uri: p.redirect,
        scopes: p.scopes,
        expires_at_unix_seconds: p.expires,
    };
    tx.commit()?;
    Ok(review)
}

pub fn bearer_list(
    database: &Path,
    header: &str,
    root: Option<&RootCredential>,
    query: Result<(Id, i64)>,
) -> Result<Installations> {
    let mut db = open_existing(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let tx = db.transaction()?;
    check_snapshot(&tx)?;
    bearer::authenticate(&tx, header, root)?.require_root()?;
    let (network, limit) = query?;
    let result = inventory(&tx, network, limit)?;
    tx.commit()?;
    Ok(result)
}

fn inventory(tx: &Transaction<'_>, network: Id, limit: i64) -> Result<Installations> {
    ensure!((1..=1000).contains(&limit), ListError::Limit);
    let mut stmt=tx.prepare("SELECT id,application_id,service_principal_id,enabled,created_at,updated_at
        FROM application_installations WHERE network_id=?1 ORDER BY enabled DESC,created_at DESC,id DESC LIMIT ?2")?;
    let mut rows = stmt.query(params![network.as_bytes(), limit])?;
    let mut application_installations = Vec::new();
    while let Some(row) = rows.next()? {
        let id = Id::new(row.get(0)?)?;
        application_installations.push(Installation {
            installation_id: id.to_string(),
            application_id: Id::new(row.get(1)?)?.to_string(),
            network_id: network.to_string(),
            service_principal_id: Id::new(row.get(2)?)?.to_string(),
            scopes: installation_scopes(tx, id)?,
            enabled: row.get(3)?,
            created_at_unix_seconds: row.get(4)?,
            updated_at_unix_seconds: row.get(5)?,
        });
    }
    Ok(Installations {
        application_installations,
    })
}

pub(super) fn installation_scopes(tx: &Transaction<'_>, installation: Id) -> Result<Vec<String>> {
    Ok(tx.prepare("SELECT scope FROM application_installation_scopes WHERE installation_id=?1 ORDER BY scope")?
        .query_map([installation.as_bytes()],|r|r.get(0))?.collect::<rusqlite::Result<_>>()?)
}

struct Audit {
    actor: Id,
    kind: &'static str,
}

impl Audit {
    fn write(
        &self,
        tx: &Transaction<'_>,
        network: Id,
        action: &str,
        target: Id,
        details: serde_json::Value,
        now: i64,
    ) -> Result<()> {
        tx.execute("INSERT INTO audit_events(id,network_id,actor_id,actor_kind,action,target_type,target_id,details_json,created_at)
            VALUES(randomblob(16),?1,?2,?3,?4,'application_installation',?5,?6,?7)",
            params![network.as_bytes(),self.actor.as_bytes(),self.kind,action,target.as_bytes(),details.to_string(),now])?;
        Ok(())
    }
}

fn change(
    tx: &Transaction<'_>,
    action: Action,
    browser: Option<bool>,
    audit: Audit,
    now: i64,
) -> Result<Option<Zeroizing<String>>> {
    let authorize = |network| {
        if browser == Some(false) {
            check_network(tx, audit.actor, network)?;
        }
        Ok::<_, anyhow::Error>(())
    };
    match action {
        Action::Approve {
            network,
            request,
            scopes,
        } => {
            ensure!(browser.is_some(), SessionError::Denied);
            authorize(network)?;
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
                [network.as_bytes()],
                |r| r.get(0),
            )?;
            ensure!(exists, ListError::Missing);
            let scopes = normalize_scopes(scopes)?;
            let p = pending(tx, request)?;
            ensure!(
                now >= p.created
                    && now < p.expires
                    && p.application.enabled
                    && subset(&scopes, &p.scopes)
                    && subset(&scopes, &p.application.manifest.scopes),
                ListError::Missing
            );
            let (installation, service) = upsert(tx, p.app, network, audit.actor, &scopes, now)?;
            let code_id = id()?;
            let (code, digest) = new_secret(Purpose::Authorization, code_id)?;
            tx.execute("INSERT INTO application_authorization_codes
                (id,installation_id,application_id,network_id,redirect_uri,scopes_json,code_hash,pkce_challenge,created_at,expires_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                 params![code_id.as_bytes(),installation.as_bytes(),p.app.as_bytes(),network.as_bytes(),p.redirect,
                    serde_json::to_string(&scopes)?,digest,p.challenge,now,now+300])?;
            consume(tx, request, now)?;
            audit.write(tx,network,"application_installation.authorize",installation,json!({
                "application_id":p.app.to_string(),"service_principal_id":service.to_string(),"scopes":scopes,
            }),now)?;
            Ok(Some(callback(
                &p.redirect,
                &[("code", &code), ("state", &p.state)],
            )?))
        }
        Action::Cancel { network, request } => {
            ensure!(browser.is_some(), SessionError::Denied);
            authorize(network)?;
            let p = pending(tx, request)?;
            consume(tx, request, now.max(p.created))?;
            Ok(Some(callback(
                &p.redirect,
                &[("error", "access_denied"), ("state", &p.state)],
            )?))
        }
        Action::Revoke(id) => {
            let (network,service,enabled,updated):([u8;16],[u8;16],bool,i64)=tx.query_row(
                "SELECT network_id,service_principal_id,enabled,updated_at FROM application_installations WHERE id=?1",
                [id.as_bytes()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
            ).optional()?.ok_or(ListError::Missing)?;
            let network = Id::new(network)?;
            authorize(network)?;
            ensure!(enabled, ListError::Missing);
            let now = now.max(updated);
            tx.execute("UPDATE application_installations SET enabled=0,updated_at=?2,revoked_at=?2 WHERE id=?1",
                params![id.as_bytes(),now])?;
            retire(
                tx,
                id,
                Id::new(service)?,
                now,
                "application installation revoked",
            )?;
            audit.write(
                tx,
                network,
                "application_installation.revoke",
                id,
                json!({}),
                now,
            )?;
            Ok(None)
        }
    }
}

fn consume(tx: &Transaction<'_>, request: Id, now: i64) -> Result<()> {
    ensure!(tx.execute("UPDATE application_authorization_requests SET consumed_at=?2 WHERE id=?1 AND consumed_at IS NULL",
        params![request.as_bytes(),now])?==1,AdministratorError::Conflict);
    Ok(())
}

fn upsert(
    tx: &Transaction<'_>,
    app: Id,
    network: Id,
    actor: Id,
    scopes: &[String],
    now: i64,
) -> Result<(Id, Id)> {
    let existing:Option<([u8;16],[u8;16])>=tx.query_row(
        "SELECT id,service_principal_id FROM application_installations WHERE application_id=?1 AND network_id=?2 AND enabled=1",
        params![app.as_bytes(),network.as_bytes()],|r|Ok((r.get(0)?,r.get(1)?)),
    ).optional()?;
    let existing = existing
        .map(|(i, p)| Ok::<_, anyhow::Error>((Id::new(i)?, Id::new(p)?)))
        .transpose()?;
    if let Some((installation, service)) = existing
        && installation_scopes(tx, installation)? == scopes
    {
        return Ok((installation, service));
    }
    let service = id()?;
    let name = format!(
        "app-{}-{}-{}",
        &app.to_string()[..8],
        &network.to_string()[..8],
        &service.to_string()[..8]
    );
    tx.execute("INSERT INTO automation_service_principals(id,name,created_at,updated_at) VALUES(?1,?2,?3,?3)",params![service.as_bytes(),name,now])?;
    tx.execute("INSERT INTO automation_service_principal_networks(principal_id,network_id,created_at) VALUES(?1,?2,?3)",
        params![service.as_bytes(),network.as_bytes(),now])?;
    let installation = if let Some((installation, previous)) = existing {
        retire(
            tx,
            installation,
            previous,
            now,
            "application installation scopes replaced",
        )?;
        tx.execute(
            "DELETE FROM application_installation_scopes WHERE installation_id=?1",
            [installation.as_bytes()],
        )?;
        tx.execute("UPDATE application_installations SET service_principal_id=?2,installer_principal_id=?3,updated_at=max(updated_at,?4) WHERE id=?1",
            params![installation.as_bytes(),service.as_bytes(),actor.as_bytes(),now])?;
        installation
    } else {
        let installation = id()?;
        tx.execute("INSERT INTO application_installations(id,application_id,network_id,service_principal_id,
            installer_principal_id,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?6)",
            params![installation.as_bytes(),app.as_bytes(),network.as_bytes(),service.as_bytes(),actor.as_bytes(),now])?;
        installation
    };
    for scope in scopes {
        tx.execute("INSERT INTO automation_service_principal_permissions(principal_id,operation,created_at) VALUES(?1,?2,?3)",
            params![service.as_bytes(),scope,now])?;
        tx.execute(
            "INSERT INTO application_installation_scopes(installation_id,scope) VALUES(?1,?2)",
            params![installation.as_bytes(), scope],
        )?;
    }
    Ok((installation, service))
}

fn retire(
    tx: &Transaction<'_>,
    installation: Id,
    principal: Id,
    now: i64,
    reason: &str,
) -> Result<()> {
    tx.execute("UPDATE automation_service_principals SET enabled=0,updated_at=max(updated_at,?2),disabled_at=max(created_at,?2)
        WHERE id=?1 AND enabled=1",params![principal.as_bytes(),now])?;
    tx.execute("UPDATE automation_service_access_tokens SET revoked_at=max(created_at,?2),revocation_reason=?3
        WHERE principal_id=?1 AND revoked_at IS NULL",params![principal.as_bytes(),now,reason])?;
    tx.execute("UPDATE application_refresh_token_families SET revoked_at=max(created_at,?2),revocation_reason=?3
        WHERE installation_id=?1 AND revoked_at IS NULL",params![installation.as_bytes(),now,reason])?;
    tx.execute(
        "UPDATE application_authorization_codes SET consumed_at=max(created_at,?2)
        WHERE installation_id=?1 AND consumed_at IS NULL",
        params![installation.as_bytes(), now],
    )?;
    Ok(())
}
