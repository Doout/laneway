//! Managed-access administration against the existing controller database.
mod inventory;
mod named;
pub(crate) mod service_ports;
mod subjects;
use crate::{
    RootCredential, SessionError, SessionReply, SessionStore, management_write::BrowserWrite,
    sessions::check_network,
};
use anyhow::{Result, ensure};
use laneway_protocol::Id;
use rusqlite::{OptionalExtension, Transaction};
use serde_json::{Value, json};
pub use service_ports::{Port, ServiceProtocol};

#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("record not found")]
    Missing,
    #[error("request conflicts with controller state")]
    Conflict,
}

pub enum Request {
    Inventory(Id),
    CreateUser(Id, String),
    SetUserEnabled(Id, bool),
    CreateTeam(Id, String),
    SetMember(Id, Id, bool),
    CreateGrant {
        net: Id,
        subject: Subject,
        target: Target,
    },
    DeleteGrant(Id),
    CreateResource(Id, String, ResourceTarget),
    SetResourceEnabled(Id, bool),
    CreateService(Id, String, ServiceProtocol, Vec<Port>),
    SetServiceEnabled(Id, bool),
    CreateResourceGrant {
        net: Id,
        subject: Subject,
        resource: Id,
        service: Id,
    },
    DeleteResourceGrant(Id),
}

#[derive(Clone, Copy)]
pub enum Subject {
    User(Id),
    Team(Id),
}
#[derive(Clone, Copy)]
pub enum Target {
    Network,
    Node(Id),
    Exit(Id),
}
pub enum ResourceTarget {
    Node(Id),
    Prefix { route: Id, prefix: ipnet::IpNet },
}

struct Scope {
    network: Id,
    object: bool,
}
struct Actor {
    kind: &'static str,
    id: Id,
}

impl Request {
    pub fn is_read(&self) -> bool {
        matches!(self, Self::Inventory(_))
    }
    fn permission(&self) -> &'static str {
        if self.is_read() {
            "acl.read"
        } else {
            "acl.manage"
        }
    }
    fn scope(&self, tx: &Transaction<'_>) -> Result<Scope> {
        let object = match self {
            Self::Inventory(net)
            | Self::CreateUser(net, _)
            | Self::CreateTeam(net, _)
            | Self::CreateResource(net, ..)
            | Self::CreateService(net, ..)
            | Self::CreateResourceGrant { net, .. }
            | Self::CreateGrant { net, .. } => {
                return Ok(Scope {
                    network: *net,
                    object: false,
                });
            }
            Self::SetUserEnabled(id, _) => ("SELECT network_id FROM access_users WHERE id=?", id),
            Self::SetMember(id, _, _) => ("SELECT network_id FROM access_teams WHERE id=?", id),
            Self::DeleteGrant(id) => ("SELECT network_id FROM access_grants WHERE id=?", id),
            Self::SetResourceEnabled(id, _) => {
                ("SELECT network_id FROM access_resources WHERE id=?", id)
            }
            Self::SetServiceEnabled(id, _) => {
                ("SELECT network_id FROM access_services WHERE id=?", id)
            }
            Self::DeleteResourceGrant(id) => (
                "SELECT network_id FROM access_resource_grants WHERE id=?",
                id,
            ),
        };
        let network = tx
            .query_row(object.0, [object.1.as_bytes()], |r| r.get::<_, [u8; 16]>(0))
            .optional()?
            .ok_or(AccessError::Missing)?;
        Ok(Scope {
            network: Id::new(network)?,
            object: true,
        })
    }
    fn execute(self, tx: &Transaction<'_>, net: Id, actor: Actor, now: i64) -> Result<Value> {
        let editor = subjects::Editor {
            tx,
            net,
            actor,
            now,
        };
        match self {
            Self::Inventory(_) => inventory::read(tx, net),
            Self::CreateUser(_, name) => editor.create_subject(&name, false),
            Self::CreateTeam(_, name) => editor.create_subject(&name, true),
            Self::SetUserEnabled(id, on) => editor.set_user_enabled(id, on),
            Self::SetMember(team, user, present) => editor.member(team, user, present),
            Self::CreateGrant {
                subject, target, ..
            } => editor.grant(subject, target),
            Self::DeleteGrant(id) => editor.delete_grant(id),
            Self::CreateResource(_, name, target) => editor.create_resource(&name, target),
            Self::SetResourceEnabled(id, on) => editor.toggle_named(id, on, false),
            Self::CreateService(_, name, proto, ports) => {
                editor.create_service(&name, proto, ports)
            }
            Self::SetServiceEnabled(id, on) => editor.toggle_named(id, on, true),
            Self::CreateResourceGrant {
                subject,
                resource,
                service,
                ..
            } => editor.resource_grant(subject, resource, service),
            Self::DeleteResourceGrant(id) => editor.delete_resource_grant(id),
        }
    }
}
impl Scope {
    fn conceal(&self, result: Result<()>) -> Result<()> {
        if self.object
            && result.as_ref().is_err_and(|e| {
                matches!(e.downcast_ref::<SessionError>(), Some(SessionError::Denied))
            })
        {
            return Err(AccessError::Missing.into());
        }
        result
    }
}

impl SessionStore {
    pub fn browser_access(
        &mut self,
        token: &str,
        csrf: Option<&str>,
        read: bool,
        request: Result<Request>,
    ) -> Result<SessionReply<Value>> {
        let run = |tx: &Transaction<'_>, id: Id, all: bool, now: i64| {
            let req = request?;
            ensure!(
                read == req.is_read(),
                "access request and session mode differ"
            );
            let scope = req.scope(tx)?;
            if !all {
                scope.conceal(check_network(tx, id, scope.network))?;
            }
            req.execute(
                tx,
                scope.network,
                Actor {
                    kind: "administrator",
                    id,
                },
                now,
            )
        };
        if read {
            self.with_session(token, true, |tx, id, _, all, now| run(tx, id, all, now))
        } else {
            self.browser_write(token, csrf, BrowserWrite::ManageAccess, run)
        }
    }

    pub fn bearer_access(
        &mut self,
        header: &str,
        root: Option<&RootCredential>,
        request: Result<Request>,
    ) -> Result<Value> {
        self.bearer_write(header, root, |tx, actor, now| {
            let req = request?;
            let permission = req.permission();
            actor.authorize(tx, permission, None)?;
            let scope = req.scope(tx)?;
            scope.conceal(actor.authorize(tx, permission, Some(scope.network)))?;
            req.execute(
                tx,
                scope.network,
                Actor {
                    kind: "service_principal",
                    id: actor.id,
                },
                now,
            )
        })
    }
}

fn change(
    tx: &Transaction<'_>,
    net: Id,
    actor: &Actor,
    now: i64,
    action: &str,
    target: (&str, Id),
    details: Value,
) -> Result<i64> {
    let epoch = tx
        .query_row(
            "UPDATE networks SET configuration_epoch=configuration_epoch+1
        WHERE id=? AND configuration_epoch<9223372036854775807 RETURNING configuration_epoch",
            [net.as_bytes()],
            |r| r.get(0),
        )
        .optional()?
        .ok_or(AccessError::Conflict)?;
    tx.execute("INSERT INTO audit_events(id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
        VALUES(randomblob(16),?,?,?,?,?,?,?,?)",rusqlite::params![net.as_bytes(),actor.kind,actor.id.as_bytes(),action,target.0,target.1.as_bytes(),details.to_string(),now])?;
    Ok(epoch)
}
fn epoch_reply(epoch: i64) -> Value {
    json!({"configuration_epoch":epoch})
}
fn next_id() -> Result<Id> {
    let mut id = [0; 16];
    getrandom::fill(&mut id)?;
    Ok(Id::new(id)?)
}
fn conflict<T>(value: rusqlite::Result<T>) -> Result<T> {
    match value {
        Err(rusqlite::Error::SqliteFailure(e, _))
            if matches!(
                e.extended_code,
                rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                    | rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                    | rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY
            ) =>
        {
            Err(AccessError::Conflict.into())
        }
        other => Ok(other?),
    }
}
fn row_id(row: &rusqlite::Row<'_>, col: usize) -> Result<Id> {
    Ok(Id::new(row.get::<_, [u8; 16]>(col)?)?)
}

fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= 253 && name.trim() == name && !name.contains('\0'),
        AccessError::Invalid("name must be 1..253 trimmed bytes")
    );
    Ok(())
}
