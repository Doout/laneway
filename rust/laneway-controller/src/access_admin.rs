//! Network-scoped administration against the existing controller database.
mod acl;
mod devices;
mod inventory;
mod named;
mod policy_history;
mod relays;
mod routes;
pub(crate) mod service_ports;
mod subjects;
pub use crate::enrollment::snapshot_policy::AclSelector;
pub use crate::enrollment::{diagnostics::Diagnostics, policy_preview::Preview};
use crate::{
    RootCredential, SessionError, SessionReply, SessionStore,
    management_write::{BrowserWrite, verify_browser_csrf},
    node_location::Location,
    sessions::check_network,
};
pub use acl::AclRule;
use anyhow::{Result, ensure};
use laneway_protocol::Id;
use laneway_protocol::fleet_updates::Create as FleetPlan;
pub use routes::{NodeRouteRequest, RouteKind, RouteMode, RouteSpec};
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
    PrivateDns(Id),
    EndpointStatuses(Id, usize),
    Topology(Id, usize),
    FleetUpdates(Id, usize),
    CreateFleetUpdate(Id, Result<FleetPlan>),
    AdvanceFleetUpdate(Id, Id, bool),
    NodeLocations(Id, usize, Option<&'static str>),
    SetNodeLocation(Id, Option<Location>),
    ListRoutes(Id, usize),
    AssignRoute(Id, Id, RouteSpec),
    ApproveRoute(Id),
    WithdrawRoute(Id),
    ListCertificates(Id, usize),
    RevokeCertificate(Id, Vec<u8>, String),
    RevokeNode(Id, String),
    IssueNodeRecovery(Id, Result<NodeRecoveryApproval>),
    SetNodeCapabilities(Id, u64),
    ListRelays(Id, usize),
    RegisterRelay {
        net: Id,
        service: Id,
        node: Option<Id>,
        name: String,
        endpoint: String,
    },
    UpdateRelay(Id, String, String, bool),
    DisableRelay(Id),
    ListAclRules(Id, usize),
    PolicyPreview(Id, Result<Preview>),
    Diagnostics(Id, Result<Diagnostics>),
    PolicyHistory(Id, usize),
    RestorePolicy(Id, i64, i64),
    CreateAclRule(Id, AclRule),
    UpdateAclRule(Id, AclRule),
    DeleteAclRule(Id),
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

pub struct NodeRecoveryApproval {
    pub certificate_serial: Vec<u8>,
    pub reason: String,
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
pub(crate) struct Actor {
    pub(crate) kind: &'static str,
    pub(crate) id: Id,
}

pub struct AdminReply {
    pub data: Value,
    pub created: Option<bool>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BrowserAccess {
    Read,
    Query,
    Write,
}

impl Request {
    fn browser_access(&self) -> BrowserAccess {
        if matches!(self, Self::PolicyPreview(..) | Self::Diagnostics(..)) {
            BrowserAccess::Query
        } else if self.is_read() {
            BrowserAccess::Read
        } else {
            BrowserAccess::Write
        }
    }

    pub fn is_read(&self) -> bool {
        matches!(
            self,
            Self::Inventory(_)
                | Self::PrivateDns(_)
                | Self::EndpointStatuses(..)
                | Self::Topology(..)
                | Self::FleetUpdates(..)
                | Self::NodeLocations(..)
                | Self::ListAclRules(..)
                | Self::PolicyPreview(..)
                | Self::Diagnostics(..)
                | Self::PolicyHistory(..)
                | Self::ListRoutes(..)
                | Self::ListCertificates(..)
                | Self::ListRelays(..)
        )
    }
    fn permission(&self) -> &'static str {
        match self {
            Self::ListRoutes(..) => "route.read",
            Self::EndpointStatuses(..)
            | Self::Topology(..)
            | Self::FleetUpdates(..)
            | Self::NodeLocations(..) => "node.read",
            Self::ListCertificates(..) => "certificate.read",
            Self::ListRelays(..) => "relay.read",
            Self::RegisterRelay { .. } | Self::UpdateRelay(..) | Self::DisableRelay(_) => {
                "relay.manage"
            }
            Self::RevokeCertificate(..) => "certificate.revoke",
            Self::RevokeNode(..)
            | Self::IssueNodeRecovery(..)
            | Self::CreateFleetUpdate(..)
            | Self::AdvanceFleetUpdate(..)
            | Self::SetNodeCapabilities(..)
            | Self::SetNodeLocation(..) => "node.manage",
            Self::AssignRoute(..) | Self::ApproveRoute(_) | Self::WithdrawRoute(_) => {
                "route.manage"
            }
            _ if self.is_read() => "acl.read",
            _ => "acl.manage",
        }
    }
    fn scope(&self, tx: &Transaction<'_>) -> Result<Scope> {
        let object = match self {
            Self::Inventory(net)
            | Self::PrivateDns(net)
            | Self::EndpointStatuses(net, _)
            | Self::Topology(net, _)
            | Self::FleetUpdates(net, _)
            | Self::CreateFleetUpdate(net, _)
            | Self::AdvanceFleetUpdate(net, ..)
            | Self::NodeLocations(net, ..)
            | Self::ListRoutes(net, _)
            | Self::AssignRoute(net, ..)
            | Self::ListCertificates(net, _)
            | Self::ListRelays(net, _)
            | Self::RegisterRelay { net, .. }
            | Self::RevokeCertificate(net, ..)
            | Self::ListAclRules(net, _)
            | Self::PolicyPreview(net, _)
            | Self::Diagnostics(net, _)
            | Self::PolicyHistory(net, _)
            | Self::RestorePolicy(net, ..)
            | Self::CreateAclRule(net, _)
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
            Self::RevokeNode(id, _)
            | Self::IssueNodeRecovery(id, _)
            | Self::SetNodeCapabilities(id, _)
            | Self::SetNodeLocation(id, _) => ("SELECT network_id FROM nodes WHERE id=?", id),
            Self::UpdateRelay(id, ..) | Self::DisableRelay(id) => {
                ("SELECT network_id FROM relays WHERE id=?", id)
            }
            Self::ApproveRoute(id) | Self::WithdrawRoute(id) => {
                ("SELECT network_id FROM routes WHERE id=?", id)
            }
            Self::UpdateAclRule(id, _) | Self::DeleteAclRule(id) => {
                ("SELECT network_id FROM acl_rules WHERE id=?", id)
            }
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
    fn execute(self, tx: &Transaction<'_>, net: Id, actor: Actor, now: i64) -> Result<AdminReply> {
        let editor = subjects::Editor {
            tx,
            net,
            actor,
            now,
        };
        let data = match self {
            Self::Inventory(_) => inventory::read(tx, net),
            Self::PrivateDns(_) => crate::enrollment::private_dns::admin_catalog(tx, net, now),
            Self::EndpointStatuses(_, limit) => {
                crate::endpoint_status::inventory(tx, net, limit, now)
            }
            Self::Topology(_, limit) => crate::topology::inventory(tx, net, limit, now),
            Self::FleetUpdates(_, limit) => crate::fleet_updates::inventory(tx, net, limit),
            Self::CreateFleetUpdate(_, plan) => {
                crate::fleet_updates::create(tx, net, &editor.actor, now, plan?)
            }
            Self::AdvanceFleetUpdate(_, id, cancel) => {
                crate::fleet_updates::advance(tx, net, &editor.actor, now, id, cancel)?;
                Ok(Value::Null)
            }
            Self::NodeLocations(_, limit, provider) => {
                crate::node_location::inventory(tx, net, now, limit, provider)
            }
            Self::SetNodeLocation(id, location) => editor.set_node_location(id, location),
            Self::ListRoutes(_, limit) => editor.list_routes(limit),
            Self::AssignRoute(_, node, spec) => {
                let (data, created) = editor.assign_route(node, spec)?;
                return Ok(AdminReply {
                    data,
                    created: Some(created),
                });
            }
            Self::ApproveRoute(id) => editor.approve_route(id).map(epoch_reply),
            Self::WithdrawRoute(id) => editor.withdraw_route(id, None).map(epoch_reply),
            Self::ListCertificates(_, limit) => editor.certificates(limit),
            Self::ListRelays(_, limit) => editor.list_relays(limit),
            Self::RegisterRelay {
                service,
                node,
                name,
                endpoint,
                ..
            } => editor.register_relay(service, node, &name, &endpoint),
            Self::UpdateRelay(id, name, endpoint, enabled) => {
                editor.update_relay(id, &name, &endpoint, enabled)
            }
            Self::DisableRelay(id) => editor.disable_relay(id).map(epoch_reply),
            Self::RevokeCertificate(_, serial, reason) => {
                editor.revoke_certificate(&serial, &reason).map(epoch_reply)
            }
            Self::RevokeNode(id, reason) => editor.revoke_node(id, &reason).map(epoch_reply),
            Self::IssueNodeRecovery(node, form) => {
                let form = form?;
                let reason = &form.reason;
                ensure!(
                    !reason.is_empty() && reason == reason.trim() && reason.len() <= 1024,
                    AccessError::Invalid("invalid approval reason")
                );
                let (token, expires) = crate::enrollment::credential_recovery::approve(
                    tx,
                    net,
                    node,
                    now,
                    &form.certificate_serial,
                )?;
                audit(
                    tx,
                    net,
                    &editor.actor,
                    now,
                    "node.credential_recovery.approve",
                    ("node", node),
                    json!({"reason": reason}),
                )?;
                Ok(json!({"recovery_token": token.as_str(), "expires_at_unix_seconds": expires}))
            }
            Self::SetNodeCapabilities(id, capabilities) => editor
                .set_node_capabilities(id, capabilities)
                .map(epoch_reply),
            Self::ListAclRules(_, limit) => editor.list_acl_rules(limit),
            Self::PolicyPreview(_, request) => {
                crate::enrollment::policy_preview::preview(tx, net, now, request)
            }
            Self::Diagnostics(_, request) => {
                crate::enrollment::diagnostics::diagnose(tx, net, now, request)
            }
            Self::PolicyHistory(_, limit) => editor.policy_history(limit),
            Self::RestorePolicy(_, revision, epoch) => editor.restore_policy(revision, epoch),
            Self::CreateAclRule(_, rule) => editor.write_acl_rule(None, rule),
            Self::UpdateAclRule(id, rule) => editor.write_acl_rule(Some(id), rule),
            Self::DeleteAclRule(id) => editor.delete_acl_rule(id),
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
        }?;
        Ok(AdminReply {
            data,
            created: None,
        })
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
        access: BrowserAccess,
        request: Result<Request>,
    ) -> Result<SessionReply<AdminReply>> {
        let run = |tx: &Transaction<'_>, id: Id, all: bool, now: i64| {
            let req = request?;
            ensure!(
                access == req.browser_access(),
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
        match access {
            BrowserAccess::Read => {
                self.with_session(token, true, |tx, id, _, all, now| run(tx, id, all, now))
            }
            BrowserAccess::Query => self.with_session(token, false, |tx, id, session, all, now| {
                verify_browser_csrf(tx, session, csrf)?;
                run(tx, id, all, now)
            }),
            BrowserAccess::Write => {
                self.browser_write(token, csrf, BrowserWrite::ManageAccess, run)
            }
        }
    }

    pub fn bearer_access(
        &mut self,
        header: &str,
        root: Option<&RootCredential>,
        request: Result<Request>,
    ) -> Result<AdminReply> {
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
    audit(tx, net, actor, now, action, target, details)?;
    Ok(epoch)
}
pub(crate) fn audit(
    tx: &Transaction<'_>,
    net: Id,
    actor: &Actor,
    now: i64,
    action: &str,
    target: (&str, Id),
    details: Value,
) -> Result<()> {
    tx.execute("INSERT INTO audit_events(id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
        VALUES(randomblob(16),?,?,?,?,?,?,?,?)",rusqlite::params![net.as_bytes(),actor.kind,actor.id.as_bytes(),action,target.0,target.1.as_bytes(),details.to_string(),now])?;
    Ok(())
}
fn epoch_reply(epoch: i64) -> Value {
    json!({"configuration_epoch":epoch})
}
pub(crate) fn next_id() -> Result<Id> {
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
