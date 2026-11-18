use super::{
    AUTH, Failure, INTERNAL, Reply, State, credential,
    form::{json_form, required_json_form},
    malformed,
    mutations::{DENIED, csrf_proof},
    response, with_session_headers,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    SessionError, SessionStore,
    access_admin::{
        AccessError, AclRule, AclSelector, Port, Request as Action, ResourceTarget, RouteMode,
        RouteSpec, ServiceProtocol, Subject, Target,
    },
};
use laneway_protocol::Id;
use serde::Deserialize;

pub(super) enum Route<'a> {
    Inventory(&'a str),
    EndpointStatuses(&'a str),
    ListRoutes(&'a str),
    AssignSubnet,
    ApproveAdvertisement(&'a str),
    WithdrawAdvertisement(&'a str),
    Certificates(&'a str),
    RevokeCertificate(&'a str, &'a str),
    RevokeNode(&'a str),
    NodeCapabilities(&'a str),
    RelayCollection(&'a str),
    RelayUpdate(&'a str),
    RelayDisable(&'a str),
    AclRules(&'a str),
    AclRule(&'a str),
    UserCreate(&'a str),
    UserUpdate(&'a str),
    TeamCreate(&'a str),
    Membership(&'a str, &'a str),
    GrantCreate(&'a str),
    GrantDelete(&'a str),
    ResourceCreate(&'a str),
    ResourceUpdate(&'a str),
    ServiceCreate(&'a str),
    ServiceUpdate(&'a str),
    ResourceGrantCreate(&'a str),
    ResourceGrantDelete(&'a str),
}
impl<'a> Route<'a> {
    pub(super) fn parse(parts: &[&'a str]) -> Option<Self> {
        use Route::*;
        Some(match parts {
            ["", "v1", "admin", "networks", id, "access-subjects"] => Inventory(id),
            ["", "v1", "admin", "networks", id, "endpoint-statuses"] => EndpointStatuses(id),
            ["", "v1", "admin", "networks", id, "routes"] => ListRoutes(id),
            ["", "v1", "admin", "routes", "assign"] => AssignSubnet,
            ["", "v1", "admin", "routes", id, "approve"] => ApproveAdvertisement(id),
            ["", "v1", "admin", "routes", id, "withdraw"] => WithdrawAdvertisement(id),
            ["", "v1", "admin", "networks", id, "certificates"] => Certificates(id),
            [
                "",
                "v1",
                "admin",
                "networks",
                id,
                "certificates",
                serial,
                "revoke",
            ] => RevokeCertificate(id, serial),
            ["", "v1", "admin", "nodes", id, "revoke"] => RevokeNode(id),
            ["", "v1", "admin", "nodes", id, "capabilities"] => NodeCapabilities(id),
            ["", "v1", "admin", "networks", id, "relays"] => RelayCollection(id),
            ["", "v1", "admin", "relays", id] => RelayUpdate(id),
            ["", "v1", "admin", "relays", id, "disable"] => RelayDisable(id),
            ["", "v1", "admin", "networks", id, "acl-rules"] => AclRules(id),
            ["", "v1", "admin", "acl-rules", id] => AclRule(id),
            ["", "v1", "admin", "networks", id, "users"] => UserCreate(id),
            ["", "v1", "admin", "users", id] => UserUpdate(id),
            ["", "v1", "admin", "networks", id, "teams"] => TeamCreate(id),
            ["", "v1", "admin", "teams", id, "members", user] => Membership(id, user),
            ["", "v1", "admin", "networks", id, "access-grants"] => GrantCreate(id),
            ["", "v1", "admin", "access-grants", id] => GrantDelete(id),
            ["", "v1", "admin", "networks", id, "resources"] => ResourceCreate(id),
            ["", "v1", "admin", "resources", id] => ResourceUpdate(id),
            ["", "v1", "admin", "networks", id, "services"] => ServiceCreate(id),
            ["", "v1", "admin", "services", id] => ServiceUpdate(id),
            ["", "v1", "admin", "networks", id, "resource-access-grants"] => {
                ResourceGrantCreate(id)
            }
            ["", "v1", "admin", "resource-access-grants", id] => ResourceGrantDelete(id),
            _ => return None,
        })
    }
    fn allow(&self) -> &'static str {
        match self {
            Self::Inventory(_)
            | Self::ListRoutes(_)
            | Self::Certificates(_)
            | Self::EndpointStatuses(_) => "GET, HEAD",
            Self::NodeCapabilities(_) | Self::RelayUpdate(_) => "PUT",
            Self::RelayCollection(_) => "GET, HEAD, POST",
            Self::AclRules(_) => "GET, HEAD, POST",
            Self::AclRule(_) => "DELETE, PUT",
            Self::UserCreate(_)
            | Self::AssignSubnet
            | Self::ApproveAdvertisement(_)
            | Self::WithdrawAdvertisement(_)
            | Self::RevokeCertificate(..)
            | Self::RevokeNode(_)
            | Self::RelayDisable(_)
            | Self::TeamCreate(_)
            | Self::GrantCreate(_)
            | Self::ResourceCreate(_)
            | Self::ServiceCreate(_)
            | Self::ResourceGrantCreate(_) => "POST",
            Self::UserUpdate(_) | Self::ResourceUpdate(_) | Self::ServiceUpdate(_) => "PATCH",
            Self::Membership(..) => "DELETE, PUT",
            Self::GrantDelete(_) | Self::ResourceGrantDelete(_) => "DELETE",
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct NameForm {
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignForm {
    network_id: String,
    node_id: String,
    prefix: ipnet::IpNet,
    mode: RouteMode,
    #[serde(default)]
    metric: u32,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CapabilitiesForm {
    enabled_capabilities: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationForm {
    reason: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayRegisterForm {
    service_id: String,
    node_id: Option<String>,
    name: String,
    endpoint: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayUpdateForm {
    name: String,
    endpoint: String,
    #[serde(default)]
    enabled: bool,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EnabledForm {
    enabled: Option<bool>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AclCreateForm {
    priority: u32,
    action: String,
    selector: Option<AclSelector>,
    description: String,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AclUpdateForm {
    priority: u32,
    action: String,
    selector: Option<AclSelector>,
    description: String,
    enabled: bool,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GrantForm {
    subject_kind: String,
    subject_id: String,
    target_kind: String,
    node_id: String,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ResourceForm {
    name: String,
    target_kind: String,
    node_id: Option<String>,
    route_id: Option<String>,
    prefix: Option<String>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceForm {
    name: String,
    protocol: Option<ServiceProtocol>,
    // An omitted ports field is allowed for non-port protocols; explicit
    // null (and an explicit empty array for any/ICMP) is not.
    #[serde(default, deserialize_with = "non_null_ports")]
    ports: Option<Vec<Port>>,
}
fn non_null_ports<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<Port>>, D::Error> {
    Vec::<Port>::deserialize(deserializer).map(Some)
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ResourceGrantForm {
    subject_kind: String,
    subject_id: String,
    resource_id: String,
    service_id: String,
}

pub(super) async fn handle(
    req: Request<Incoming>,
    state: State,
    id: &str,
    route: Route<'_>,
) -> Result<Reply, Failure> {
    let head = req.method() == Method::HEAD;
    if !route
        .allow()
        .split(", ")
        .any(|method| req.method().as_str() == method)
    {
        let mut r = Failure(
            S::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
            false,
        )
        .reply(id, head);
        r.headers_mut().insert(
            header::ALLOW,
            header::HeaderValue::from_static(route.allow()),
        );
        return Ok(r);
    }
    let auth = credential(req.headers())?;
    let read = matches!(req.method().clone(), Method::GET | Method::HEAD);
    let creates = req.method() == Method::POST
        && matches!(
            route,
            Route::AclRules(_)
                | Route::RelayCollection(_)
                | Route::UserCreate(_)
                | Route::TeamCreate(_)
                | Route::GrantCreate(_)
                | Route::ResourceCreate(_)
                | Route::ServiceCreate(_)
                | Route::ResourceGrantCreate(_)
        );
    let put = req.method() == Method::PUT;
    let proof = (!read)
        .then(|| csrf_proof(req.headers()).filter(|_| crate::origin::same_origin(req.headers())))
        .flatten();
    let action = decode(route, req, put).await.map_err(anyhow::Error::from);
    let permit = state.queries.try_acquire_owned().map_err(|_| {
        Failure(
            S::SERVICE_UNAVAILABLE,
            "ERROR_CODE_RESOURCE_EXHAUSTED",
            "controller busy",
            true,
        )
    })?;
    let (data, meta) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _permit = permit;
        let mut store = SessionStore::open(&state.database)?;
        Ok(match auth {
            super::Credential::Session(token) => {
                let reply = store.browser_access(&token, proof.as_deref(), read, action)?;
                (reply.list, Some((reply.id, reply.idle, reply.absolute)))
            }
            super::Credential::Bearer(header) => (
                store.bearer_access(&header, state.root.as_deref(), action)?,
                None,
            ),
        })
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    let status = if data.created.unwrap_or(creates) {
        S::CREATED
    } else {
        S::OK
    };
    let data = serde_json::to_vec(&data.data).map_err(|_| INTERNAL)?;
    with_session_headers(response(status, id, data, head), meta)
}

async fn decode(route: Route<'_>, req: Request<Incoming>, put: bool) -> Result<Action, Failure> {
    Ok(match route {
        Route::Inventory(net) => Action::Inventory(parse(net)?),
        Route::EndpointStatuses(net) => Action::EndpointStatuses(
            parse(net)?,
            super::query_limit(req.uri().query())
                .map_err(|_| malformed("limit must be an integer from 1 through 1000"))?,
        ),
        Route::ListRoutes(net) => Action::ListRoutes(
            parse(net)?,
            super::query_limit(req.uri().query()).map_err(|_| malformed("invalid limit"))?,
        ),
        Route::AssignSubnet => {
            let f = required_json_form::<AssignForm>(req).await?;
            Action::AssignRoute(
                parse(&f.network_id)?,
                parse(&f.node_id)?,
                RouteSpec {
                    prefix: f.prefix,
                    mode: f.mode,
                    metric: f.metric,
                },
            )
        }
        Route::ApproveAdvertisement(id) => Action::ApproveRoute(parse(id)?),
        Route::WithdrawAdvertisement(id) => Action::WithdrawRoute(parse(id)?),
        Route::Certificates(net) => Action::ListCertificates(
            parse(net)?,
            super::query_limit(req.uri().query()).map_err(|_| malformed("invalid limit"))?,
        ),
        Route::RevokeCertificate(net, serial) => Action::RevokeCertificate(
            parse(net)?,
            super::revocation::parse_serial(serial)
                .filter(|raw| raw[0] != 0)
                .ok_or(malformed("invalid certificate serial"))?,
            required_json_form::<RevocationForm>(req).await?.reason,
        ),
        Route::RevokeNode(id) => Action::RevokeNode(
            parse(id)?,
            required_json_form::<RevocationForm>(req).await?.reason,
        ),
        Route::NodeCapabilities(id) => Action::SetNodeCapabilities(
            parse(id)?,
            json_form::<CapabilitiesForm>(req)
                .await?
                .enabled_capabilities,
        ),
        Route::RelayCollection(net) if req.method() == Method::POST => {
            let net = parse(net)?;
            let form = required_json_form::<RelayRegisterForm>(req).await?;
            Action::RegisterRelay {
                net,
                service: parse(&form.service_id)?,
                node: form
                    .node_id
                    .as_deref()
                    .filter(|id| !id.is_empty())
                    .map(parse)
                    .transpose()?,
                name: form.name,
                endpoint: form.endpoint,
            }
        }
        Route::RelayCollection(net) => Action::ListRelays(
            parse(net)?,
            super::query_limit(req.uri().query()).map_err(|_| malformed("invalid limit"))?,
        ),
        Route::RelayUpdate(id) => {
            let id = parse(id)?;
            let form = required_json_form::<RelayUpdateForm>(req).await?;
            Action::UpdateRelay(id, form.name, form.endpoint, form.enabled)
        }
        Route::RelayDisable(id) => Action::DisableRelay(parse(id)?),
        Route::AclRules(net) if req.method() == Method::POST => {
            let id = parse(net)?;
            let f = json_form::<AclCreateForm>(req).await?;
            Action::CreateAclRule(
                id,
                AclRule {
                    priority: f.priority,
                    action: f.action,
                    selector: f.selector.ok_or(malformed("selector is required"))?,
                    description: f.description,
                    enabled: true,
                },
            )
        }
        Route::AclRules(net) => Action::ListAclRules(
            parse(net)?,
            super::query_limit(req.uri().query()).map_err(|_| malformed("invalid limit"))?,
        ),
        Route::AclRule(id) if put => {
            let id = parse(id)?;
            let f = json_form::<AclUpdateForm>(req).await?;
            Action::UpdateAclRule(
                id,
                AclRule {
                    priority: f.priority,
                    action: f.action,
                    selector: f.selector.ok_or(malformed("selector is required"))?,
                    description: f.description,
                    enabled: f.enabled,
                },
            )
        }
        Route::AclRule(id) => Action::DeleteAclRule(parse(id)?),
        Route::UserCreate(net) => {
            Action::CreateUser(parse(net)?, json_form::<NameForm>(req).await?.name)
        }
        Route::TeamCreate(net) => {
            Action::CreateTeam(parse(net)?, json_form::<NameForm>(req).await?.name)
        }
        Route::UserUpdate(id) => Action::SetUserEnabled(parse(id)?, enabled(req).await?),
        Route::Membership(team, user) => Action::SetMember(parse(team)?, parse(user)?, put),
        Route::GrantDelete(id) => Action::DeleteGrant(parse(id)?),
        Route::GrantCreate(net) => {
            let net = parse(net)?;
            let form = json_form::<GrantForm>(req).await?;
            let subject = subject(&form.subject_kind, &form.subject_id)?;
            let target = match form.target_kind.as_str() {
                "network" if form.node_id.is_empty() => Target::Network,
                "node" => Target::Node(parse(&form.node_id)?),
                "exit" => Target::Exit(parse(&form.node_id)?),
                _ => return Err(malformed("invalid grant target")),
            };
            Action::CreateGrant {
                net,
                subject,
                target,
            }
        }
        Route::ResourceCreate(net) => {
            let net = parse(net)?;
            let form = json_form::<ResourceForm>(req).await?;
            let target = match (
                form.target_kind.as_str(),
                form.node_id.as_deref().filter(|s| !s.is_empty()),
                form.route_id.as_deref().filter(|s| !s.is_empty()),
                form.prefix.as_deref().filter(|s| !s.is_empty()),
            ) {
                ("node", Some(node), None, None) => ResourceTarget::Node(parse(node)?),
                ("prefix", None, Some(route), Some(prefix)) => ResourceTarget::Prefix {
                    route: parse(route)?,
                    prefix: prefix.parse().map_err(|_| malformed("invalid prefix"))?,
                },
                _ => return Err(malformed("invalid resource target")),
            };
            Action::CreateResource(net, form.name, target)
        }
        Route::ResourceUpdate(id) => Action::SetResourceEnabled(parse(id)?, enabled(req).await?),
        Route::ServiceCreate(net) => {
            let net = parse(net)?;
            let form = json_form::<ServiceForm>(req).await?;
            let protocol = form
                .protocol
                .ok_or(malformed("service protocol is required"))?;
            if protocol.supports_ports() != form.ports.is_some() {
                return Err(malformed("only TCP and UDP require port ranges"));
            }
            Action::CreateService(net, form.name, protocol, form.ports.unwrap_or_default())
        }
        Route::ServiceUpdate(id) => Action::SetServiceEnabled(parse(id)?, enabled(req).await?),
        Route::ResourceGrantCreate(net) => {
            let net = parse(net)?;
            let form = json_form::<ResourceGrantForm>(req).await?;
            Action::CreateResourceGrant {
                net,
                subject: subject(&form.subject_kind, &form.subject_id)?,
                resource: parse(&form.resource_id)?,
                service: parse(&form.service_id)?,
            }
        }
        Route::ResourceGrantDelete(id) => Action::DeleteResourceGrant(parse(id)?),
    })
}
pub(super) fn parse(value: &str) -> Result<Id, Failure> {
    value.parse().map_err(|_| malformed("invalid identifier"))
}
fn subject(kind: &str, id: &str) -> Result<Subject, Failure> {
    let id = parse(id)?;
    match kind {
        "user" => Ok(Subject::User(id)),
        "team" => Ok(Subject::Team(id)),
        _ => Err(malformed("invalid grant subject")),
    }
}
async fn enabled(req: Request<Incoming>) -> Result<bool, Failure> {
    json_form::<EnabledForm>(req)
        .await?
        .enabled
        .ok_or(malformed("enabled is required"))
}
pub(super) fn failure(e: anyhow::Error) -> Failure {
    match e.downcast_ref::<AccessError>() {
        Some(AccessError::Invalid(detail)) => return malformed(detail),
        Some(AccessError::Missing) => {
            return Failure(
                S::NOT_FOUND,
                "ERROR_CODE_MALFORMED",
                "record not found",
                false,
            );
        }
        Some(AccessError::Conflict) => {
            return Failure(
                S::CONFLICT,
                "ERROR_CODE_PERMISSION_DENIED",
                "request conflicts with controller state",
                false,
            );
        }
        None => {}
    }
    match e.downcast_ref::<SessionError>() {
        Some(SessionError::Denied) => DENIED,
        Some(_) => AUTH,
        None => e.downcast::<Failure>().unwrap_or(INTERNAL),
    }
}
