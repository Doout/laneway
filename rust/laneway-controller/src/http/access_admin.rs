use super::{
    AUTH, Failure, INTERNAL, Reply, State, credential,
    form::json_form,
    malformed,
    mutations::{DENIED, csrf_proof},
    response, with_session_headers,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    SessionError, SessionStore,
    access_admin::{AccessError, Request as Action, Subject, Target},
};
use laneway_protocol::Id;
use serde::Deserialize;

pub(super) enum Route<'a> {
    Inventory(&'a str),
    UserCreate(&'a str),
    UserUpdate(&'a str),
    TeamCreate(&'a str),
    Membership(&'a str, &'a str),
    GrantCreate(&'a str),
    GrantDelete(&'a str),
}
impl<'a> Route<'a> {
    pub(super) fn parse(parts: &[&'a str]) -> Option<Self> {
        use Route::*;
        Some(match parts {
            ["", "v1", "admin", "networks", id, "access-subjects"] => Inventory(id),
            ["", "v1", "admin", "networks", id, "users"] => UserCreate(id),
            ["", "v1", "admin", "users", id] => UserUpdate(id),
            ["", "v1", "admin", "networks", id, "teams"] => TeamCreate(id),
            ["", "v1", "admin", "teams", id, "members", user] => Membership(id, user),
            ["", "v1", "admin", "networks", id, "access-grants"] => GrantCreate(id),
            ["", "v1", "admin", "access-grants", id] => GrantDelete(id),
            _ => return None,
        })
    }
    fn allow(&self) -> &'static str {
        match self {
            Self::Inventory(_) => "GET, HEAD",
            Self::UserCreate(_) | Self::TeamCreate(_) | Self::GrantCreate(_) => "POST",
            Self::UserUpdate(_) => "PATCH",
            Self::Membership(..) => "DELETE, PUT",
            Self::GrantDelete(_) => "DELETE",
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct NameForm {
    name: String,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EnabledForm {
    enabled: Option<bool>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GrantForm {
    subject_kind: String,
    subject_id: String,
    target_kind: String,
    node_id: String,
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
    let read = matches!(route, Route::Inventory(_));
    let post = req.method() == Method::POST;
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
    let data = serde_json::to_vec(&data).map_err(|_| INTERNAL)?;
    with_session_headers(
        response(if post { S::CREATED } else { S::OK }, id, data, head),
        meta,
    )
}

async fn decode(route: Route<'_>, req: Request<Incoming>, put: bool) -> Result<Action, Failure> {
    let parse = |value: &str| -> Result<Id, Failure> {
        value
            .parse()
            .map_err(|_| malformed("invalid access identifier"))
    };
    Ok(match route {
        Route::Inventory(net) => Action::Inventory(parse(net)?),
        Route::UserCreate(net) => {
            Action::CreateUser(parse(net)?, json_form::<NameForm>(req).await?.name)
        }
        Route::TeamCreate(net) => {
            Action::CreateTeam(parse(net)?, json_form::<NameForm>(req).await?.name)
        }
        Route::UserUpdate(id) => Action::SetUserEnabled(
            parse(id)?,
            json_form::<EnabledForm>(req)
                .await?
                .enabled
                .ok_or(malformed("enabled is required"))?,
        ),
        Route::Membership(team, user) => Action::SetMember(parse(team)?, parse(user)?, put),
        Route::GrantDelete(id) => Action::DeleteGrant(parse(id)?),
        Route::GrantCreate(net) => {
            let net = parse(net)?;
            let form = json_form::<GrantForm>(req).await?;
            let subject_id = parse(&form.subject_id)?;
            let subject = match form.subject_kind.as_str() {
                "user" => Subject::User(subject_id),
                "team" => Subject::Team(subject_id),
                _ => return Err(malformed("invalid grant subject")),
            };
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
    })
}
fn failure(e: anyhow::Error) -> Failure {
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
