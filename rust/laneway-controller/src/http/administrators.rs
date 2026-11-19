use super::{
    Credential, Failure, INTERNAL, Reply, State, credential, malformed, no_content, query_limit,
    response, valid_query_field, with_session_headers,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    ListError, SessionStore,
    administrators::{AdministratorError, Read, Rotation, bearer_inventory},
};
use laneway_protocol::Id;

mod changes;

#[derive(Clone, Copy)]
pub(super) enum Route<'a> {
    List,
    Principal(&'a str),
    Sessions(&'a str),
    Password(&'a str),
    Revoke(&'a str),
    Rotation(&'a str, Rotation),
}

impl<'a> Route<'a> {
    pub(super) fn parse(path: &[&'a str]) -> Option<Self> {
        Some(match path {
            ["", "v1", "admin", "administrators"] => Self::List,
            ["", "v1", "admin", "administrators", id] => Self::Principal(id),
            ["", "v1", "admin", "administrators", id, "sessions"] => Self::Sessions(id),
            ["", "v1", "admin", "administrators", id, "password"] => Self::Password(id),
            ["", "v1", "admin", "sessions", id, "revoke"] => Self::Revoke(id),
            [
                "",
                "v1",
                "admin",
                "auth",
                "root-token-rotations",
                id,
                "begin",
            ] => Self::Rotation(id, Rotation::Begin),
            [
                "",
                "v1",
                "admin",
                "auth",
                "root-token-rotations",
                id,
                "complete",
            ] => Self::Rotation(id, Rotation::Complete),
            _ => return None,
        })
    }
}

fn parse_id(raw: &str, field: &'static str) -> Result<Id, AdministratorError> {
    raw.parse().map_err(|_| AdministratorError::Id(field))
}

fn list(query: Option<&str>) -> Read {
    let mut query_fields = query
        .unwrap_or_default()
        .split('&')
        .filter(|part| valid_query_field(part))
        .flat_map(|part| form_urlencoded::parse(part.as_bytes()));
    let mut username = None;
    let mut count = 0;
    for (key, value) in query_fields.by_ref() {
        if key == "username" {
            username = Some(value.into_owned());
        }
        count += 1;
    }
    match username {
        Some(user) if count == 1 => Read::Username(Ok(user)),
        Some(_) => Read::Username(Err(AdministratorError::Username)),
        None => Read::List(query_limit(query)),
    }
}

pub(super) async fn handle(
    req: Request<Incoming>,
    state: State,
    id: &str,
    route: Route<'_>,
) -> Result<Reply, Failure> {
    let change = match (route, req.method()) {
        (Route::List, &Method::POST) => Some(changes::Route::Create),
        (Route::Principal(id), &Method::PATCH) => Some(changes::Route::Update(id)),
        (Route::Password(id), &Method::POST) => Some(changes::Route::Password(id)),
        (Route::Revoke(id), &Method::POST) => Some(changes::Route::Revoke(id)),
        _ => None,
    };
    if let Some(change) = change {
        return changes::handle(req, state, id, change).await;
    }
    let is_rotation = matches!(route, Route::Rotation(..));
    let head = req.method() == Method::HEAD;
    let allowed = if is_rotation {
        req.method() == Method::POST
    } else {
        !matches!(route, Route::Password(_) | Route::Revoke(_))
            && (head || req.method() == Method::GET)
    };
    if !allowed {
        let mut reply = Failure(
            S::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
            false,
        )
        .reply(id, head);
        let allow = match route {
            Route::Rotation(..) | Route::Password(_) | Route::Revoke(_) => "POST",
            Route::List => "GET, HEAD, POST",
            Route::Principal(_) => "GET, HEAD, PATCH",
            Route::Sessions(_) => "GET, HEAD",
        };
        reply
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static(allow));
        return Ok(reply);
    }
    let caller = credential(req.headers())?;
    let permit = state
        .queries
        .try_acquire_owned()
        .map_err(|_| crate::http::QUERY_BUSY)?;
    let query = req.uri().query();
    let read = match route {
        Route::List => list(query),
        Route::Principal(target) => Read::Principal(parse_id(target, "principal_id")),
        Route::Sessions(target) => {
            Read::Sessions(parse_id(target, "principal_id"), query_limit(query))
        }
        Route::Password(_) | Route::Revoke(_) => unreachable!("only POST allowed"),
        Route::Rotation(target, phase) => {
            let target = parse_id(target, "rotation_id");
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let mut store = SessionStore::open(&state.database)?;
                match caller {
                    Credential::Bearer(raw) => {
                        store.record_root_rotation(&raw, state.root.as_deref(), target, phase)
                    }
                    Credential::Session(raw) => store.deny_root_only_session(&raw),
                }
            })
            .await
            .map_err(|_| INTERNAL)?
            .map_err(failure)?;
            return Ok(no_content(id));
        }
    };
    let (data, meta) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _permit = permit;
        let (inventory, meta) = match caller {
            Credential::Bearer(raw) => (
                bearer_inventory(&state.database, &raw, state.root.as_deref(), read)?,
                None,
            ),
            Credential::Session(raw) => {
                let reply =
                    SessionStore::open(&state.database)?.administrator_inventory(&raw, read)?;
                (reply.list, Some((reply.id, reply.idle, reply.absolute)))
            }
        };
        Ok((serde_json::to_vec(&inventory)?, meta))
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    with_session_headers(response(S::OK, id, data, head), meta)
}

pub(super) fn failure(err: anyhow::Error) -> Failure {
    if let Some(reason) = err.downcast_ref::<AdministratorError>() {
        return match reason {
            AdministratorError::Id("rotation_id") => malformed("invalid rotation_id"),
            AdministratorError::Id(_) => malformed("invalid principal_id"),
            AdministratorError::Username => {
                malformed("username must be one canonical administrator username")
            }
            AdministratorError::Conflict => Failure(
                S::CONFLICT,
                "ERROR_CODE_PERMISSION_DENIED",
                "request conflicts with controller state",
                false,
            ),
            AdministratorError::Invalid => malformed("invalid request"),
        };
    }
    match err.downcast_ref::<ListError>() {
        Some(ListError::Limit) => malformed("limit must be an integer from 1 through 1000"),
        Some(ListError::Missing) => Failure(
            S::NOT_FOUND,
            "ERROR_CODE_MALFORMED",
            "record not found",
            false,
        ),
        _ => super::access_admin::failure(err),
    }
}
