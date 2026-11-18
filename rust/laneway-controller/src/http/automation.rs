use super::{
    Credential, Failure, INTERNAL, Reply, State, administrators::failure, credential,
    form::required_json_form, malformed, mutations::csrf_proof, no_content, query_limit, response,
    with_session_headers,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    RootCredential, SessionStore,
    administrators::Caller,
    automation::{Read, Spec, Token, Write, Written, bearer_inventory},
};
use laneway_protocol::Id;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(super) enum Route<'a> {
    Principals,
    Tokens(&'a str),
    Disable(&'a str),
    Revoke(&'a str),
}

impl<'a> Route<'a> {
    pub(super) fn parse(path: &[&'a str]) -> Option<Self> {
        Some(match path {
            ["", "v1", "admin", "service-principals"] => Self::Principals,
            ["", "v1", "admin", "service-principals", id, "tokens"] => Self::Tokens(id),
            ["", "v1", "admin", "service-principals", id, "disable"] => Self::Disable(id),
            ["", "v1", "admin", "service-access-tokens", id, "revoke"] => Self::Revoke(id),
            _ => return None,
        })
    }

    fn read(self, query: Option<&str>) -> anyhow::Result<Read> {
        let limit = query_limit(query)? as i64;
        Ok(match self {
            Self::Principals => Read::Principals(limit),
            Self::Tokens(id) => Read::Tokens {
                principal: principal(id)?,
                limit,
            },
            _ => unreachable!("write-only automation route"),
        })
    }
}

struct Auth {
    credential: Credential,
    csrf: Option<String>,
    root: Option<Arc<RootCredential>>,
}

impl Auth {
    fn caller(&self) -> Caller<'_> {
        match &self.credential {
            Credential::Session(session) => Caller::Browser {
                token: session,
                csrf: self.csrf.as_deref(),
            },
            Credential::Bearer(header) => Caller::Bearer {
                header,
                root: self.root.as_deref(),
            },
        }
    }
}

const BUSY: Failure = Failure(
    S::SERVICE_UNAVAILABLE,
    "ERROR_CODE_RESOURCE_EXHAUSTED",
    "controller busy",
    true,
);

pub(super) async fn handle(
    req: Request<Incoming>,
    state: State,
    id: &str,
    route: Route<'_>,
) -> Result<Reply, Failure> {
    let listable = matches!(route, Route::Principals | Route::Tokens(_));
    let head = req.method() == Method::HEAD;
    if req.method() == Method::POST {
        return change(req, state, id, route).await;
    }
    if !listable || !(head || req.method() == Method::GET) {
        let mut reply = Failure(
            S::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
            false,
        )
        .reply(id, head);
        reply.headers_mut().insert(
            header::ALLOW,
            header::HeaderValue::from_static(if listable { "GET, HEAD, POST" } else { "POST" }),
        );
        return Ok(reply);
    }
    let caller = credential(req.headers())?;
    let pending = route.read(req.uri().query());
    let permit = state.queries.try_acquire_owned().map_err(|_| BUSY)?;
    let (body, session) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _permit = permit;
        let (data, session) = match caller {
            Credential::Bearer(token) => (
                bearer_inventory(&state.database, &token, state.root.as_deref(), pending)?,
                None,
            ),
            Credential::Session(token) => {
                let reply =
                    SessionStore::open(&state.database)?.read_automation(&token, pending)?;
                (reply.list, Some((reply.id, reply.idle, reply.absolute)))
            }
        };
        Ok((serde_json::to_vec(&data)?, session))
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    with_session_headers(response(S::OK, id, body, head), session)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    name: Option<String>,
    all_networks: Option<bool>,
    network_ids: Option<Vec<String>>,
    permissions: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issue {
    label: Option<String>,
    expires_at_unix_seconds: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revoke {
    reason: Option<String>,
}

#[derive(Serialize)]
struct Issued<'a> {
    access_token: &'a str,
    token: &'a Token,
}

fn principal(raw: &str) -> Result<Id, Failure> {
    raw.parse().map_err(|_| malformed("invalid principal_id"))
}

async fn input(req: Request<Incoming>, route: Route<'_>) -> Result<Write, Failure> {
    Ok(match route {
        Route::Principals => {
            let form: Create = required_json_form(req).await?;
            let network_ids = form
                .network_ids
                .unwrap_or_default()
                .iter()
                .map(|id| id.parse().map_err(|_| malformed("invalid network_ids")))
                .collect::<Result<_, _>>()?;
            Write::Create(Spec {
                name: form.name.unwrap_or_default(),
                all_networks: form.all_networks.unwrap_or(false),
                network_ids,
                permissions: form.permissions.unwrap_or_default(),
            })
        }
        Route::Tokens(id) => {
            let principal = principal(id)?;
            let form: Issue = required_json_form(req).await?;
            Write::Issue {
                principal,
                label: form.label.unwrap_or_default(),
                expires: form.expires_at_unix_seconds.unwrap_or_default(),
            }
        }
        Route::Disable(id) => Write::Disable(principal(id)?),
        Route::Revoke(id) => {
            let token = id.parse().map_err(|_| malformed("invalid token_id"))?;
            let form: Revoke = required_json_form(req).await?;
            Write::Revoke {
                token,
                reason: form.reason.unwrap_or_default(),
            }
        }
    })
}

async fn change(
    req: Request<Incoming>,
    state: State,
    id: &str,
    route: Route<'_>,
) -> Result<Reply, Failure> {
    let auth = Arc::new(Auth {
        credential: credential(req.headers())?,
        csrf: csrf_proof(req.headers()).filter(|_| crate::origin::same_origin(req.headers())),
        root: state.root,
    });
    let permit = state
        .queries
        .clone()
        .try_acquire_owned()
        .map_err(|_| BUSY)?;
    let database = state.database.clone();
    let preflight = auth.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        SessionStore::open(&database)?.check_administrator_change(preflight.caller())
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    let write = input(req, route).await?;
    let permit = state.queries.try_acquire_owned().map_err(|_| BUSY)?;
    let changed = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        SessionStore::open(&state.database)?.write_automation(auth.caller(), write)
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    let (resource, body) = match changed.result {
        Written::Empty => return with_session_headers(no_content(id), changed.session),
        Written::Principal(principal) => (
            format!("/v1/admin/service-principals/{}", principal.principal_id),
            serde_json::to_vec(&principal).map_err(|_| INTERNAL)?,
        ),
        Written::Issued { token, bearer } => (
            format!("/v1/admin/service-access-tokens/{}", token.token_id),
            serde_json::to_vec(&Issued {
                access_token: &bearer,
                token: &token,
            })
            .map_err(|_| INTERNAL)?,
        ),
    };
    let mut reply = response(S::CREATED, id, body, false);
    reply
        .headers_mut()
        .insert(header::LOCATION, resource.parse().map_err(|_| INTERNAL)?);
    with_session_headers(reply, changed.session)
}
