use super::{BUSY, app_error, no_cache};
use crate::http::{
    Credential, Failure, INTERNAL, Reply, State, administrators::failure, credential,
    form::required_json_form, malformed, mutations::csrf_proof, no_content, query_limit, response,
    valid_query_field, with_session_headers,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    SessionStore,
    administrators::Caller,
    applications::authorization::{Action, bearer_list, read_request},
};
use laneway_protocol::Id;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr, time::Instant};

#[derive(Clone, Copy)]
pub(in crate::http) enum Route<'a> {
    Start,
    Review(&'a str),
    List(&'a str),
    Consent {
        network: &'a str,
        request: &'a str,
        approve: bool,
    },
    Revoke(&'a str),
}

impl<'a> Route<'a> {
    pub(in crate::http) fn parse(path: &[&'a str]) -> Option<Self> {
        Some(match path {
            ["", "oauth", "authorize"] => Self::Start,
            ["", "oauth", "authorization-requests", id] => Self::Review(id),
            [
                "",
                "v1",
                "admin",
                "networks",
                network,
                "application-installations",
            ] => Self::List(network),
            [
                "",
                "v1",
                "admin",
                "networks",
                network,
                "application-authorization-requests",
                request,
                "approve",
            ] => Self::Consent {
                network,
                request,
                approve: true,
            },
            [
                "",
                "v1",
                "admin",
                "networks",
                network,
                "application-authorization-requests",
                request,
                "cancel",
            ] => Self::Consent {
                network,
                request,
                approve: false,
            },
            ["", "v1", "admin", "application-installations", id] => Self::Revoke(id),
            _ => return None,
        })
    }
}

pub(in crate::http) async fn handle(
    req: Request<Incoming>,
    state: State,
    id: &str,
    peer: IpAddr,
    route: Route<'_>,
) -> Result<Reply, Failure> {
    let head = req.method() == Method::HEAD;
    let (allowed, allow) = match route {
        Route::Consent { .. } => (req.method() == Method::POST, "POST"),
        Route::Revoke(_) => (req.method() == Method::DELETE, "DELETE"),
        _ => (head || req.method() == Method::GET, "GET, HEAD"),
    };
    if !allowed {
        let mut reply = Failure(
            S::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
            false,
        )
        .reply(id, head);
        reply
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static(allow));
        return Ok(reply);
    }
    match route {
        Route::Start => {
            if !state
                .applications
                .lock()
                .map_err(|_| INTERNAL)?
                .admit(peer, Instant::now())
            {
                let mut reply = app_error(
                    S::TOO_MANY_REQUESTS,
                    id,
                    "temporarily_unavailable",
                    "request rate limit exceeded",
                );
                reply.headers_mut().insert(header::RETRY_AFTER, 1.into());
                return Ok(reply);
            }
            Ok(start(req, state, id, head).await)
        }
        Route::Review(request) => Ok(review(state, id, request, head).await),
        Route::List(network) => list(req, state, id, network, head).await,
        _ => change(req, state, id, route).await,
    }
}

struct Query {
    client: String,
    redirect: String,
    scopes: Vec<String>,
    state: String,
    proof: String,
}

fn parse_query(raw: &str) -> Option<Query> {
    let mut values = HashMap::new();
    for field in raw.split('&') {
        if !valid_query_field(field) {
            return None;
        }
        for (key, value) in form_urlencoded::parse(field.as_bytes()) {
            if !matches!(
                key.as_ref(),
                "response_type"
                    | "client_id"
                    | "redirect_uri"
                    | "scope"
                    | "state"
                    | "code_challenge"
                    | "code_challenge_method"
            ) || values.insert(key, value).is_some()
            {
                return None;
            }
        }
    }
    if values.remove("response_type")?.as_ref() != "code"
        || values.remove("code_challenge_method")?.as_ref() != "S256"
    {
        return None;
    }
    Some(Query {
        client: values.remove("client_id")?.into_owned(),
        redirect: values.remove("redirect_uri")?.into_owned(),
        scopes: values
            .remove("scope")?
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
        state: values.remove("state")?.into_owned(),
        proof: values.remove("code_challenge")?.into_owned(),
    })
}

async fn start(req: Request<Incoming>, state: State, id: &str, head: bool) -> Reply {
    let invalid = || {
        auth_error(
            S::BAD_REQUEST,
            id,
            "invalid_request",
            "invalid authorization request",
            head,
        )
    };
    let Some(query) = req.uri().query().and_then(parse_query) else {
        return invalid();
    };
    let Ok(permit) = state.queries.try_acquire_owned() else {
        return auth_error(
            S::SERVICE_UNAVAILABLE,
            id,
            "temporarily_unavailable",
            "authorization unavailable",
            head,
        );
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        SessionStore::open(&state.database)?.start_application_authorization(
            &query.client,
            &query.redirect,
            query.scopes,
            &query.state,
            &query.proof,
        )
    })
    .await;
    let Ok(Ok(request)) = result else {
        return invalid();
    };
    let mut reply = no_content(id);
    *reply.status_mut() = S::SEE_OTHER;
    reply.headers_mut().insert(
        header::LOCATION,
        format!("/applications/install?request={request}")
            .parse()
            .expect("canonical authorization id"),
    );
    reply
}

async fn review(state: State, id: &str, request: &str, head: bool) -> Reply {
    let missing = || {
        auth_error(
            S::NOT_FOUND,
            id,
            "invalid_request",
            "authorization request not found",
            head,
        )
    };
    let Ok(request) = request.parse() else {
        return missing();
    };
    let Ok(permit) = state.queries.try_acquire_owned() else {
        return auth_error(
            S::SERVICE_UNAVAILABLE,
            id,
            "temporarily_unavailable",
            "authorization unavailable",
            head,
        );
    };
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        read_request(&state.database, request).and_then(|value| Ok(serde_json::to_vec(&value)?))
    })
    .await
    {
        Ok(Ok(body)) => response(S::OK, id, body, head),
        _ => missing(),
    }
}

fn auth_error(status: S, id: &str, error: &str, description: &str, head: bool) -> Reply {
    no_cache(response(
        status,
        id,
        serde_json::json!({"error":error,"error_description":description})
            .to_string()
            .into_bytes(),
        head,
    ))
}

fn parse(raw: &str, error: &'static str) -> Result<Id, Failure> {
    raw.parse().map_err(|_| malformed(error))
}

async fn list(
    req: Request<Incoming>,
    state: State,
    id: &str,
    network: &str,
    head: bool,
) -> Result<Reply, Failure> {
    let auth = credential(req.headers())?;
    let query = (|| -> anyhow::Result<_> {
        Ok((
            parse(network, "invalid network_id")?,
            query_limit(req.uri().query())? as i64,
        ))
    })();
    let permit = state.queries.try_acquire_owned().map_err(|_| BUSY)?;
    let (body, meta) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _permit = permit;
        let (data, meta) = match auth {
            Credential::Bearer(raw) => (
                bearer_list(&state.database, &raw, state.root.as_deref(), query)?,
                None,
            ),
            Credential::Session(raw) => {
                let reply = SessionStore::open(&state.database)?
                    .list_application_installations(&raw, query)?;
                (reply.list, Some((reply.id, reply.idle, reply.absolute)))
            }
        };
        Ok((serde_json::to_vec(&data)?, meta))
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    with_session_headers(response(S::OK, id, body, head), meta)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scopes {
    scopes: Option<Vec<String>>,
}

async fn change(
    req: Request<Incoming>,
    state: State,
    id: &str,
    route: Route<'_>,
) -> Result<Reply, Failure> {
    let auth = credential(req.headers())?;
    let csrf = csrf_proof(req.headers()).filter(|_| crate::origin::same_origin(req.headers()));
    let action = match route {
        Route::Consent {
            network,
            request,
            approve,
        } => {
            let network = parse(network, "invalid network_id")?;
            let request = parse(request, "invalid request_id")?;
            if approve {
                let form: Scopes = required_json_form(req).await?;
                Action::Approve {
                    network,
                    request,
                    scopes: form.scopes.unwrap_or_default(),
                }
            } else {
                Action::Cancel { network, request }
            }
        }
        Route::Revoke(raw) => Action::Revoke(parse(raw, "invalid installation_id")?),
        _ => unreachable!("read routes handled above"),
    };
    let permit = state.queries.try_acquire_owned().map_err(|_| BUSY)?;
    let outcome = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let caller = match &auth {
            Credential::Bearer(header) => Caller::Bearer {
                header,
                root: state.root.as_deref(),
            },
            Credential::Session(token) => Caller::Browser {
                token,
                csrf: csrf.as_deref(),
            },
        };
        SessionStore::open(&state.database)?.change_application_installation(caller, action)
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    #[derive(Serialize)]
    struct Redirect<'a> {
        redirect_uri: &'a str,
    }
    let reply = if let Some(uri) = outcome.redirect {
        response(
            S::OK,
            id,
            serde_json::to_vec(&Redirect { redirect_uri: &uri }).map_err(|_| INTERNAL)?,
            false,
        )
    } else {
        no_content(id)
    };
    with_session_headers(reply, outcome.session)
}
