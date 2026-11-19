use super::{
    Credential, Failure, INTERNAL, Reply, State,
    administrators::failure,
    credential,
    form::{empty_secret, required_json_form, secret},
    list_limit, malformed,
    mutations::csrf_proof,
    no_content, response, with_session_headers,
};
use http_body_util::BodyExt;
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    SessionStore,
    administrators::Caller,
    applications::{Consent, Manifest, Read, bearer_inventory, valid_percent},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr, time::Instant};
use zeroize::Zeroizing;

pub(super) mod authorization;
mod lifecycle;
mod tokens;

pub(super) enum Route<'a> {
    Start,
    Exchange,
    Token,
    RevokeToken,
    Apps,
    App(&'a str),
    Disable(&'a str),
    RotateSecret(&'a str),
    Review(&'a str),
    Consent(&'a str, Consent),
}

impl<'a> Route<'a> {
    pub(super) fn parse(path: &[&'a str]) -> Option<Self> {
        Some(match path {
            ["", "applications", "new"] => Self::Start,
            ["", "v1", "application-registrations", "exchange"] => Self::Exchange,
            ["", "oauth", "token"] => Self::Token,
            ["", "oauth", "revoke"] => Self::RevokeToken,
            ["", "v1", "admin", "applications"] => Self::Apps,
            ["", "v1", "admin", "applications", id] => Self::App(id),
            ["", "v1", "admin", "applications", id, "disable"] => Self::Disable(id),
            ["", "v1", "admin", "applications", id, "client-secrets"] => Self::RotateSecret(id),
            ["", "v1", "admin", "application-registration-requests", id] => Self::Review(id),
            [
                "",
                "v1",
                "admin",
                "application-registration-requests",
                id,
                "approve",
            ] => Self::Consent(id, Consent::Approve),
            [
                "",
                "v1",
                "admin",
                "application-registration-requests",
                id,
                "cancel",
            ] => Self::Consent(id, Consent::Cancel),
            _ => return None,
        })
    }
}

const BUSY: Failure = crate::http::QUERY_BUSY;

pub(super) async fn handle(
    req: Request<Incoming>,
    state: State,
    id: &str,
    peer: IpAddr,
    route: Route<'_>,
) -> Result<Reply, Failure> {
    use laneway_controller::applications::lifecycle::Action;
    let change = match (&route, req.method()) {
        (Route::App(app), &Method::DELETE) => Some((*app, Action::Delete)),
        (Route::Disable(app), &Method::POST) => Some((*app, Action::Disable)),
        (Route::RotateSecret(app), &Method::POST) => Some((*app, Action::RotateSecret)),
        _ => None,
    };
    if let Some((app, action)) = change {
        return lifecycle::handle(req, state, id, app, action).await;
    }
    let head = req.method() == Method::HEAD;
    let post = matches!(
        route,
        Route::Start
            | Route::Exchange
            | Route::Consent(..)
            | Route::Token
            | Route::RevokeToken
            | Route::Disable(_)
            | Route::RotateSecret(_)
    );
    if if post {
        req.method() != Method::POST
    } else {
        !head && req.method() != Method::GET
    } {
        let mut reply = Failure(
            S::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
            false,
        )
        .reply(id, head);
        let allow = if post {
            "POST"
        } else if matches!(route, Route::App(_)) {
            "GET, HEAD, DELETE"
        } else {
            "GET, HEAD"
        };
        reply
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static(allow));
        return Ok(reply);
    }
    if matches!(
        route,
        Route::Start | Route::Exchange | Route::Token | Route::RevokeToken
    ) {
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
        return Ok(match route {
            Route::Start => start(req, state, id).await,
            Route::Exchange => exchange(req, state, id).await,
            Route::Token => tokens::handle(req, state, id, false).await,
            Route::RevokeToken => tokens::handle(req, state, id, true).await,
            _ => unreachable!("not a public application endpoint"),
        });
    }
    let auth = credential(req.headers())?;
    let permit = state.queries.try_acquire_owned().map_err(|_| BUSY)?;
    if let Route::Consent(request, consent) = route {
        let csrf = csrf_proof(req.headers()).filter(|_| crate::origin::same_origin(req.headers()));
        let request = request
            .parse()
            .map_err(|_| malformed("invalid request_id").into());
        let (body, session) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            let _permit = permit;
            let mut store = SessionStore::open(&state.database)?;
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
            let (redirect, session) = store.application_consent(caller, request, consent)?;
            #[derive(Serialize)]
            struct Redirect<'a> {
                redirect_uri: &'a str,
            }
            Ok((
                serde_json::to_vec(&Redirect {
                    redirect_uri: &redirect,
                })?,
                session,
            ))
        })
        .await
        .map_err(|_| INTERNAL)?
        .map_err(failure)?;
        return with_session_headers(response(S::OK, id, body, false), session);
    }
    let read = match route {
        Route::Apps => list_limit(req.uri().query(), 500)
            .map(|n| Read::Applications(n as i64))
            .map_err(anyhow::Error::from),
        Route::App(id) => id
            .parse()
            .map(Read::Application)
            .map_err(|_| malformed("invalid application_id").into()),
        Route::Review(id) => id
            .parse()
            .map(Read::Registration)
            .map_err(|_| malformed("invalid request_id").into()),
        _ => unreachable!("public routes handled above"),
    };
    let (body, session) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _permit = permit;
        let (data, session) = match auth {
            Credential::Bearer(token) => (
                bearer_inventory(&state.database, &token, state.root.as_deref(), read)?,
                None,
            ),
            Credential::Session(token) => {
                let reply =
                    SessionStore::open(&state.database)?.application_inventory(&token, read)?;
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

fn app_error(status: S, id: &str, error: &str, description: &str) -> Reply {
    no_cache(response(
        status,
        id,
        serde_json::json!({"error": error, "error_description": description})
            .to_string()
            .into_bytes(),
        false,
    ))
}

fn no_cache(mut reply: Reply) -> Reply {
    reply
        .headers_mut()
        .insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
    reply
}

async fn form(
    req: Request<Incoming>,
    allowed: &[&str],
) -> Option<HashMap<String, Zeroizing<String>>> {
    if req.uri().query().is_some_and(|q| !q.is_empty())
        || req.headers().get_all(header::CONTENT_TYPE).iter().count() != 1
        || req.headers().get(header::CONTENT_TYPE)?.as_bytes()
            != b"application/x-www-form-urlencoded"
    {
        return None;
    }
    let mut input = Zeroizing::new(Vec::new());
    let mut body = req.into_body();
    while let Some(frame) = body.frame().await {
        if let Ok(bytes) = frame.ok()?.into_data() {
            if bytes.len() > 131072 - input.len() {
                return None;
            }
            input.extend_from_slice(&bytes);
        }
    }
    let text = std::str::from_utf8(&input).ok()?;
    if text.contains(';') || !valid_percent(text) {
        return None;
    }
    let mut fields = HashMap::new();
    for (key, value) in form_urlencoded::parse(&input) {
        if !allowed.contains(&key.as_ref())
            || fields
                .insert(key.into_owned(), Zeroizing::new(value.into_owned()))
                .is_some()
        {
            return None;
        }
    }
    Some(fields)
}

async fn start(req: Request<Incoming>, state: State, id: &str) -> Reply {
    let invalid = || {
        app_error(
            S::BAD_REQUEST,
            id,
            "invalid_request",
            "invalid registration request",
        )
    };
    let unavailable = || {
        app_error(
            S::SERVICE_UNAVAILABLE,
            id,
            "temporarily_unavailable",
            "registration unavailable",
        )
    };
    let Some(mut fields) = form(
        req,
        &[
            "manifest",
            "state",
            "code_challenge",
            "code_challenge_method",
        ],
    )
    .await
    else {
        return invalid();
    };
    let (Some(manifest), Some(proof), Some(relay_state)) = (
        fields.remove("manifest"),
        fields.remove("code_challenge"),
        fields.remove("state"),
    ) else {
        return invalid();
    };
    if fields
        .get("code_challenge_method")
        .map(|value| value.as_str())
        != Some("S256")
        || manifest.is_empty()
        || proof.is_empty()
        || relay_state.is_empty()
    {
        return invalid();
    }
    let loopback = state.allow_loopback_callbacks;
    let parsed = serde_json::from_str::<Manifest>(&manifest)
        .ok()
        .and_then(|m| m.validate(loopback).ok());
    let Some(manifest) = parsed else {
        return app_error(
            S::BAD_REQUEST,
            id,
            "invalid_request",
            "invalid application manifest",
        );
    };
    let Ok(permit) = state.queries.try_acquire_owned() else {
        return unavailable();
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        SessionStore::open(&state.database)?.create_application_registration(
            manifest,
            &relay_state,
            &proof,
            loopback,
        )
    })
    .await;
    match result {
        Ok(Ok(request)) => {
            let mut reply = no_content(id);
            *reply.status_mut() = S::SEE_OTHER;
            reply.headers_mut().insert(
                header::LOCATION,
                format!("/applications/consent?request={request}")
                    .parse()
                    .expect("canonical request identifier"),
            );
            reply
        }
        _ => unavailable(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    #[serde(default = "empty_secret", deserialize_with = "secret")]
    code: Zeroizing<String>,
    #[serde(default = "empty_secret", deserialize_with = "secret")]
    code_verifier: Zeroizing<String>,
}

async fn exchange(req: Request<Incoming>, state: State, id: &str) -> Reply {
    let invalid = || {
        app_error(
            S::BAD_REQUEST,
            id,
            "invalid_request",
            "invalid registration exchange",
        )
    };
    let rejected = || {
        app_error(
            S::BAD_REQUEST,
            id,
            "invalid_grant",
            "registration exchange failed",
        )
    };
    let Ok(form) = required_json_form::<Exchange>(req).await else {
        return invalid();
    };
    if form.code.is_empty() || form.code_verifier.is_empty() {
        return invalid();
    }
    let Ok(permit) = state.queries.try_acquire_owned() else {
        return app_error(
            S::SERVICE_UNAVAILABLE,
            id,
            "temporarily_unavailable",
            "registration unavailable",
        );
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        SessionStore::open(&state.database)?
            .exchange_application_registration(&form.code, &form.code_verifier)
    })
    .await;
    let Ok(Ok(value)) = result else {
        return rejected();
    };
    #[derive(Serialize)]
    struct Issued<'a> {
        application_id: &'a str,
        client_id: &'a str,
        client_secret: &'a str,
        name: &'a str,
    }
    match serde_json::to_vec(&Issued {
        application_id: &value.application.application_id,
        client_id: &value.application.client_id,
        client_secret: &value.secret,
        name: value.application.name(),
    }) {
        Ok(body) => no_cache(response(S::OK, id, body, false)),
        Err(_) => INTERNAL.reply(id, false),
    }
}
