use super::{AUTH, COOKIE, Failure, INTERNAL, Reply, State, cookie, malformed, mutations};
use http_body_util::BodyExt;
use hyper::{Request, StatusCode, body::Incoming, header};
use laneway_controller::{SessionError, SessionStore, password::Busy};
use serde::Deserialize;
use std::{net::IpAddr, time::Instant};
use zeroize::Zeroizing;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Form {
    username: Option<String>,
    password: Option<String>,
}

fn limited(id: &str, wait: u64) -> Reply {
    let mut r = Failure(
        StatusCode::TOO_MANY_REQUESTS,
        "ERROR_CODE_RESOURCE_EXHAUSTED",
        "authentication temporarily unavailable",
        true,
    )
    .reply(id, false);
    r.headers_mut().insert(header::RETRY_AFTER, wait.into());
    r
}
fn store_error(e: anyhow::Error) -> Failure {
    if e.is::<SessionError>() {
        AUTH
    } else {
        INTERNAL
    }
}

pub(super) async fn handle(
    req: Request<Incoming>,
    state: State,
    id: &str,
    peer: IpAddr,
) -> Result<Reply, Failure> {
    let h = req.headers();
    if h.contains_key(header::AUTHORIZATION) {
        return Err(AUTH);
    }
    let previous = cookie(h, COOKIE)?.map(str::to_owned);
    if !crate::origin::same_origin(h) {
        return Err(mutations::DENIED);
    }
    let media = h
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<mime::Mime>().ok());
    if media
        .as_ref()
        .is_none_or(|m| m.essence_str() != "application/json")
    {
        return Err(Failure(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "ERROR_CODE_MALFORMED",
            "Content-Type must be application/json",
            false,
        ));
    }
    let forwarded = h.contains_key("x-laneway-public-client-ip");
    let mut body = req.into_body();
    let mut data = Zeroizing::new(Vec::new());
    while let Some(frame) = body.frame().await {
        if let Ok(bytes) = frame
            .map_err(|_| malformed("could not read request body"))?
            .into_data()
        {
            if bytes.len() > 131072 - data.len() {
                return Err(Failure(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "ERROR_CODE_RESOURCE_EXHAUSTED",
                    "request body exceeds limit",
                    false,
                ));
            }
            data.extend_from_slice(&bytes);
        }
    }
    let mut de = serde_json::Deserializer::from_slice(&data);
    let form = Option::<Form>::deserialize(&mut de)
        .map_err(|_| malformed("malformed JSON request"))?
        .unwrap_or_default();
    let password = Zeroizing::new(form.password.unwrap_or_default().into_bytes());
    de.end()
        .map_err(|_| malformed("request must contain one JSON value"))?;
    drop(data);
    if forwarded {
        return Err(AUTH);
    }
    let username = form.username.unwrap_or_default();
    let attempt =
        state
            .logins
            .lock()
            .map_err(|_| INTERNAL)?
            .attempt(peer, &username, Instant::now());
    if let Err(wait) = attempt {
        return Ok(limited(id, wait));
    }
    let _permit = state.queries.try_acquire_owned().map_err(|_| {
        Failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERROR_CODE_RESOURCE_EXHAUSTED",
            "controller busy",
            true,
        )
    })?;
    if let Some(old) = previous {
        let db = state.database.clone();
        tokio::task::spawn_blocking(move || {
            SessionStore::open(&db)?.reject_active_login_cookie(&old)
        })
        .await
        .map_err(|_| INTERNAL)?
        .map_err(store_error)?;
    }
    let result = state
        .passwords
        .verify((*state.database).clone(), username, password)
        .await;
    let candidate = match result {
        Ok(Some(candidate)) => candidate,
        other => {
            let busy = match other {
                Ok(None) => false,
                Err(e) if e.is::<Busy>() => true,
                _ => return Err(INTERNAL),
            };
            let db = state.database.clone();
            // Go also treats failure auditing as best effort; never reveal a
            // difference between missing and disabled administrators.
            let _ = tokio::task::spawn_blocking(move || {
                SessionStore::open(&db)?.audit_login_failure(busy)
            })
            .await;
            return if busy { Ok(limited(id, 1)) } else { Err(AUTH) };
        }
    };
    let s = tokio::task::spawn_blocking(move || {
        let _permit = _permit;
        SessionStore::open(&state.database)?.issue_after_password(candidate)
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(store_error)?;
    mutations::issued(id, s)
}
