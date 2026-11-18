use super::{app_error, form, no_cache};
use crate::http::{Reply, State, no_content, response};
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::{HeaderMap, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{SessionStore, applications::tokens::Client};
use zeroize::Zeroizing;

fn basic(headers: &HeaderMap) -> Option<Client> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let raw = values.next()?.as_bytes().strip_prefix(b"Basic ")?;
    if values.next().is_some() || raw.len() > 1024 {
        return None;
    }
    let decoded = Zeroizing::new(STANDARD.decode(raw).ok()?);
    let (client, secret) = std::str::from_utf8(&decoded).ok()?.split_once(':')?;
    Client::from_basic(client, secret)
}

fn invalid_client(id: &str) -> Reply {
    let mut reply = app_error(
        S::UNAUTHORIZED,
        id,
        "invalid_client",
        "client authentication failed",
    );
    reply.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Basic realm=\"Laneway OAuth\""),
    );
    reply
}

const TOKEN_FIELDS: &[&str] = &[
    "grant_type",
    "code",
    "code_verifier",
    "redirect_uri",
    "refresh_token",
];
const REVOKE_FIELDS: &[&str] = &["token", "token_type_hint"];

pub(super) async fn handle(req: Request<Incoming>, state: State, id: &str, revoke: bool) -> Reply {
    let unavailable = || {
        app_error(
            S::SERVICE_UNAVAILABLE,
            id,
            "temporarily_unavailable",
            "token endpoint unavailable",
        )
    };
    let invalid = || {
        app_error(
            S::BAD_REQUEST,
            id,
            "invalid_request",
            if revoke {
                "invalid revocation request"
            } else {
                "invalid token request"
            },
        )
    };
    let invalid_grant = || app_error(S::BAD_REQUEST, id, "invalid_grant", "token grant failed");
    let Some(client) = basic(req.headers()) else {
        return invalid_client(id);
    };
    let Ok(permit) = state.queries.clone().try_acquire_owned() else {
        return unavailable();
    };
    let database = state.database.clone();
    let preflight = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _permit = permit;
        let mut store = SessionStore::open(&database)?;
        store.check_application_client(&client)?;
        // The grant transaction verifies the client again and will not
        // rely on this earlier read if the credential is rotated meanwhile.
        let _ = store.prune_application_credentials();
        Ok(client)
    })
    .await;
    let Ok(Ok(client)) = preflight else {
        return invalid_client(id);
    };
    let Some(fields) = form(req, if revoke { REVOKE_FIELDS } else { TOKEN_FIELDS }).await else {
        return invalid();
    };
    let get = |key: &str| fields.get(key).map_or("", |value| value.as_str());
    let authorization = match (revoke, get("grant_type")) {
        (true, _) if get("token").is_empty() || get("token_type_hint") != "refresh_token" => {
            return invalid();
        }
        (true, _) => false,
        (false, "authorization_code") => {
            if get("code").is_empty()
                || get("code_verifier").is_empty()
                || get("redirect_uri").is_empty()
                || !get("refresh_token").is_empty()
            {
                return invalid_grant();
            }
            true
        }
        (false, "refresh_token") => {
            if get("refresh_token").is_empty()
                || !get("code").is_empty()
                || !get("code_verifier").is_empty()
                || !get("redirect_uri").is_empty()
            {
                return invalid_grant();
            }
            false
        }
        (false, _) => {
            return app_error(
                S::BAD_REQUEST,
                id,
                "unsupported_grant_type",
                "unsupported grant type",
            );
        }
    };
    let Ok(permit) = state.queries.try_acquire_owned() else {
        return unavailable();
    };
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _permit = permit;
        let get = |key: &str| fields.get(key).map_or("", |value| value.as_str());
        let mut store = SessionStore::open(&state.database)?;
        if revoke {
            store.revoke_application_refresh(&client, get("token"))?;
            return Ok(None);
        }
        let grant = if authorization {
            store.exchange_application_code(
                &client,
                get("code"),
                get("code_verifier"),
                get("redirect_uri"),
            )?
        } else {
            store.rotate_application_refresh(&client, get("refresh_token"))?
        };
        Ok(Some(grant.encode()?))
    })
    .await;
    match result {
        Ok(Ok(Some(body))) => no_cache(response(S::OK, id, body, false)),
        Ok(Ok(None)) => {
            let mut reply = no_content(id);
            *reply.status_mut() = S::OK;
            no_cache(reply)
        }
        _ if revoke => invalid_client(id),
        _ => invalid_grant(),
    }
}
