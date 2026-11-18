use super::{
    AUTH, COOKIE, Credential, Failure, INTERNAL, Reply, State, cookie, credential,
    form::required_json_form, login::limited, malformed, mutations::DENIED, no_content, response,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    SessionError, SessionStore,
    password::{Busy, valid_length},
    recovery::{Purpose, RecoveryError, valid_username},
};
use laneway_protocol::Id;
use serde::{Deserialize, Deserializer};
use serde_json::json;
use std::{net::IpAddr, time::Instant};
use zeroize::Zeroizing;

pub(super) enum Route<'a> {
    Issue(Option<&'a str>),
    Redeem(Purpose),
}

impl<'a> Route<'a> {
    pub(super) fn parse(parts: &[&'a str]) -> Option<Self> {
        Some(match parts {
            ["", "v1", "admin", "auth", "bootstrap-grants"] => Self::Issue(None),
            [
                "",
                "v1",
                "admin",
                "administrators",
                target,
                "recovery-grants",
            ] => Self::Issue(Some(target)),
            ["", "v1", "admin", "auth", "bootstrap"] => Self::Redeem(Purpose::Bootstrap),
            ["", "v1", "admin", "auth", "recover"] => Self::Redeem(Purpose::Owner),
            _ => return None,
        })
    }
}

fn secret<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    Ok(Zeroizing::new(
        Option::<String>::deserialize(d)?.unwrap_or_default(),
    ))
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RecoveryForm {
    #[serde(deserialize_with = "secret")]
    grant: Zeroizing<String>,
    #[serde(deserialize_with = "secret")]
    password: Zeroizing<String>,
}

impl Default for RecoveryForm {
    fn default() -> Self {
        Self {
            grant: Zeroizing::new(String::new()),
            password: Zeroizing::new(String::new()),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapForm {
    username: Option<String>,
    #[serde(default = "empty_secret", deserialize_with = "secret")]
    grant: Zeroizing<String>,
    #[serde(default = "empty_secret", deserialize_with = "secret")]
    password: Zeroizing<String>,
}

fn empty_secret() -> Zeroizing<String> {
    Zeroizing::new(String::new())
}

fn store_error(err: anyhow::Error) -> Failure {
    match err.downcast_ref::<RecoveryError>() {
        Some(RecoveryError::BootstrapComplete) => Failure(
            S::CONFLICT,
            "ERROR_CODE_PERMISSION_DENIED",
            "administrator bootstrap is already complete",
            false,
        ),
        Some(RecoveryError::Missing) => Failure(
            S::NOT_FOUND,
            "ERROR_CODE_MALFORMED",
            "record not found",
            false,
        ),
        Some(RecoveryError::Conflict) => Failure(
            S::CONFLICT,
            "ERROR_CODE_PERMISSION_DENIED",
            "request conflicts with controller state",
            false,
        ),
        None => match err.downcast_ref::<SessionError>() {
            Some(SessionError::Denied) => DENIED,
            Some(_) => AUTH,
            None => INTERNAL,
        },
    }
}

const CONTROLLER_BUSY: Failure = Failure(
    S::SERVICE_UNAVAILABLE,
    "ERROR_CODE_RESOURCE_EXHAUSTED",
    "controller busy",
    true,
);

pub(super) async fn handle(
    req: Request<Incoming>,
    state: State,
    id: &str,
    peer: IpAddr,
    route: Route<'_>,
) -> Result<Reply, Failure> {
    if req.method() != Method::POST {
        let mut reply = Failure(
            S::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
            false,
        )
        .reply(id, req.method() == Method::HEAD);
        reply
            .headers_mut()
            .insert(header::ALLOW, "POST".parse().unwrap());
        return Ok(reply);
    }
    match route {
        Route::Issue(target) => issue(req, state, id, target).await,
        Route::Redeem(purpose) => redeem(req, state, id, peer, purpose).await,
    }
}

async fn issue(
    req: Request<Incoming>,
    state: State,
    id: &str,
    target: Option<&str>,
) -> Result<Reply, Failure> {
    let caller = credential(req.headers())?;
    let target = target
        .map(|raw| {
            raw.parse::<Id>()
                .map_err(|_| malformed("invalid administrator ID"))
        })
        .transpose()?;
    let permit = state
        .queries
        .clone()
        .try_acquire_owned()
        .map_err(|_| CONTROLLER_BUSY)?;
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut db = SessionStore::open(&state.database)?;
        match caller {
            Credential::Bearer(header) => {
                db.issue_recovery_grant(&header, state.root.as_deref(), target)
            }
            Credential::Session(session) => db.deny_root_only_session(&session),
        }
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(store_error)?;
    Ok(response(
        S::CREATED,
        id,
        json!({"grant": &*result.secret, "expires_at_unix_seconds": result.expires})
            .to_string()
            .into_bytes(),
        false,
    ))
}

async fn audit_failure(state: &State, busy: bool) {
    let db = state.database.clone();
    let _ =
        tokio::task::spawn_blocking(move || SessionStore::open(&db)?.audit_recovery_failure(busy))
            .await;
}

async fn redeem(
    req: Request<Incoming>,
    state: State,
    id: &str,
    peer: IpAddr,
    purpose: Purpose,
) -> Result<Reply, Failure> {
    let headers = req.headers();
    if headers.contains_key(header::AUTHORIZATION) || cookie(headers, COOKIE)?.is_some() {
        return Err(AUTH);
    }
    if !crate::origin::same_origin(headers) {
        return Err(DENIED);
    }
    let forwarded = headers.contains_key("x-laneway-public-client-ip");
    let (username, grant, password, bucket) = match purpose {
        Purpose::Bootstrap => {
            let form: BootstrapForm = required_json_form(req).await?;
            (
                form.username.unwrap_or_default(),
                form.grant,
                form.password,
                "bootstrap",
            )
        }
        Purpose::Owner => {
            let form: RecoveryForm = required_json_form(req).await?;
            (String::new(), form.grant, form.password, "recovery")
        }
    };
    if forwarded {
        return Err(AUTH);
    }
    let attempt =
        state
            .recoveries
            .lock()
            .map_err(|_| INTERNAL)?
            .attempt(peer, bucket, Instant::now());
    if let Err(wait) = attempt {
        return Ok(limited(id, wait));
    }
    let _permit = state
        .queries
        .clone()
        .try_acquire_owned()
        .map_err(|_| CONTROLLER_BUSY)?;
    let db = state.database.clone();
    let candidate = match tokio::task::spawn_blocking(move || {
        SessionStore::open(&db)?.recovery_candidate(&grant, purpose)
    })
    .await
    .map_err(|_| INTERNAL)?
    {
        Ok(candidate) => candidate,
        Err(err) if err.is::<SessionError>() => {
            audit_failure(&state, false).await;
            return Err(AUTH);
        }
        Err(_) => return Err(INTERNAL),
    };
    if matches!(purpose, Purpose::Bootstrap) && !valid_username(&username) {
        return Err(malformed("invalid username"));
    }
    if !valid_length(password.as_bytes()) {
        return Err(malformed("invalid password"));
    }
    let hash = match state.passwords.hash(password).await {
        Ok(hash) => hash,
        Err(err) if err.is::<Busy>() => {
            audit_failure(&state, true).await;
            return Ok(limited(id, 1));
        }
        Err(_) => return Err(INTERNAL),
    };
    let db = state.database.clone();
    match tokio::task::spawn_blocking(move || {
        SessionStore::open(&db)?.redeem_recovery(candidate, &username, hash)
    })
    .await
    .map_err(|_| INTERNAL)?
    {
        Ok(()) => Ok(no_content(id)),
        Err(err) if err.is::<SessionError>() => {
            audit_failure(&state, false).await;
            Err(AUTH)
        }
        Err(err) => Err(store_error(err)),
    }
}
