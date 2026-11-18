use super::failure;
use crate::http::{
    Credential, Failure, INTERNAL, Reply, State, credential,
    form::{empty_secret, required_json_form, secret},
    login::limited,
    malformed, mutations, no_content, response, with_session_headers,
};
use hyper::{Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    RootCredential, SessionStore,
    administrators::{Access, Caller, Change},
    password::{Busy, PasswordHash, valid_length},
};
use laneway_protocol::Id;
use serde::Deserialize;
use std::{collections::HashSet, sync::Arc};
use zeroize::Zeroizing;

pub(super) enum Route<'a> {
    Create,
    Update(&'a str),
    Password(&'a str),
    Revoke(&'a str),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateForm {
    username: Option<String>,
    role: Option<String>,
    all_networks: Option<bool>,
    network_ids: Option<Vec<String>>,
    #[serde(default = "empty_secret", deserialize_with = "secret")]
    password: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessForm {
    role: Option<String>,
    all_networks: Option<bool>,
    network_ids: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateForm {
    access: Option<AccessForm>,
    enabled: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordForm {
    #[serde(default = "empty_secret", deserialize_with = "secret")]
    password: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeForm {
    reason: Option<String>,
}

fn networks(values: Vec<String>) -> Result<Vec<Id>, Failure> {
    let mut seen = HashSet::with_capacity(values.len());
    let mut networks = Vec::with_capacity(values.len());
    for value in values {
        let id = value
            .parse()
            .map_err(|_| malformed("invalid network_ids"))?;
        if !seen.insert(id) {
            return Err(malformed("duplicate network_ids"));
        }
        networks.push(id);
    }
    Ok(networks)
}

enum PasswordTarget {
    New(String, Access),
    Existing(Id),
}

impl PasswordTarget {
    fn action(self, password: PasswordHash) -> Change {
        match self {
            Self::New(username, access) => Change::Create {
                username,
                access,
                password,
            },
            Self::Existing(id) => Change::ReplacePassword { id, password },
        }
    }
}

enum Pending {
    Ready(Change),
    Derive(PasswordTarget, Zeroizing<String>),
}

async fn input(route: Route<'_>, req: Request<Incoming>) -> Result<Pending, Failure> {
    let principal = |id: &str| {
        id.parse::<Id>()
            .map_err(|_| malformed("invalid principal_id"))
    };
    Ok(match route {
        Route::Create => {
            let form: CreateForm = required_json_form(req).await?;
            let access = Access {
                role: form.role.unwrap_or_default(),
                all_networks: form.all_networks.unwrap_or(false),
                networks: networks(form.network_ids.unwrap_or_default())?,
            };
            Pending::Derive(
                PasswordTarget::New(form.username.unwrap_or_default(), access),
                form.password,
            )
        }
        Route::Update(id) => {
            let id = principal(id)?;
            let form: UpdateForm = required_json_form(req).await?;
            if form.access.is_none() && form.enabled.is_none() {
                return Err(malformed("access or enabled is required"));
            }
            let access = if let Some(fields) = form.access {
                let (Some(role), Some(all_networks), Some(ids)) =
                    (fields.role, fields.all_networks, fields.network_ids)
                else {
                    return Err(malformed(
                        "access requires role, all_networks, and network_ids",
                    ));
                };
                Some(Access {
                    role,
                    all_networks,
                    networks: networks(ids)?,
                })
            } else {
                None
            };
            Pending::Ready(Change::Update {
                id,
                access,
                enabled: form.enabled,
            })
        }
        Route::Password(id) => {
            let id = principal(id)?;
            let form: PasswordForm = required_json_form(req).await?;
            Pending::Derive(PasswordTarget::Existing(id), form.password)
        }
        Route::Revoke(raw) => {
            let session = raw.parse().map_err(|_| malformed("invalid session_id"))?;
            let form: RevokeForm = required_json_form(req).await?;
            Pending::Ready(Change::RevokeSession {
                session,
                reason: form.reason.unwrap_or_default(),
            })
        }
    })
}

struct Auth {
    credential: Credential,
    csrf: Option<String>,
    root: Option<Arc<RootCredential>>,
}

const CONTROLLER_BUSY: Failure = Failure(
    S::SERVICE_UNAVAILABLE,
    "ERROR_CODE_RESOURCE_EXHAUSTED",
    "controller busy",
    true,
);

impl Auth {
    fn caller(&self) -> Caller<'_> {
        match &self.credential {
            Credential::Session(token) => Caller::Browser {
                token,
                csrf: self.csrf.as_deref(),
            },
            Credential::Bearer(header) => Caller::Bearer {
                header,
                root: self.root.as_deref(),
            },
        }
    }
}

pub(super) async fn handle(
    req: Request<Incoming>,
    state: State,
    id: &str,
    route: Route<'_>,
) -> Result<Reply, Failure> {
    let create = matches!(route, Route::Create);
    let auth = Arc::new(Auth {
        credential: credential(req.headers())?,
        csrf: mutations::csrf_proof(req.headers())
            .filter(|_| crate::origin::same_origin(req.headers())),
        root: state.root,
    });
    let permit = state
        .queries
        .clone()
        .try_acquire_owned()
        .map_err(|_| CONTROLLER_BUSY)?;
    let database = state.database.clone();
    let preflight = auth.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        SessionStore::open(&database)?.check_administrator_change(preflight.caller())
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    let pending = input(route, req).await?;
    let permit = state
        .queries
        .try_acquire_owned()
        .map_err(|_| CONTROLLER_BUSY)?;
    let action = match pending {
        Pending::Ready(action) => action,
        Pending::Derive(target, password) => {
            if !valid_length(password.as_bytes()) {
                return Err(malformed("invalid password"));
            }
            match state.passwords.hash(password).await {
                Ok(hash) => target.action(hash),
                Err(e) if e.is::<Busy>() => return Ok(limited(id, 1)),
                Err(_) => return Err(INTERNAL),
            }
        }
    };
    let changed = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        SessionStore::open(&state.database)?.change_administrator(auth.caller(), action)
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    let mut reply = if let Some(principal) = changed.principal {
        let status = if create { S::CREATED } else { S::OK };
        let body = serde_json::to_vec(&principal).map_err(|_| INTERNAL)?;
        let mut reply = response(status, id, body, false);
        if create {
            reply.headers_mut().insert(
                header::LOCATION,
                format!("/v1/admin/administrators/{}", principal.id())
                    .parse()
                    .map_err(|_| INTERNAL)?,
            );
        }
        reply
    } else {
        no_content(id)
    };
    if changed.clear_cookies {
        mutations::clear_cookies(&mut reply);
    }
    with_session_headers(reply, changed.session)
}
