use super::{
    AUTH, Credential, Failure, INTERNAL, QUERY_BUSY, Reply, State, credential, form, malformed,
    mutations, response, valid_query_field, with_session_headers,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    SessionError, SessionReply, SessionStore,
    twingate::{self, Credentials, Failure as TwingateError, OwnerAccess, Storage},
};
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub(super) enum Route {
    Connection,
    Gateway,
    Test,
    Resources,
}

impl Route {
    pub(super) fn parse(pieces: &[&str]) -> Option<Self> {
        match pieces {
            ["", "v1", "admin", "integrations", "twingate"] => Some(Self::Connection),
            ["", "v1", "admin", "integrations", "twingate", "test"] => Some(Self::Test),
            ["", "v1", "admin", "integrations", "twingate", "resources"] => Some(Self::Resources),
            ["", "v1", "admin", "integrations", "twingate", "gateway"] => Some(Self::Gateway),
            _ => None,
        }
    }
}

enum Action {
    GatewayRead,
    GatewayEnable,
    GatewayDisable,
    Read,
    Save,
    Test,
    Disconnect,
    Resources,
}

struct Owner {
    session: Zeroizing<String>,
    csrf: Option<Zeroizing<String>>,
}

impl Owner {
    async fn run<T: Send + 'static>(
        self: &Arc<Self>,
        state: &State,
        write: bool,
        action: impl FnOnce(Storage) -> T + Send + 'static,
    ) -> Result<SessionReply<T>, Failure> {
        let permit = state
            .queries
            .clone()
            .try_acquire_owned()
            .map_err(|_| QUERY_BUSY)?;
        let actor = self.clone();
        let database = state.database.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut sessions = SessionStore::open(&database)?;
            let access = if write {
                OwnerAccess::Write(actor.csrf.as_ref().map(|value| value.as_str()))
            } else {
                OwnerAccess::Read
            };
            sessions.with_twingate_owner(&actor.session, access, || {
                action(Storage::for_database(&database))
            })
        })
        .await
        .map_err(|_| INTERNAL)?
        .map_err(|error| match error.downcast_ref::<SessionError>() {
            Some(SessionError::Denied) => mutations::DENIED,
            Some(_) => AUTH,
            None => INTERNAL,
        })
    }
}

pub(super) async fn handle(
    req: Request<Incoming>,
    state: State,
    id: &str,
    route: Route,
) -> Result<Reply, Failure> {
    let head = req.method() == Method::HEAD;
    let action = match (route, req.method()) {
        (Route::Gateway, &Method::GET | &Method::HEAD) => Action::GatewayRead,
        (Route::Gateway, &Method::PUT) => Action::GatewayEnable,
        (Route::Gateway, &Method::DELETE) => Action::GatewayDisable,
        (Route::Connection, &Method::GET | &Method::HEAD) => Action::Read,
        (Route::Connection, &Method::PUT) => Action::Save,
        (Route::Connection, &Method::DELETE) => Action::Disconnect,
        (Route::Test, &Method::POST) => Action::Test,
        (Route::Resources, &Method::GET | &Method::HEAD) => Action::Resources,
        _ => {
            let mut reply = Failure(
                S::METHOD_NOT_ALLOWED,
                "ERROR_CODE_MALFORMED",
                "method not allowed",
                false,
            )
            .reply(id, head);
            let allowed = match route {
                Route::Connection | Route::Gateway => "GET, HEAD, PUT, DELETE",
                Route::Test => "POST",
                Route::Resources => "GET, HEAD",
            };
            reply
                .headers_mut()
                .insert(header::ALLOW, header::HeaderValue::from_static(allowed));
            return Ok(reply);
        }
    };

    let Credential::Session(session) = credential(req.headers())? else {
        return Err(mutations::DENIED);
    };
    let csrf = mutations::csrf_proof(req.headers())
        .filter(|_| crate::origin::same_origin(req.headers()))
        .map(Zeroizing::new);
    let actor = Arc::new(Owner {
        session: Zeroizing::new(session),
        csrf,
    });
    let result = match action {
        Action::GatewayRead | Action::GatewayEnable | Action::GatewayDisable => {
            let configured = state.bootstrap_discovery.is_some() && state.issuer.is_some();
            let database = state.database.clone();
            let expected = req
                .headers()
                .get(header::IF_MATCH)
                .map(|value| {
                    value
                        .to_str()
                        .ok()
                        .and_then(|h| h.strip_prefix('"')?.strip_suffix('"'))
                        .filter(|tag| (1..=65).contains(&tag.len()))
                        .map(str::to_owned)
                        .ok_or(TwingateError::GatewayChanged)
                })
                .transpose();
            let result = match action {
                Action::GatewayEnable => {
                    actor.run(&state, true, |_| ()).await?;
                    let expected = expected.map_err(failure)?;
                    let input: twingate::gateway::Selection =
                        form::bounded_json_form(req, 4096).await?;
                    let checked = actor
                        .run(&state, true, |store| store.saved())
                        .await?
                        .list
                        .map_err(failure)?;
                    if state
                        .bootstrap_discovery
                        .as_ref()
                        .is_some_and(|d| Some(d.network_id()) != input.network_id.parse().ok())
                    {
                        return Err(failure(TwingateError::GatewayRoute));
                    }
                    let _check = state
                        .twingate_checks
                        .try_acquire()
                        .map_err(|_| QUERY_BUSY)?;
                    let candidate = twingate::gateway::prepare(
                        &database,
                        &checked,
                        input,
                        configured,
                        expected.as_deref(),
                    )
                    .await
                    .map_err(failure)?;
                    actor
                        .run(&state, true, move |store| {
                            store.request_gateway(&checked, candidate)?;
                            store.gateway_status(&database, configured)
                        })
                        .await?
                }
                Action::GatewayDisable => {
                    actor
                        .run(&state, true, move |store| {
                            store.remove_gateway(expected?.as_deref())?;
                            store.gateway_status(&database, configured)
                        })
                        .await?
                }
                _ => {
                    actor
                        .run(&state, false, move |store| {
                            store.gateway_status(&database, configured)
                        })
                        .await?
                }
            };
            return json_reply(result, id, head);
        }
        Action::Resources => {
            let checked = actor
                .run(&state, false, |store| store.saved())
                .await?
                .list
                .map_err(failure)?;
            let after = cursor(req.uri().query())?;
            let _check = state
                .twingate_checks
                .try_acquire()
                .map_err(|_| QUERY_BUSY)?;
            let page = twingate::list_resources(checked.credentials(), after.as_deref())
                .await
                .map_err(resource_failure)?;
            let result = actor
                .run(&state, false, move |store| {
                    store.ensure_current(&checked)?;
                    Ok(page)
                })
                .await?;
            return json_reply(result, id, head);
        }
        Action::Read => actor.run(&state, false, |store| store.status()).await?,
        Action::Disconnect => actor.run(&state, true, |store| store.disconnect()).await?,
        Action::Save => {
            actor.run(&state, true, |_| ()).await?;
            let input: Credentials = form::bounded_json_form(req, 32 * 1024).await?;
            let input = input.validated().map_err(failure)?;
            let _check = state
                .twingate_checks
                .try_acquire()
                .map_err(|_| QUERY_BUSY)?;
            twingate::verify(&input).await.map_err(failure)?;
            actor.run(&state, true, |store| store.save(input)).await?
        }
        Action::Test => {
            let checked = actor
                .run(&state, true, |store| store.saved())
                .await?
                .list
                .map_err(failure)?;
            let _check = state
                .twingate_checks
                .try_acquire()
                .map_err(|_| QUERY_BUSY)?;
            twingate::verify(checked.credentials())
                .await
                .map_err(failure)?;
            actor
                .run(&state, true, |store| store.confirm(checked))
                .await?
        }
    };
    json_reply(result, id, head)
}

fn json_reply<T: serde::Serialize>(
    result: SessionReply<Result<T, TwingateError>>,
    id: &str,
    head: bool,
) -> Result<Reply, Failure> {
    let data = serde_json::to_vec(&result.list.map_err(failure)?).map_err(|_| INTERNAL)?;
    with_session_headers(
        response(S::OK, id, data, head),
        Some((result.id, result.idle, result.absolute)),
    )
}

fn cursor(query: Option<&str>) -> Result<Option<String>, Failure> {
    let Some(query) = query.filter(|query| !query.is_empty()) else {
        return Ok(None);
    };
    if query.len() > 3 * 1024 + "after=".len() || !valid_query_field(query) {
        return Err(malformed("Invalid Twingate resource cursor."));
    }
    let mut fields = form_urlencoded::parse(query.as_bytes());
    match (fields.next(), fields.next()) {
        (Some((key, value)), None) if key == "after" && twingate::valid_cursor(&value) => {
            Ok(Some(value.into_owned()))
        }
        _ => Err(malformed("Invalid Twingate resource cursor.")),
    }
}

fn resource_failure(error: TwingateError) -> Failure {
    match error {
        TwingateError::Rejected => Failure(
            S::UNPROCESSABLE_ENTITY,
            "ERROR_CODE_MALFORMED",
            "Twingate did not allow the resource list. Check the saved connection and API token.",
            false,
        ),
        TwingateError::Unavailable => Failure(
            S::BAD_GATEWAY,
            "ERROR_CODE_INTERNAL",
            "Twingate resource inventory is unavailable. Try again shortly.",
            true,
        ),
        _ => failure(error),
    }
}

fn failure(error: TwingateError) -> Failure {
    match error {
        TwingateError::InvalidTenant => {
            malformed("Enter the network name before .twingate.com, for example acme.")
        }
        TwingateError::InvalidToken => malformed("Enter a valid Twingate API token."),
        TwingateError::Rejected => Failure(
            S::UNPROCESSABLE_ENTITY,
            "ERROR_CODE_MALFORMED",
            "Twingate rejected the connection check. Verify the network name, token, and any token IP restrictions.",
            false,
        ),
        TwingateError::RateLimited => Failure(
            S::TOO_MANY_REQUESTS,
            "ERROR_CODE_RESOURCE_EXHAUSTED",
            "Twingate limited API requests. Try again shortly.",
            true,
        ),
        TwingateError::Unavailable => Failure(
            S::BAD_GATEWAY,
            "ERROR_CODE_INTERNAL",
            "The controller could not verify the connection with Twingate. Try again shortly.",
            true,
        ),
        TwingateError::NotConnected => Failure(
            S::CONFLICT,
            "ERROR_CODE_MALFORMED",
            "Save a Twingate connection to continue.",
            false,
        ),
        TwingateError::ConnectionChanged => Failure(
            S::CONFLICT,
            "ERROR_CODE_MALFORMED",
            "The saved connection changed during the request. Refresh and try again.",
            true,
        ),
        TwingateError::GatewayConflict => Failure(
            S::CONFLICT,
            "ERROR_CODE_MALFORMED",
            "Disable the managed gateway and wait for removal before changing this configuration.",
            false,
        ),
        TwingateError::GatewayChanged => Failure(
            S::PRECONDITION_FAILED,
            "ERROR_CODE_MALFORMED",
            "The gateway changed. Refresh and confirm the change to the current gateway.",
            false,
        ),
        TwingateError::GatewayBusy => Failure(
            S::CONFLICT,
            "ERROR_CODE_RESOURCE_EXHAUSTED",
            "The managed gateway is being updated. Refresh and retry.",
            true,
        ),
        TwingateError::GatewayUnsupported => Failure(
            S::UNPROCESSABLE_ENTITY,
            "ERROR_CODE_MALFORMED",
            "Select an active IPv4 resource and a permitted TCP port.",
            false,
        ),
        TwingateError::GatewayUnavailable => Failure(
            S::SERVICE_UNAVAILABLE,
            "ERROR_CODE_INTERNAL",
            "A healthy gateway worker and a tenant bootstrap profile are required.",
            true,
        ),
        TwingateError::GatewayRoute => Failure(
            S::CONFLICT,
            "ERROR_CODE_MALFORMED",
            "Check the selected client and overlapping routes in this network.",
            false,
        ),
        TwingateError::Storage => Failure(
            S::SERVICE_UNAVAILABLE,
            "ERROR_CODE_INTERNAL",
            "The controller could not access the saved Twingate connection.",
            true,
        ),
    }
}
