use super::{
    AUTH, Credential, Failure, INTERNAL, QUERY_BUSY, Reply, State, credential, form, malformed,
    mutations, response, with_session_headers,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    SessionError, SessionReply, SessionStore,
    twingate::{
        self, ConnectionStatus, Credentials, Failure as TwingateError, OwnerAccess, Storage,
    },
};
use std::sync::Arc;
use zeroize::Zeroizing;

pub(super) fn path(pieces: &[&str]) -> Option<bool> {
    match pieces {
        ["", "v1", "admin", "integrations", "twingate"] => Some(false),
        ["", "v1", "admin", "integrations", "twingate", "test"] => Some(true),
        _ => None,
    }
}

enum Action {
    Read,
    Save,
    Test,
    Disconnect,
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
    test: bool,
) -> Result<Reply, Failure> {
    let head = req.method() == Method::HEAD;
    let action = match (test, req.method()) {
        (false, &Method::GET | &Method::HEAD) => Action::Read,
        (false, &Method::PUT) => Action::Save,
        (false, &Method::DELETE) => Action::Disconnect,
        (true, &Method::POST) => Action::Test,
        _ => {
            let mut reply = Failure(
                S::METHOD_NOT_ALLOWED,
                "ERROR_CODE_MALFORMED",
                "method not allowed",
                false,
            )
            .reply(id, head);
            let allowed = if test {
                "POST"
            } else {
                "GET, HEAD, PUT, DELETE"
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
    connection_reply(result, id, head)
}

fn connection_reply(
    result: SessionReply<Result<ConnectionStatus, TwingateError>>,
    id: &str,
    head: bool,
) -> Result<Reply, Failure> {
    let data = serde_json::to_vec(&result.list.map_err(failure)?).map_err(|_| INTERNAL)?;
    with_session_headers(
        response(S::OK, id, data, head),
        Some((result.id, result.idle, result.absolute)),
    )
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
            "Save a Twingate connection before testing it.",
            false,
        ),
        TwingateError::ConnectionChanged => Failure(
            S::CONFLICT,
            "ERROR_CODE_MALFORMED",
            "The saved connection changed during the test. Reload the page and try again.",
            true,
        ),
        TwingateError::Storage => Failure(
            S::SERVICE_UNAVAILABLE,
            "ERROR_CODE_INTERNAL",
            "The controller could not access the saved Twingate connection.",
            true,
        ),
    }
}
