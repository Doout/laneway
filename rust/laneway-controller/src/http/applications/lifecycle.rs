use super::{BUSY, no_cache};
use crate::http::{
    Credential, Failure, INTERNAL, Reply, State, administrators::failure, credential,
    form::required_json_form, malformed, mutations::csrf_proof, no_content, response,
    with_session_headers,
};
use hyper::{
    Request, StatusCode as S,
    body::{Body, Incoming},
};
use laneway_controller::{SessionStore, administrators::Caller, applications::lifecycle::Action};
use laneway_protocol::Id;
use serde::{Deserialize, Serialize};

pub(super) async fn handle(
    req: Request<Incoming>,
    state: State,
    id: &str,
    app: &str,
    action: Action,
) -> Result<Reply, Failure> {
    let auth = credential(req.headers())?;
    let csrf = csrf_proof(req.headers()).filter(|_| crate::origin::same_origin(req.headers()));
    let app = app
        .parse::<Id>()
        .map_err(|_| malformed("invalid application_id"));
    let canonical = app.as_ref().ok().map(ToString::to_string);
    let parsed = if matches!(action, Action::RotateSecret)
        && req.body().size_hint().exact().is_some_and(|n| n > 0)
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Empty {}
        required_json_form::<Empty>(req).await.map(|_| ())
    } else {
        Ok(())
    };
    let permit = state.queries.try_acquire_owned().map_err(|_| BUSY)?;
    let outcome = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let pending = (|| {
            let app = app?;
            parsed?;
            Ok::<_, anyhow::Error>(app)
        })();
        let caller = match &auth {
            Credential::Session(token) => Caller::Browser {
                token,
                csrf: csrf.as_deref(),
            },
            Credential::Bearer(header) => Caller::Bearer {
                header,
                root: state.root.as_deref(),
            },
        };
        SessionStore::open(&state.database)?.change_registered_application(caller, pending, action)
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    let reply = if let Some(secret) = outcome.secret {
        #[derive(Serialize)]
        struct Rotated<'a> {
            application_id: &'a str,
            client_secret: &'a str,
        }
        let data = serde_json::to_vec(&Rotated {
            application_id: canonical.as_deref().ok_or(INTERNAL)?,
            client_secret: &secret,
        })
        .map_err(|_| INTERNAL)?;
        no_cache(response(S::CREATED, id, data, false))
    } else {
        no_content(id)
    };
    with_session_headers(reply, outcome.session)
}
