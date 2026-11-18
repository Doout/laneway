use super::{
    AUTH, Failure, INTERNAL, Reply, State,
    mutations::{DENIED, csrf_proof},
    response,
};
use hyper::StatusCode;
use laneway_controller::{
    ListError, NetworkError, RootCredential, SessionError, SessionReply, SessionStore,
};
use serde::{Serialize, de::DeserializeOwned};

type BrowserWriter<F, T> =
    fn(&mut SessionStore, &str, Option<&str>, anyhow::Result<F>) -> anyhow::Result<SessionReply<T>>;
type BearerWriter<F, T> =
    fn(&mut SessionStore, &str, Option<&RootCredential>, anyhow::Result<F>) -> anyhow::Result<T>;

pub(super) async fn create<
    F: DeserializeOwned + Default + Send + 'static,
    T: Serialize + Send + 'static,
>(
    req: hyper::Request<hyper::body::Incoming>,
    state: State,
    id: &str,
    browser: BrowserWriter<F, T>,
    bearer: BearerWriter<F, T>,
) -> Result<Reply, Failure> {
    let auth = super::credential(req.headers())?;
    let proof = csrf_proof(req.headers()).filter(|_| crate::origin::same_origin(req.headers()));
    // Buffer a bounded body before obtaining a database worker. A slow
    // upload must not hold a SQLite write lock or exhaust the query pool.
    let form = super::form::json_form::<F>(req).await;
    let permit = state.queries.try_acquire_owned().map_err(|_| {
        Failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERROR_CODE_RESOURCE_EXHAUSTED",
            "controller busy",
            true,
        )
    })?;
    let (created, meta) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _permit = permit;
        let mut store = SessionStore::open(&state.database)?;
        let form = form.map_err(anyhow::Error::from);
        Ok(match auth {
            super::Credential::Session(token) => {
                let r = browser(&mut store, &token, proof.as_deref(), form)?;
                (r.list, Some((r.id, r.idle, r.absolute)))
            }
            super::Credential::Bearer(header) => (
                bearer(&mut store, &header, state.root.as_deref(), form)?,
                None,
            ),
        })
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(|e| {
        if matches!(e.downcast_ref::<ListError>(), Some(ListError::Missing)) {
            return Failure(
                StatusCode::NOT_FOUND,
                "ERROR_CODE_MALFORMED",
                "record not found",
                false,
            );
        }
        if let Some(p) = e.downcast_ref::<NetworkError>() {
            return match p {
                NetworkError::Malformed(detail) => super::malformed(detail),
                NetworkError::Conflict => Failure(
                    StatusCode::CONFLICT,
                    "ERROR_CODE_PERMISSION_DENIED",
                    "request conflicts with controller state",
                    false,
                ),
            };
        }
        if let Some(p) = e.downcast_ref::<SessionError>() {
            return match p {
                SessionError::Denied => DENIED,
                _ => AUTH,
            };
        }
        e.downcast::<Failure>().unwrap_or(INTERNAL)
    })?;
    super::with_session_headers(
        response(
            StatusCode::CREATED,
            id,
            serde_json::to_vec(&created).map_err(|_| INTERNAL)?,
            false,
        ),
        meta,
    )
}
