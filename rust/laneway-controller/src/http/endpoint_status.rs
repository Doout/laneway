use super::{
    AUTH, Failure, INTERNAL, Reply, State, form::required_json_form, mutations::DENIED, response,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    SessionStore,
    enrollment::{EnrollError, renewal::NodeCredential},
};
use laneway_protocol::endpoint_status::Report;
use rustls::pki_types::CertificateDer;

pub(super) async fn handle(
    mut req: Request<Incoming>,
    state: State,
    id: &str,
) -> Result<Reply, Failure> {
    if req.method() != Method::PUT {
        let mut r = Failure(
            S::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
            false,
        )
        .reply(id, req.method() == Method::HEAD);
        r.headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("PUT"));
        return Ok(r);
    }
    let leaf = req
        .extensions_mut()
        .remove::<CertificateDer<'static>>()
        .ok_or(AUTH)?;
    let permit = state.queries.try_acquire_owned().map_err(|_| {
        Failure(
            S::SERVICE_UNAVAILABLE,
            "ERROR_CODE_RESOURCE_EXHAUSTED",
            "controller busy",
            true,
        )
    })?;
    let (peer, mut store, permit) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let peer = NodeCredential::from_verified_peer(leaf.as_ref())?;
        let mut store = SessionStore::open(&state.database)?;
        store.check_node_peer(&peer)?;
        Ok((peer, store, permit))
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    let report = required_json_form::<Report>(req).await?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        store.record_endpoint_status(&peer, report)
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    let mut reply = response(S::NO_CONTENT, id, Vec::new(), true);
    reply.headers_mut().remove(header::CONTENT_LENGTH);
    reply.headers_mut().remove(header::CONTENT_TYPE);
    Ok(reply)
}

fn failure(err: anyhow::Error) -> Failure {
    match err.downcast_ref::<EnrollError>() {
        Some(EnrollError::Denied) => DENIED,
        Some(EnrollError::Invalid) => AUTH,
        _ => super::access_admin::failure(err),
    }
}
