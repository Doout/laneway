use super::{AUTH, Failure, INTERNAL, Reply, State, response};
use hyper::{Method, Request, StatusCode as S, body::Incoming};
use laneway_controller::{
    SessionStore,
    enrollment::{EnrollError, renewal::NodeCredential},
};
use rustls::pki_types::CertificateDer;

pub(super) async fn handle(
    mut req: Request<Incoming>,
    state: State,
    id: &str,
) -> Result<Reply, Failure> {
    let head = req.method() == Method::HEAD;
    if !head && req.method() != Method::GET {
        return Err(Failure(
            S::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
            false,
        ));
    }
    let cert = req
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
    let bytes = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _permit = permit;
        let peer = NodeCredential::from_verified_peer(cert.as_ref())?;
        SessionStore::open(&state.database)?.node_private_dns(&peer)
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(|err| match err.downcast_ref::<EnrollError>() {
        Some(EnrollError::Invalid) => AUTH,
        Some(EnrollError::Denied) => Failure(
            S::FORBIDDEN,
            "ERROR_CODE_PERMISSION_DENIED",
            "permission denied",
            false,
        ),
        _ => INTERNAL,
    })?;
    Ok(response(S::OK, id, bytes, head))
}
