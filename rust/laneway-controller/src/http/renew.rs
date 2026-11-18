use super::{
    Reply, State,
    node_proto::{error, failure, internal, proto, read_body},
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    SessionStore,
    enrollment::{EnrollError, renewal::NodeCredential},
};
use laneway_protocol::v1::{ErrorCode as Code, RenewalRequest};
use prost::Message;
use rustls::pki_types::CertificateDer;

pub(super) async fn handle(mut req: Request<Incoming>, state: State, id: &str) -> Reply {
    if req.method() != Method::POST {
        let mut r = error(
            S::METHOD_NOT_ALLOWED,
            Code::Malformed,
            "method not allowed",
            false,
            id,
        );
        r.headers_mut()
            .insert(header::ALLOW, "POST".parse().unwrap());
        return r;
    }
    let Some(leaf) = req.extensions_mut().remove::<CertificateDer<'static>>() else {
        return failure(EnrollError::Invalid.into(), id);
    };
    let Some(issuer) = state.issuer else {
        return internal(id);
    };
    let Ok(permit) = state.queries.try_acquire_owned() else {
        return error(
            S::SERVICE_UNAVAILABLE,
            Code::ResourceExhausted,
            "controller busy",
            true,
            id,
        );
    };
    let (peer, mut store, permit) =
        match tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            let peer = NodeCredential::from_verified_peer(leaf.as_ref())?;
            let mut store = SessionStore::open(&state.database)?;
            store.check_node_peer(&peer)?;
            Ok((peer, store, permit))
        })
        .await
        {
            Ok(Ok(it)) => it,
            Ok(Err(e)) => return failure(e, id),
            Err(_) => return internal(id),
        };
    let data = match read_body(req, id).await {
        Ok(data) => data,
        Err(r) => return r,
    };
    let (cancel, _alive) = tokio::sync::oneshot::channel::<()>();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let req = RenewalRequest::decode(data.as_slice())
            .map_err(|_| EnrollError::Malformed("malformed protobuf request"))?;
        store.renew_certificate(
            &peer,
            req,
            &issuer,
            laneway_controller::enrollment::renewal::RenewalTransport::Https,
            || cancel.is_closed(),
        )
    })
    .await
    {
        Ok(Ok(r)) => proto(S::OK, id, r),
        Ok(Err(e)) => failure(e, id),
        Err(_) => internal(id),
    }
}
