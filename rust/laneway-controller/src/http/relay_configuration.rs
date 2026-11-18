use super::{
    Reply, State,
    node_proto::{error, failure, internal, proto, read_body},
    response,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    SessionStore,
    enrollment::{
        EnrollError,
        configuration::ConfigurationError,
        relay_configuration::{RelayCredential, RelayReply},
    },
};
use laneway_protocol::v1::{ErrorCode as Code, RelayConfigurationRequest};
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
            .insert(header::ALLOW, header::HeaderValue::from_static("POST"));
        return r;
    }
    let Some(cert) = req.extensions_mut().remove::<CertificateDer<'static>>() else {
        return failure(EnrollError::Invalid.into(), id);
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
            let peer = RelayCredential::from_verified_peer(cert.as_ref())?;
            let mut store = SessionStore::open(&state.database)?;
            store.check_relay_peer(&peer)?;
            Ok((peer, store, permit))
        })
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return failure(e, id),
            Err(_) => return internal(id),
        };
    let body = match read_body(req, id).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let (cancel, _alive) = tokio::sync::oneshot::channel::<()>();
    let validity = state.snapshot_validity;
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let req = RelayConfigurationRequest::decode(body.as_slice())
            .map_err(|_| EnrollError::Malformed("malformed protobuf request"))?;
        store.relay_configuration(&peer, req, validity, || cancel.is_closed())
    })
    .await
    {
        Ok(Ok(RelayReply::Snapshot(cfg))) => proto(S::OK, id, cfg),
        Ok(Ok(RelayReply::Lease(lease))) => {
            let mut r = response(S::NOT_MODIFIED, id, Vec::new(), true);
            r.headers_mut().remove(header::CONTENT_TYPE);
            r.headers_mut().remove(header::CONTENT_LENGTH);
            r.headers_mut().insert(
                "x-laneway-configuration-valid-until",
                header::HeaderValue::from(lease.valid_until_unix_seconds),
            );
            r
        }
        Ok(Err(e))
            if matches!(
                e.downcast_ref::<ConfigurationError>(),
                Some(ConfigurationError::StaleEpoch)
            ) =>
        {
            error(
                S::CONFLICT,
                Code::StaleEpoch,
                "known epoch is ahead of controller",
                false,
                id,
            )
        }
        Ok(Err(e)) => failure(e, id),
        Err(_) => internal(id),
    }
}
