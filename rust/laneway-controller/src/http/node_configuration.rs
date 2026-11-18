use super::{
    Reply, State,
    node_proto::{error, failure, internal, not_modified, proto, read_body},
    record_presence,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    SessionStore,
    enrollment::{EnrollError, configuration::ConfigurationError, renewal::NodeCredential},
};
use laneway_protocol::v1::{ConfigurationRequest, ErrorCode as Code, controller_envelope::Body};
use prost::Message;
use rustls::pki_types::CertificateDer;
use std::net::IpAddr;

pub(super) async fn handle(
    mut req: Request<Incoming>,
    state: State,
    id: &str,
    remote: IpAddr,
) -> Reply {
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
    let locations = state.locations.clone();
    let Ok(permit) = state.queries.try_acquire_owned() else {
        return error(
            S::SERVICE_UNAVAILABLE,
            Code::ResourceExhausted,
            "controller busy",
            true,
            id,
        );
    };
    let validity = state.snapshot_validity;
    let (peer, mut store, permit) =
        match tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            let peer = NodeCredential::from_verified_peer(cert.as_ref())?;
            let mut store = SessionStore::open(&state.database)?;
            store.check_node_peer(&peer)?;
            Ok((peer, store, permit))
        })
        .await
        {
            Ok(Ok(value)) => value,
            Ok(Err(err)) => return failure(err, id),
            Err(_) => return internal(id),
        };
    let data = match read_body(req, id).await {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let (cancel, _alive) = tokio::sync::oneshot::channel::<()>();
    match tokio::task::spawn_blocking(move || -> anyhow::Result<Body> {
        let _permit = permit;
        let req = ConfigurationRequest::decode(data.as_slice())
            .map_err(|_| EnrollError::Malformed("malformed protobuf request"))?;
        // HTTPS never holds the exclusive ephemeral Exit control claim.
        // Both transports build and lease the same transaction-bound snapshot.
        let snapshot =
            store.node_configuration(&peer, req, false, validity, || cancel.is_closed())?;
        if !cancel.is_closed() {
            record_presence(&mut store, &peer, remote, locations.as_deref());
        }
        Ok(snapshot)
    })
    .await
    {
        Ok(Ok(Body::NodeConfiguration(snapshot))) => proto(S::OK, id, snapshot),
        Ok(Ok(Body::ConfigurationLease(lease))) => not_modified(id, lease.valid_until_unix_seconds),
        Ok(Err(err))
            if matches!(
                err.downcast_ref::<ConfigurationError>(),
                Some(ConfigurationError::StaleEpoch)
            ) =>
        {
            error(
                S::CONFLICT,
                Code::StaleEpoch,
                "known configuration epoch is ahead of controller",
                false,
                id,
            )
        }
        Ok(Err(err)) => failure(err, id),
        _ => internal(id),
    }
}
