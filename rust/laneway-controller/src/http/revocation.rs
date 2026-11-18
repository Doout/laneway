use super::{
    Reply, State,
    node_proto::{error, failure, internal, proto},
    response,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    SessionStore,
    enrollment::{EnrollError, renewal::NodeCredential, revocation::RevocationStatus},
};
use laneway_protocol::v1::ErrorCode as Code;
use rustls::pki_types::CertificateDer;

pub(super) fn parse_serial(serial: &str) -> Option<Vec<u8>> {
    if serial.is_empty() || serial.len() > 64 || serial.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(serial).ok()
}

pub(super) async fn handle(
    mut req: Request<Incoming>,
    state: State,
    id: &str,
    serial: &str,
) -> Reply {
    let head = req.method() == Method::HEAD;
    let mut reply = read(&mut req, state, id, serial).await;
    if head {
        *reply.body_mut() = http_body_util::Full::new(bytes::Bytes::new());
    }
    reply
}

async fn read(req: &mut Request<Incoming>, state: State, id: &str, serial: &str) -> Reply {
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        let mut r = error(
            S::METHOD_NOT_ALLOWED,
            Code::Malformed,
            "method not allowed",
            false,
            id,
        );
        r.headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("GET, HEAD"));
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
    let serial = parse_serial(serial);
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let peer = NodeCredential::from_verified_peer(cert.as_ref())?;
        SessionStore::open(&state.database)?.certificate_revocation(&peer, serial)
    })
    .await
    {
        Ok(Ok(RevocationStatus::Revoked(record))) => proto(S::OK, id, record),
        Ok(Ok(RevocationStatus::Missing)) => {
            error(S::NOT_FOUND, Code::Malformed, "record not found", false, id)
        }
        Ok(Ok(RevocationStatus::NotRevoked)) => {
            let mut r = response(S::NO_CONTENT, id, Vec::new(), true);
            r.headers_mut().remove(header::CONTENT_LENGTH);
            r.headers_mut().remove(header::CONTENT_TYPE);
            r
        }
        Ok(Err(err)) => failure(err, id),
        Err(_) => internal(id),
    }
}
