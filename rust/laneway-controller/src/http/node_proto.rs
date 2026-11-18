use super::{Reply, response};
use http_body_util::BodyExt;
use hyper::{Request, StatusCode as S, body::Incoming, header};
use laneway_controller::enrollment::EnrollError;
use laneway_protocol::v1::{ErrorCode as Code, ProtocolError};
use prost::Message;
use zeroize::Zeroizing;
pub(super) fn proto(status: S, id: &str, body: impl Message) -> Reply {
    let mut r = response(status, id, body.encode_to_vec(), false);
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/x-protobuf".parse().unwrap(),
    );
    r
}
pub(super) fn error(status: S, code: Code, detail: &str, retryable: bool, id: &str) -> Reply {
    proto(
        status,
        id,
        ProtocolError {
            code: code as i32,
            detail: detail.into(),
            retryable,
        },
    )
}
pub(super) fn failure(err: anyhow::Error, id: &str) -> Reply {
    let Some(e) = err.downcast_ref::<EnrollError>() else {
        return internal(id);
    };
    let (status, code) = match e {
        EnrollError::Invalid | EnrollError::Expired => (S::UNAUTHORIZED, Code::Unauthenticated),
        EnrollError::Denied | EnrollError::Name | EnrollError::Class | EnrollError::Network => {
            (S::FORBIDDEN, Code::PermissionDenied)
        }
        EnrollError::Used | EnrollError::Conflict => (S::CONFLICT, Code::PermissionDenied),
        EnrollError::Malformed(_) => (S::BAD_REQUEST, Code::Malformed),
        EnrollError::PoolExhausted => return internal(id),
    };
    error(status, code, &e.to_string(), false, id)
}
pub(super) fn internal(id: &str) -> Reply {
    error(
        S::INTERNAL_SERVER_ERROR,
        Code::Internal,
        "internal controller error",
        true,
        id,
    )
}

pub(super) async fn read_body(
    req: Request<Incoming>,
    id: &str,
) -> Result<Zeroizing<Vec<u8>>, Reply> {
    let media = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<mime::Mime>().ok());
    if !media.is_some_and(|m| {
        matches!(
            m.essence_str(),
            "application/protobuf" | "application/x-protobuf"
        )
    }) {
        return Err(error(
            S::UNSUPPORTED_MEDIA_TYPE,
            Code::Malformed,
            "Content-Type must be application/x-protobuf",
            false,
            id,
        ));
    }
    let mut data = Zeroizing::new(Vec::new());
    let mut body = req.into_body();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            return Err(error(
                S::BAD_REQUEST,
                Code::Malformed,
                "could not read request body",
                false,
                id,
            ));
        };
        if let Ok(bytes) = frame.into_data() {
            if bytes.len() > 131072 - data.len() {
                return Err(error(
                    S::PAYLOAD_TOO_LARGE,
                    Code::ResourceExhausted,
                    "request body exceeds limit",
                    false,
                    id,
                ));
            }
            data.extend_from_slice(&bytes);
        }
    }
    Ok(data)
}
