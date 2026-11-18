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
pub(super) fn not_modified(id: &str, deadline: u64) -> Reply {
    let mut r = response(S::NOT_MODIFIED, id, Vec::new(), true);
    r.headers_mut().remove(header::CONTENT_TYPE);
    r.headers_mut().remove(header::CONTENT_LENGTH);
    r.headers_mut().insert(
        "x-laneway-configuration-valid-until",
        header::HeaderValue::from(deadline),
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

pub(super) struct BodyError(S, Code, &'static str);

impl BodyError {
    pub(super) fn reply(self, id: &str) -> Reply {
        error(self.0, self.1, self.2, false, id)
    }
}

pub(super) async fn read_body(req: Request<Incoming>) -> Result<Zeroizing<Vec<u8>>, BodyError> {
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
        return Err(BodyError(
            S::UNSUPPORTED_MEDIA_TYPE,
            Code::Malformed,
            "Content-Type must be application/x-protobuf",
        ));
    }
    let mut data = Zeroizing::new(Vec::new());
    let mut body = req.into_body();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            return Err(BodyError(
                S::BAD_REQUEST,
                Code::Malformed,
                "could not read request body",
            ));
        };
        if let Ok(bytes) = frame.into_data() {
            if bytes.len() > 131072 - data.len() {
                return Err(BodyError(
                    S::PAYLOAD_TOO_LARGE,
                    Code::ResourceExhausted,
                    "request body exceeds limit",
                ));
            }
            data.extend_from_slice(&bytes);
        }
    }
    Ok(data)
}
