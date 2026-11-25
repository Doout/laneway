use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::{Method, Request, Response, StatusCode, body::Incoming, header};
use laneway_protocol::v1::{EnrollmentRequest, ErrorCode, ProtocolError, RenewalRequest};
use prost::Message;

use crate::{
    enrollment::{self, EnrollmentAuthority, EnrollmentError},
    store::Store,
};

type Reply = Response<Full<Bytes>>;
const MAX_BODY: usize = 128 << 10;
const PROTOBUF: &str = "application/x-protobuf";

pub(super) struct Enrollment {
    pub(crate) authority: EnrollmentAuthority,
    rate_limit: Mutex<RateLimit>,
}

impl Enrollment {
    pub(super) fn new(authority: EnrollmentAuthority) -> Self {
        Self {
            authority,
            rate_limit: Mutex::new(RateLimit::default()),
        }
    }

    pub(super) async fn handle(
        self: Arc<Self>,
        store: Arc<Mutex<Store>>,
        request: Request<Incoming>,
        peer: IpAddr,
    ) -> Reply {
        if request.method() != Method::POST {
            let mut reply = error(
                StatusCode::METHOD_NOT_ALLOWED,
                ErrorCode::Malformed,
                "method not allowed",
            );
            reply
                .headers_mut()
                .insert(header::ALLOW, header::HeaderValue::from_static("POST"));
            return reply;
        }
        let allowed = match self.rate_limit.lock() {
            Ok(mut limit) => limit.allow(peer, Instant::now()),
            Err(_) => return internal(),
        };
        if !allowed {
            let mut reply = error(
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::ResourceExhausted,
                "enrollment rate limit exceeded; retry later",
            );
            reply
                .headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
            return reply;
        }

        let request: EnrollmentRequest = match decode_protobuf(request).await {
            Ok(request) => request,
            Err(error) => return enrollment_error(error),
        };
        let canceled = Arc::new(AtomicBool::new(false));
        let _cancel_on_disconnect = CancelOnDrop(canceled.clone());
        let outcome = tokio::task::spawn_blocking(move || {
            let mut store = store.lock().map_err(|_| EnrollmentError {
                status: 500,
                code: ErrorCode::Internal,
                detail: "internal controller error",
                retryable: true,
            })?;
            enrollment::enroll(&mut store, &self.authority, request, &canceled)
        })
        .await;
        match outcome {
            Ok(Ok(response)) => protobuf(StatusCode::CREATED, response),
            Ok(Err(problem)) => enrollment_error(problem),
            Err(_) => internal(),
        }
    }

    pub(crate) async fn handle_renew(
        self: Arc<Self>,
        store: Arc<Mutex<Store>>,
        peer_der: Vec<u8>,
        request: Request<Incoming>,
    ) -> Reply {
        if request.method() != Method::POST {
            let mut reply = error(
                StatusCode::METHOD_NOT_ALLOWED,
                ErrorCode::Malformed,
                "method not allowed",
            );
            reply
                .headers_mut()
                .insert(header::ALLOW, header::HeaderValue::from_static("POST"));
            return reply;
        }
        let request: RenewalRequest = match decode_protobuf(request).await {
            Ok(request) => request,
            Err(error) => return enrollment_error(error),
        };
        let canceled = Arc::new(AtomicBool::new(false));
        let _cancel_on_disconnect = CancelOnDrop(canceled.clone());
        let outcome = tokio::task::spawn_blocking(move || {
            let mut store = store.lock().map_err(|_| EnrollmentError {
                status: 500,
                code: ErrorCode::Internal,
                detail: "internal controller error",
                retryable: true,
            })?;
            enrollment::renew(&mut store, &self.authority, &peer_der, request, &canceled)
        })
        .await;
        match outcome {
            Ok(Ok(response)) => protobuf(StatusCode::OK, response),
            Ok(Err(problem)) => enrollment_error(problem),
            Err(_) => internal(),
        }
    }
}

async fn decode_protobuf<M: Message + Default>(
    request: Request<Incoming>,
) -> Result<M, EnrollmentError> {
    let failure = |status, code, detail| EnrollmentError {
        status,
        code,
        detail,
        retryable: false,
    };
    let mut headers = request.headers().get_all(header::CONTENT_TYPE).iter();
    let content_type = headers
        .next()
        .and_then(|header| header.to_str().ok())
        .and_then(|media| media.parse::<mime::Mime>().ok());
    if headers.next().is_some()
        || !content_type
            .is_some_and(|value| matches!(value.essence_str(), PROTOBUF | "application/protobuf"))
    {
        return Err(failure(
            415,
            ErrorCode::Malformed,
            "Content-Type must be application/x-protobuf",
        ));
    }
    let body = match Limited::new(request.into_body(), MAX_BODY).collect().await {
        Ok(body) => body.to_bytes(),
        Err(error) if error.is::<LengthLimitError>() => {
            return Err(failure(
                413,
                ErrorCode::ResourceExhausted,
                "request body exceeds limit",
            ));
        }
        Err(_) => {
            return Err(failure(
                400,
                ErrorCode::Malformed,
                "could not read request body",
            ));
        }
    };
    M::decode(body).map_err(|_| failure(400, ErrorCode::Malformed, "malformed protobuf request"))
}

fn enrollment_error(error: EnrollmentError) -> Reply {
    protobuf(
        StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        ProtocolError {
            code: error.code as i32,
            detail: error.detail.to_owned(),
            retryable: error.retryable,
        },
    )
}

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn protobuf(status: StatusCode, message: impl Message) -> Reply {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, PROTOBUF)
        .body(Full::new(Bytes::from(message.encode_to_vec())))
        .expect("static enrollment response")
}

fn error(status: StatusCode, code: ErrorCode, detail: &'static str) -> Reply {
    protobuf(
        status,
        ProtocolError {
            code: code as i32,
            detail: detail.into(),
            retryable: status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS,
        },
    )
}

fn internal() -> Reply {
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        ErrorCode::Internal,
        "internal controller error",
    )
}

pub(crate) fn renewal_unauthenticated() -> Reply {
    error(
        StatusCode::UNAUTHORIZED,
        ErrorCode::Unauthenticated,
        "authentication failed",
    )
}

#[derive(Default)]
struct RateLimit {
    sources: HashMap<IpAddr, (f64, Instant)>,
}

impl RateLimit {
    fn allow(&mut self, peer: IpAddr, now: Instant) -> bool {
        const MAX_SOURCES: usize = 4096;
        const TTL: Duration = Duration::from_secs(600);
        let peer = peer.to_canonical();
        if peer.is_unspecified() || peer.is_multicast() {
            return false;
        }
        if !self.sources.contains_key(&peer) && self.sources.len() >= MAX_SOURCES {
            self.sources
                .retain(|_, (_, last)| now.saturating_duration_since(*last) <= TTL);
            if self.sources.len() >= MAX_SOURCES {
                return false;
            }
        }
        let (tokens, last) = self.sources.entry(peer).or_insert((10.0, now));
        *tokens = (*tokens + now.saturating_duration_since(*last).as_secs_f64()).min(10.0);
        *last = now.max(*last);
        if *tokens < 1.0 {
            return false;
        }
        *tokens -= 1.0;
        true
    }
}

pub(super) async fn issue_token(
    store: Arc<Mutex<Store>>,
    principal: laneway_protocol::Id,
    request: Request<Incoming>,
    request_id: &str,
) -> Reply {
    let failure = |status, code, detail| {
        json(
            status,
            &serde_json::json!({
                "code": code,
                "detail": detail,
                "retryable": StatusCode::is_server_error(&status),
                "request_id": request_id,
            }),
        )
    };
    if request.method() != Method::POST {
        let mut reply = failure(
            StatusCode::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
        );
        reply
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("POST"));
        return reply;
    }
    let mut headers = request.headers().get_all(header::CONTENT_TYPE).iter();
    let content_type = headers
        .next()
        .and_then(|header| header.to_str().ok())
        .and_then(|media| media.parse::<mime::Mime>().ok());
    if headers.next().is_some()
        || !content_type.is_some_and(|value| value.essence_str() == "application/json")
    {
        return failure(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "ERROR_CODE_MALFORMED",
            "Content-Type must be application/json",
        );
    }
    let body = match Limited::new(request.into_body(), MAX_BODY).collect().await {
        Ok(body) => body.to_bytes(),
        Err(error) if error.is::<LengthLimitError>() => {
            return failure(
                StatusCode::PAYLOAD_TOO_LARGE,
                "ERROR_CODE_RESOURCE_EXHAUSTED",
                "request body exceeds limit",
            );
        }
        Err(_) => {
            return failure(
                StatusCode::BAD_REQUEST,
                "ERROR_CODE_MALFORMED",
                "could not read request body",
            );
        }
    };
    let issue: enrollment::IssueRequest = match serde_json::from_slice(&body) {
        Ok(issue) => issue,
        Err(_) => {
            return failure(
                StatusCode::BAD_REQUEST,
                "ERROR_CODE_MALFORMED",
                "malformed JSON request",
            );
        }
    };
    let canceled = Arc::new(AtomicBool::new(false));
    let _cancel_on_disconnect = CancelOnDrop(canceled.clone());
    let outcome = tokio::task::spawn_blocking(move || {
        let mut store = store.lock().map_err(|_| EnrollmentError {
            status: 500,
            code: ErrorCode::Internal,
            detail: "internal controller error",
            retryable: true,
        })?;
        enrollment::issue_token(&mut store, principal, issue, &canceled)
    })
    .await;
    match outcome {
        Ok(Ok(token)) => json(StatusCode::CREATED, &token),
        Ok(Err(error)) => failure(
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            error.code.as_str_name(),
            error.detail,
        ),
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERROR_CODE_INTERNAL",
            "internal controller error",
        ),
    }
}

fn json(status: StatusCode, value: &impl serde::Serialize) -> Reply {
    let (status, body) = match serde_json::to_vec(value) {
        Ok(body) => (status, body),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR,
            br#"{"code":"ERROR_CODE_INTERNAL","detail":"internal controller error","retryable":true}"#.to_vec()),
    };
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("static enrollment response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_limiter_tracks_canonical_peer_and_refills() {
        let mut limit = RateLimit::default();
        let ipv4 = "127.0.0.6".parse().unwrap();
        let mapped = "::ffff:127.0.0.6".parse().unwrap();
        let another = "127.0.0.7".parse().unwrap();
        let now = Instant::now();
        for _ in 0..10 {
            assert!(limit.allow(ipv4, now));
        }
        assert!(!limit.allow(mapped, now));
        assert!(!limit.allow(mapped, now + Duration::from_millis(999)));
        assert!(limit.allow(mapped, now + Duration::from_secs(1)));
        assert!(limit.allow(another, now));
    }
}
