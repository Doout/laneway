use super::{Reply, State, response};
use http_body_util::BodyExt;
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{SessionStore, enrollment::EnrollError};
use laneway_protocol::v1::{EnrollmentRequest, ErrorCode as Code, ProtocolError};
use prost::Message;
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Instant};
use zeroize::Zeroizing;

#[derive(Default)]
pub(super) struct Limiter(HashMap<IpAddr, (Instant, f64)>);
impl Limiter {
    fn admit(&mut self, ip: IpAddr, now: Instant) -> bool {
        let ip = ip.to_canonical();
        if ip.is_unspecified() || ip.is_multicast() {
            return false;
        }
        if self.0.len() >= 4096 && !self.0.contains_key(&ip) {
            self.0
                .retain(|_, (last, _)| now.duration_since(*last).as_secs_f64() <= 600.0);
            if self.0.len() >= 4096 {
                return false;
            }
        }
        let (last, tokens) = self.0.entry(ip).or_insert((now, 10.0));
        *tokens = (*tokens + now.saturating_duration_since(*last).as_secs_f64()).min(10.0);
        *last = now;
        if *tokens < 1.0 {
            return false;
        }
        *tokens -= 1.0;
        true
    }
}

fn proto(status: S, id: &str, body: impl Message) -> Reply {
    let mut r = response(status, id, body.encode_to_vec(), false);
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/x-protobuf".parse().unwrap(),
    );
    r
}
fn error(status: S, code: Code, detail: &str, retryable: bool, id: &str) -> Reply {
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
fn failure(err: anyhow::Error, id: &str) -> Reply {
    let Some(e) = err.downcast_ref::<EnrollError>() else {
        return internal(id);
    };
    let (status, code) = match e {
        EnrollError::Invalid | EnrollError::Expired => (S::UNAUTHORIZED, Code::Unauthenticated),
        EnrollError::Name | EnrollError::Class | EnrollError::Network => {
            (S::FORBIDDEN, Code::PermissionDenied)
        }
        EnrollError::Used | EnrollError::Conflict => (S::CONFLICT, Code::PermissionDenied),
        EnrollError::Malformed(_) => (S::BAD_REQUEST, Code::Malformed),
        EnrollError::PoolExhausted => return internal(id),
    };
    error(status, code, &e.to_string(), false, id)
}
fn internal(id: &str) -> Reply {
    error(
        S::INTERNAL_SERVER_ERROR,
        Code::Internal,
        "internal controller error",
        true,
        id,
    )
}

pub(super) async fn handle(req: Request<Incoming>, state: State, id: &str, ip: IpAddr) -> Reply {
    if req.method() != Method::POST {
        let mut reply = error(
            S::METHOD_NOT_ALLOWED,
            Code::Malformed,
            "method not allowed",
            false,
            id,
        );
        reply
            .headers_mut()
            .insert(header::ALLOW, "POST".parse().unwrap());
        return reply;
    }
    let admitted = match state.enrollments.lock() {
        Ok(mut l) => l.admit(ip, Instant::now()),
        Err(_) => return internal(id),
    };
    if !admitted {
        let mut reply = error(
            S::TOO_MANY_REQUESTS,
            Code::ResourceExhausted,
            "enrollment rate limit exceeded; retry later",
            true,
            id,
        );
        reply.headers_mut().insert(header::RETRY_AFTER, 1.into());
        return reply;
    }
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
        return error(
            S::UNSUPPORTED_MEDIA_TYPE,
            Code::Malformed,
            "Content-Type must be application/x-protobuf",
            false,
            id,
        );
    }
    let mut data = Zeroizing::new(Vec::new());
    let mut body = req.into_body();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            return error(
                S::BAD_REQUEST,
                Code::Malformed,
                "could not read request body",
                false,
                id,
            );
        };
        if let Ok(bytes) = frame.into_data() {
            if bytes.len() > 131072 - data.len() {
                return error(
                    S::PAYLOAD_TOO_LARGE,
                    Code::ResourceExhausted,
                    "request body exceeds limit",
                    false,
                    id,
                );
            }
            data.extend_from_slice(&bytes);
        }
    }
    let Ok(permit) = state.queries.try_acquire_owned() else {
        return error(
            S::SERVICE_UNAVAILABLE,
            Code::ResourceExhausted,
            "controller busy",
            true,
            id,
        );
    };
    let Some(issuer) = state.issuer else {
        return internal(id);
    };
    // Dropping this request must also cancel an uncommitted enrollment even
    // if its blocking SQLite task is still waiting for the write lock.
    let (cancel, _request_alive) = tokio::sync::oneshot::channel::<()>();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let req = EnrollmentRequest::decode(data.as_slice())
            .map_err(|_| EnrollError::Malformed("malformed protobuf request"))?;
        SessionStore::open(&state.database)?
            .redeem_enrollment(req, Arc::as_ref(&issuer), || cancel.is_closed())
    })
    .await
    {
        Ok(Ok(reply)) => proto(S::CREATED, id, reply),
        Ok(Err(e)) => failure(e, id),
        Err(_) => internal(id),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enrollment_burst_and_refill_are_source_scoped() {
        let mut l = Limiter::default();
        let now = Instant::now();
        let ip = "127.0.0.1".parse().unwrap();
        for _ in 0..10 {
            assert!(l.admit(ip, now));
        }
        assert!(!l.admit(ip, now));
        assert!(l.admit("127.0.0.2".parse().unwrap(), now));
        assert!(l.admit(ip, now + std::time::Duration::from_secs(1)));
    }
}
