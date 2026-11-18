use super::{Reply, State};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{SessionStore, enrollment::EnrollError};
use laneway_protocol::v1::{EnrollmentRequest, ErrorCode as Code};
use prost::Message;
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Instant};

#[derive(Default)]
pub(super) struct Limiter(HashMap<IpAddr, (Instant, f64)>);
impl Limiter {
    pub(super) fn admit(&mut self, ip: IpAddr, now: Instant) -> bool {
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

use super::node_proto::{error, failure, internal, proto, read_body};

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
    let data = match read_body(req, id).await {
        Ok(v) => v,
        Err(reply) => return reply,
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
