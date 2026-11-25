use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    Method, Request, Response, StatusCode,
    header::{
        CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, RETRY_AFTER, X_CONTENT_TYPE_OPTIONS,
    },
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use ipnet::IpNet;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Sleep, sleep, timeout},
};

use crate::controller::Client;

const METADATA_PATH: &str = "/.well-known/laneway/bootstrap.json";
const BUNDLE_PREFIX: &str = "/.well-known/laneway/bootstrap/";
const BUNDLE_ID_LENGTH: usize = 43;
const TRUST_LIFETIME: Duration = Duration::from_secs(3600);
const MAX_SOURCE_ENTRIES: usize = 4096;
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const UNAVAILABLE: &str = "bootstrap metadata temporarily unavailable\n";
const NOT_FOUND: &str = "404 page not found\n";

type PublicResponse = Response<Full<Bytes>>;

pub(crate) struct PublicHttp {
    controller: Option<Arc<Client>>,
    limiter: Mutex<RateLimiter>,
}

impl PublicHttp {
    pub(crate) fn new(controller: Option<Arc<Client>>) -> Self {
        Self {
            controller,
            limiter: Mutex::new(RateLimiter::default()),
        }
    }

    pub(crate) fn mark_authenticated(&self, peer: SocketAddr) {
        self.limiter
            .lock()
            .expect("public rate limiter lock")
            .mark_authenticated(peer.ip(), Instant::now());
    }

    pub(crate) async fn serve(
        &self,
        stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        peer: SocketAddr,
    ) -> Result<()> {
        http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(Duration::from_secs(5))
            .max_buf_size(16 << 10)
            .serve_connection(
                TokioIo::new(WriteDeadline {
                    stream,
                    deadline: None,
                }),
                service_fn(|request| async move {
                    Ok::<_, std::convert::Infallible>(self.handle(peer, request).await)
                }),
            )
            .await
            .context("serve public relay HTTPS")
    }

    async fn handle<B>(&self, peer: SocketAddr, request: Request<B>) -> PublicResponse {
        if !self
            .limiter
            .lock()
            .expect("public rate limiter lock")
            .allow(peer.ip(), Instant::now())
        {
            let mut response = error(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded\n");
            response.headers_mut().insert(RETRY_AFTER, 1.into());
            return response;
        }

        let Some(route) = Route::from_request(&request) else {
            return error(StatusCode::NOT_FOUND, NOT_FOUND);
        };
        let Some(controller) = &self.controller else {
            return error(StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE);
        };
        let (path, limit, content_type) = route.upstream();
        match timeout(
            Duration::from_secs(10),
            controller.bootstrap_get(&path, limit),
        )
        .await
        {
            Ok(Ok(data)) => response(StatusCode::OK, content_type, data),
            _ if matches!(route, Route::Bundle(_)) => error(StatusCode::NOT_FOUND, NOT_FOUND),
            _ => error(StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE),
        }
    }
}

// Hyper bounds the request headers and discards unneeded bodies. Bound
// socket writes as well so a client that stops reading releases its slot.
struct WriteDeadline<T> {
    stream: T,
    deadline: Option<Pin<Box<Sleep>>>,
}

impl<T: AsyncRead + Unpin> AsyncRead for WriteDeadline<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for WriteDeadline<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .poll_pending(cx, false, |stream, cx| stream.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_pending(cx, true, |stream, cx| stream.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_pending(cx, true, |stream, cx| stream.poll_shutdown(cx))
    }
}

impl<T: Unpin> WriteDeadline<T> {
    fn poll_pending<R>(
        &mut self,
        cx: &mut TaskContext<'_>,
        finish: bool,
        operation: impl FnOnce(Pin<&mut T>, &mut TaskContext<'_>) -> Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>> {
        if let Some(deadline) = self.deadline.as_mut()
            && deadline.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "write public relay HTTP response",
            )));
        }
        let result = operation(Pin::new(&mut self.stream), cx);
        if result.is_ready() {
            if finish {
                self.deadline = None;
            }
            return result;
        }
        if self.deadline.is_none() {
            let mut deadline = Box::pin(sleep(WRITE_TIMEOUT));
            let _ = deadline.as_mut().poll(cx);
            self.deadline = Some(deadline);
        }
        Poll::Pending
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Route {
    Metadata,
    Bundle(String),
}

impl Route {
    fn from_request<B>(request: &Request<B>) -> Option<Self> {
        if request.method() != Method::GET || request.uri().query().is_some_and(|q| !q.is_empty()) {
            return None;
        }
        // Go's net/http supplies a decoded URL.Path to the bootstrap handler.
        let path = percent_encoding::percent_decode_str(request.uri().path())
            .decode_utf8()
            .ok()?;
        if path == METADATA_PATH {
            return Some(Self::Metadata);
        }
        let id = path.strip_prefix(BUNDLE_PREFIX)?;
        if id.len() == BUNDLE_ID_LENGTH
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Some(Self::Bundle(id.to_owned()));
        }
        None
    }

    fn upstream(&self) -> (std::borrow::Cow<'_, str>, usize, &'static str) {
        match self {
            Self::Metadata => (METADATA_PATH.into(), 256 << 10, "application/json"),
            Self::Bundle(id) => (
                format!("/v1/bootstrap-bundles/{id}").into(),
                96 << 10,
                "text/x-shellscript; charset=utf-8",
            ),
        }
    }
}

fn response(status: StatusCode, content_type: &'static str, body: Bytes) -> PublicResponse {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .header(CACHE_CONTROL, "no-store")
        .header(X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(
            CONTENT_SECURITY_POLICY,
            "default-src 'none'; frame-ancestors 'none'",
        )
        .body(Full::new(body))
        .expect("valid public response headers")
}

fn error(status: StatusCode, body: &'static str) -> PublicResponse {
    response(
        status,
        "text/plain; charset=utf-8",
        Bytes::from_static(body.as_bytes()),
    )
}

#[derive(Default)]
struct RateLimiter {
    global: Option<Bucket>,
    ranges: HashMap<IpNet, Bucket>,
    trusted: HashMap<IpAddr, TrustedSource>,
}

struct TrustedSource {
    expires: Instant,
    bucket: Option<Bucket>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    fn mark_authenticated(&mut self, ip: IpAddr, now: Instant) {
        let Some(ip) = public_source(ip) else {
            return;
        };
        self.prune(now);
        if let Some(source) = self.trusted.get_mut(&ip) {
            source.expires = now + TRUST_LIFETIME;
            return;
        }
        if self.trusted.len() >= MAX_SOURCE_ENTRIES
            && let Some((&oldest, _)) = self.trusted.iter().min_by_key(|(_, state)| state.expires)
        {
            self.trusted.remove(&oldest);
        }
        self.trusted.insert(
            ip,
            TrustedSource {
                expires: now + TRUST_LIFETIME,
                bucket: None,
            },
        );
    }

    fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        let Some(ip) = public_source(ip) else {
            return false;
        };
        self.prune(now);
        if !self
            .global
            .get_or_insert_with(|| Bucket::new(400.0, now))
            .take(now, 200.0, 400.0)
        {
            return false;
        }
        if let Some(source) = self.trusted.get_mut(&ip) {
            return source
                .bucket
                .get_or_insert_with(|| Bucket::new(100.0, now))
                .take(now, 20.0, 100.0);
        }

        let prefix = IpNet::new(ip, if ip.is_ipv4() { 24 } else { 64 })
            .expect("valid IP prefix length")
            .trunc();
        if !self.ranges.contains_key(&prefix)
            && self.ranges.len() >= MAX_SOURCE_ENTRIES
            && let Some((&oldest, _)) = self.ranges.iter().min_by_key(|(_, bucket)| bucket.last)
        {
            self.ranges.remove(&oldest);
        }
        self.ranges
            .entry(prefix)
            .or_insert_with(|| Bucket::new(10.0, now))
            .take(now, 2.0, 10.0)
    }

    fn prune(&mut self, now: Instant) {
        self.trusted.retain(|_, source| source.expires > now);
    }
}

impl Bucket {
    fn new(tokens: f64, last: Instant) -> Self {
        Self { tokens, last }
    }

    fn take(&mut self, now: Instant, rate: f64, burst: f64) -> bool {
        if now > self.last {
            let elapsed = now.duration_since(self.last).as_secs_f64();
            self.tokens = (self.tokens + elapsed * rate).min(burst);
            self.last = now;
        }
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

fn public_source(ip: IpAddr) -> Option<IpAddr> {
    let ip = ip.to_canonical();
    if ip.is_unspecified() || ip.is_multicast() {
        return None;
    }
    Some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "Ab_-EfghIjklMNOPQRSTUVWXYZ0123456789abcdefg";

    #[test]
    fn accepts_only_bootstrap_routes() {
        assert_eq!(ID.len(), BUNDLE_ID_LENGTH);
        let metadata = Request::get(METADATA_PATH).body(()).unwrap();
        assert_eq!(Route::from_request(&metadata), Some(Route::Metadata));
        let bundle = Request::get(format!("{BUNDLE_PREFIX}{ID}"))
            .body(())
            .unwrap();
        let route = Route::from_request(&bundle).unwrap();
        assert_eq!(route, Route::Bundle(ID.to_owned()));
        assert_eq!(
            route.upstream(),
            (
                format!("/v1/bootstrap-bundles/{ID}").into(),
                96 << 10,
                "text/x-shellscript; charset=utf-8"
            ),
        );
        for (method, path) in [
            (Method::POST, METADATA_PATH.to_owned()),
            (Method::HEAD, METADATA_PATH.to_owned()),
            (Method::GET, format!("{METADATA_PATH}?hint=foo")),
            (Method::GET, format!("{BUNDLE_PREFIX}{ID}/more")),
            (Method::GET, format!("{BUNDLE_PREFIX}.{}", &ID[1..])),
            (Method::GET, format!("{BUNDLE_PREFIX}short")),
            (Method::GET, format!("{BUNDLE_PREFIX}{ID}?secret=foo")),
            (Method::GET, format!("/v1/bootstrap-bundles/{ID}")),
            (Method::GET, "/v1/admin/bootstrap-bundles".to_owned()),
            (Method::GET, "/healthz".to_owned()),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .body(())
                .unwrap();
            assert_eq!(Route::from_request(&request), None);
        }
    }

    #[tokio::test]
    async fn unavailable_controller_and_rate_limit_keep_security_headers() {
        let http = PublicHttp::new(None);
        let peer = "203.0.113.7:50000".parse().unwrap();
        for _ in 0..10 {
            let request = Request::get(METADATA_PATH).body(()).unwrap();
            let response = http.handle(peer, request).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[X_CONTENT_TYPE_OPTIONS], "nosniff");
            assert_eq!(
                response.headers()[CONTENT_SECURITY_POLICY],
                "default-src 'none'; frame-ancestors 'none'"
            );
        }
        let request = Request::get("/v1/admin/bootstrap-bundles")
            .header("x-forwarded-for", "192.0.2.5")
            .body(())
            .unwrap();
        let response = http.handle(peer, request).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[RETRY_AFTER], "1");
    }

    #[tokio::test]
    async fn serves_http1_and_rejects_administrator_requests() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

        let (mut client, server) = duplex(4096);
        let http = PublicHttp::new(None);
        let serve =
            tokio::spawn(
                async move { http.serve(server, "192.0.2.1:1234".parse().unwrap()).await },
            );
        client
            .write_all(b"GET /v1/admin/bootstrap-bundles HTTP/1.1\r\nHost: relay.example.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut body = String::new();
        timeout(Duration::from_secs(2), client.read_to_string(&mut body))
            .await
            .unwrap()
            .unwrap();
        serve.await.unwrap().unwrap();
        assert!(body.starts_with("HTTP/1.1 404 Not Found\r\n"), "{body}");
        assert!(body.contains("cache-control: no-store\r\n"), "{body}");
        assert!(body.ends_with(NOT_FOUND), "{body}");
    }

    #[tokio::test]
    async fn expires_a_stalled_socket_write() {
        use tokio::io::{AsyncWriteExt, duplex};

        let (_client, mut stream) = duplex(1);
        stream.write_all(b"a").await.unwrap();
        let mut blocked = WriteDeadline {
            stream,
            deadline: Some(Box::pin(sleep(Duration::ZERO))),
        };
        let error = timeout(Duration::from_secs(2), blocked.write_all(b"b"))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn aggregates_source_ranges_and_expires_tls_authenticated_promotion() {
        let now = Instant::now();
        let ip = "203.0.113.1".parse().unwrap();
        let same_range = "::ffff:203.0.113.2".parse().unwrap();
        let v6 = "2001:db8::1".parse().unwrap();
        let same_v6_range = "2001:db8::2".parse().unwrap();
        let mut limiter = RateLimiter::default();
        for _ in 0..10 {
            assert!(limiter.allow(ip, now));
            assert!(limiter.allow(v6, now));
        }
        assert!(!limiter.allow(same_range, now));
        assert!(!limiter.allow(same_v6_range, now));
        limiter.mark_authenticated(ip, now);
        for _ in 0..100 {
            assert!(limiter.allow(ip, now));
        }
        assert!(!limiter.allow(ip, now));
        assert!(!limiter.allow(same_range, now));
        assert!(limiter.allow(ip, now + TRUST_LIFETIME));
        assert!(limiter.trusted.is_empty());
    }

    #[test]
    fn globally_limits_distributed_requests() {
        let now = Instant::now();
        let mut limiter = RateLimiter::default();
        for n in 0..400 {
            assert!(limiter.allow(IpAddr::from([192, (n / 256) as u8, n as u8, 1]), now));
        }
        assert!(!limiter.allow(IpAddr::from([192, 2, 100, 1]), now));
        assert!(limiter.allow(IpAddr::from([192, 2, 100, 1]), now + Duration::from_secs(1)));
    }
}
