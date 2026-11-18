use std::{
    collections::HashMap,
    convert::Infallible,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{HeaderMap, Method, Request, Response, StatusCode as S, body::Incoming, header};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::ServerName;
use tokio::{net::TcpStream, sync::Semaphore, time::timeout};
use tokio_rustls::server::TlsStream;

use crate::{config::PublicHttpsConfig, controller::Client, tls};

const HTTP_ALPN: &[u8] = b"http/1.1";
const DISCOVERY: &str = "/.well-known/laneway/bootstrap.json";
const PUBLIC_BUNDLE: &str = "/.well-known/laneway/bootstrap/";
const PRIVATE_BUNDLE: &str = "/v1/bootstrap-bundles/";
const CLIENT_IP: &str = "x-laneway-public-client-ip";
const PROXY_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CONSOLE_REQUEST: usize = 256 * 1024;
const MAX_CONSOLE_RESPONSE: usize = 8 * 1024 * 1024;
type Reply = Response<Full<Bytes>>;

pub(crate) struct PublicHttps {
    tls: Arc<rustls::ServerConfig>,
    server_name: String,
    slots: Semaphore,
    controller: Arc<Client>,
    bootstrap: Mutex<BootstrapLimit>,
}

impl PublicHttps {
    pub(crate) fn new(config: &PublicHttpsConfig, controller: Arc<Client>) -> Result<Self> {
        let cert = tls::load_certificates(&config.certificate)?;
        let leaf = rustls::server::ParsedCertificate::try_from(&cert[0])?;
        rustls::client::verify_server_name(
            &leaf,
            &ServerName::try_from(config.server_name.as_str())?,
        )?;
        ensure!(
            laneway_protocol::identity_from_certificate_der(cert[0].as_ref()).is_err(),
            "public HTTPS must not use a Laneway workload credential"
        );
        let mut server =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(cert, tls::load_private_key(&config.private_key)?)
                .context("load public HTTPS certificate and key")?;
        server.alpn_protocols = vec![HTTP_ALPN.to_vec()];
        server.send_tls13_tickets = 0;
        Ok(Self {
            tls: Arc::new(server),
            server_name: config.server_name.clone(),
            slots: Semaphore::new(32),
            controller,
            bootstrap: Mutex::new(BootstrapLimit::default()),
        })
    }

    pub(crate) fn config_for_hello(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Result<Arc<rustls::ServerConfig>> {
        ensure!(
            hello.server_name() == Some(self.server_name.as_str()),
            "unexpected public TLS server name"
        );
        ensure!(
            hello
                .alpn()
                .is_none_or(|mut values| values.any(|p| p == HTTP_ALPN)),
            "unsupported public TLS protocol"
        );
        Ok(Arc::clone(&self.tls))
    }

    pub(crate) fn admit(&self) -> Result<tokio::sync::SemaphorePermit<'_>> {
        self.slots
            .try_acquire()
            .context("public HTTPS connection limit")
    }

    pub(crate) async fn serve(&self, connection: TlsStream<TcpStream>, peer: IpAddr) -> Result<()> {
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(Duration::from_secs(5))
            .max_headers(64)
            .max_buf_size(32 * 1024)
            .keep_alive(false);
        timeout(
            PROXY_TIMEOUT,
            builder.serve_connection(
                TokioIo::new(connection),
                hyper::service::service_fn(|request| async move {
                    Ok::<_, Infallible>(self.handle(request, peer).await)
                }),
            ),
        )
        .await
        .context("public HTTPS connection timed out")??;
        Ok(())
    }

    async fn handle(&self, request: Request<Incoming>, peer: IpAddr) -> Reply {
        let head = request.method() == Method::HEAD;
        let uri = request.uri();
        if uri.scheme().is_some()
            || uri.authority().is_some()
            || !public_host(request.headers(), &self.server_name)
        {
            return plain(S::MISDIRECTED_REQUEST, "unexpected HTTPS authority\n", head);
        }
        let Some(route) = route(uri.path()) else {
            return plain(S::NOT_FOUND, "404 page not found\n", head);
        };
        let peer = peer.to_canonical();
        if !matches!(route, Route::Console) {
            let mut response = if request.method() != Method::GET
                || uri.query().is_some_and(|q| !q.is_empty())
                || forbidden_credential(request.headers(), false)
            {
                plain(S::NOT_FOUND, "404 page not found\n", head)
            } else if !self
                .bootstrap
                .lock()
                .is_ok_and(|mut limit| limit.allow(peer, Instant::now()))
            {
                let mut reply = plain(S::TOO_MANY_REQUESTS, "rate limit exceeded\n", head);
                reply
                    .headers_mut()
                    .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
                reply
            } else {
                self.fetch_bootstrap(route).await
            };
            response.headers_mut().insert(
                header::CONTENT_SECURITY_POLICY,
                header::HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
            );
            return response;
        }

        let oauth_token = matches!(uri.path(), "/oauth/token" | "/oauth/revoke")
            && request.method() == Method::POST;
        if forbidden_credential(request.headers(), oauth_token)
            || !connection_headers_are_safe(request.headers())
        {
            return plain(
                S::UNAUTHORIZED,
                "credential not accepted on this endpoint\n",
                head,
            );
        }
        if !matches!(
            *request.method(),
            Method::GET
                | Method::HEAD
                | Method::POST
                | Method::PUT
                | Method::PATCH
                | Method::DELETE
                | Method::OPTIONS
        ) {
            return plain(S::METHOD_NOT_ALLOWED, "method not allowed\n", head);
        }
        match self.forward(request, peer).await {
            Ok(reply) => reply,
            Err(error) => plain(error, "console request could not be completed\n", head),
        }
    }

    async fn fetch_bootstrap(&self, route: Route<'_>) -> Reply {
        let (path, media, max, failure) = match route {
            Route::Discovery => (
                DISCOVERY.to_owned(),
                "application/json",
                256 * 1024,
                (
                    S::SERVICE_UNAVAILABLE,
                    "bootstrap metadata temporarily unavailable\n",
                ),
            ),
            Route::Bundle(id) => (
                format!("{PRIVATE_BUNDLE}{id}"),
                "text/x-shellscript; charset=utf-8",
                96 * 1024,
                (S::NOT_FOUND, "404 page not found\n"),
            ),
            Route::Console => unreachable!(),
        };
        let result = async {
            let upstream = self
                .controller
                .request(Method::GET, &path, None)
                .header(header::ACCEPT, media)
                .send()
                .await?;
            ensure!(
                upstream.status() == S::OK,
                "bootstrap upstream returned non-success"
            );
            bounded_response(upstream, max).await
        }
        .await;
        match result {
            Ok(body) if !body.is_empty() => reply(S::OK, media, body),
            _ => plain(failure.0, failure.1, false),
        }
    }

    async fn forward(&self, request: Request<Incoming>, peer: IpAddr) -> Result<Reply, S> {
        let (mut parts, body) = request.into_parts();
        let body = Limited::new(body, MAX_CONSOLE_REQUEST)
            .collect()
            .await
            .map_err(|_| S::PAYLOAD_TOO_LARGE)?
            .to_bytes();
        remove_transport_headers(&mut parts.headers);
        parts.headers.remove(header::CONTENT_LENGTH);
        let path = parts.uri.path();
        if path.starts_with("/v1/admin/")
            || path.starts_with("/oauth/")
            || matches!(
                path,
                "/applications/new" | "/v1/application-registrations/exchange"
            )
        {
            parts.headers.insert(
                CLIENT_IP,
                peer.to_string().parse().map_err(|_| S::BAD_REQUEST)?,
            );
        }
        let head = parts.method == Method::HEAD;
        let upstream = self
            .controller
            .request(parts.method, parts.uri.path(), parts.uri.query())
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map_err(|_| S::BAD_GATEWAY)?;
        let status = upstream.status();
        let mut headers = upstream.headers().clone();
        remove_transport_headers(&mut headers);
        let body = if head || matches!(status, S::NO_CONTENT | S::NOT_MODIFIED) {
            Bytes::new()
        } else {
            headers.remove(header::CONTENT_LENGTH);
            bounded_response(upstream, MAX_CONSOLE_RESPONSE)
                .await
                .map_err(|_| S::BAD_GATEWAY)?
        };
        let mut reply = Response::new(Full::new(body));
        *reply.status_mut() = status;
        *reply.headers_mut() = headers;
        Ok(reply)
    }
}

async fn bounded_response(mut upstream: reqwest::Response, limit: usize) -> Result<Bytes> {
    ensure!(
        upstream.content_length().is_none_or(|n| n <= limit as u64),
        "controller response exceeds limit"
    );
    let mut buffer = BytesMut::new();
    while let Some(chunk) = upstream.chunk().await? {
        ensure!(
            chunk.len() <= limit - buffer.len(),
            "controller response exceeds limit"
        );
        buffer.extend_from_slice(&chunk);
    }
    Ok(buffer.freeze())
}

enum Route<'a> {
    Discovery,
    Bundle(&'a str),
    Console,
}

fn route(path: &str) -> Option<Route<'_>> {
    if !path.starts_with('/')
        || path.contains(['%', '\\'])
        || path.contains("//")
        || path.split('/').any(|p| matches!(p, "." | ".."))
    {
        return None;
    }
    if path == DISCOVERY {
        return Some(Route::Discovery);
    }
    if let Some(id) = path.strip_prefix(PUBLIC_BUNDLE) {
        return (id.len() == 43
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')))
        .then_some(Route::Bundle(id));
    }
    if path == "/v1" || path.starts_with("/v1/") {
        return (path.starts_with("/v1/admin/")
            || path == "/v1/application-registrations/exchange")
            .then_some(Route::Console);
    }
    (!path.starts_with("/.well-known/") && path != "/.well-known").then_some(Route::Console)
}

fn public_host(headers: &HeaderMap, name: &str) -> bool {
    let mut hosts = headers.get_all(header::HOST).iter();
    hosts
        .next()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|host| {
            host.eq_ignore_ascii_case(name)
                || host.rsplit_once(':').is_some_and(|(host, port)| {
                    host.eq_ignore_ascii_case(name) && port.parse::<u16>().is_ok_and(|p| p != 0)
                })
        })
        && hosts.next().is_none()
}

fn forbidden_credential(headers: &HeaderMap, oauth: bool) -> bool {
    let mut auth = headers.get_all(header::AUTHORIZATION).iter();
    headers.contains_key(header::PROXY_AUTHORIZATION)
        || auth
            .next()
            .is_some_and(|v| !oauth || !v.as_bytes().starts_with(b"Basic "))
        || auth.next().is_some()
}

fn connection_headers_are_safe(headers: &HeaderMap) -> bool {
    headers.get_all(header::CONNECTION).iter().all(|value| {
        value.to_str().is_ok_and(|tokens| {
            tokens.split(',').all(|t| {
                t.trim().eq_ignore_ascii_case("close")
                    || t.trim().eq_ignore_ascii_case("keep-alive")
            })
        })
    }) && !headers.contains_key(header::UPGRADE)
}

fn remove_transport_headers(headers: &mut HeaderMap) {
    let connection: Vec<_> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|v| header::HeaderName::from_bytes(v.trim().as_bytes()).ok())
        .collect();
    for name in connection {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        CLIENT_IP,
    ] {
        headers.remove(name);
    }
}

fn reply(status: S, media: &'static str, body: Bytes) -> Reply {
    let mut reply = Response::new(Full::new(body));
    *reply.status_mut() = status;
    for (name, value) in [
        ("content-type", media),
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
    ] {
        reply
            .headers_mut()
            .insert(name, header::HeaderValue::from_static(value));
    }
    reply
}

fn plain(status: S, message: &'static str, head: bool) -> Reply {
    reply(
        status,
        "text/plain; charset=utf-8",
        if head {
            Bytes::new()
        } else {
            Bytes::from_static(message.as_bytes())
        },
    )
}

#[derive(Default)]
struct BootstrapLimit {
    global: Option<Bucket>,
    ranges: HashMap<IpAddr, Bucket>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn take(&mut self, now: Instant, rate: f64, burst: f64) -> bool {
        self.tokens = (self.tokens + now.saturating_duration_since(self.last).as_secs_f64() * rate)
            .min(burst);
        self.last = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

impl BootstrapLimit {
    fn allow(&mut self, peer: IpAddr, now: Instant) -> bool {
        if !self
            .global
            .get_or_insert(Bucket {
                tokens: 400.0,
                last: now,
            })
            .take(now, 200.0, 400.0)
        {
            return false;
        }
        let range = match peer {
            IpAddr::V4(ip) => IpAddr::V4((u32::from(ip) & !255).into()),
            IpAddr::V6(ip) => IpAddr::V6((u128::from(ip) & !(u64::MAX as u128)).into()),
        };
        if self.ranges.len() >= 4096 && !self.ranges.contains_key(&range) {
            // Reclaim only inactive buckets. Churning source ranges can't
            // refill the allowance for an active source.
            self.ranges
                .retain(|_, b| now.saturating_duration_since(b.last) < Duration::from_secs(60));
            if self.ranges.len() >= 4096 {
                return false;
            }
        }
        self.ranges
            .entry(range)
            .or_insert(Bucket {
                tokens: 10.0,
                last: now,
            })
            .take(now, 2.0, 10.0)
    }
}
