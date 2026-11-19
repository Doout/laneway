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
use laneway_protocol::public_application;
use tokio::{net::TcpStream, sync::Semaphore, time::timeout};
use tokio_rustls::server::TlsStream;

use crate::{
    config::PublicHttpsConfig,
    controller::Client,
    public_tls::{PublicTls, Renewal},
};

const DISCOVERY: &str = "/.well-known/laneway/bootstrap.json";
const PUBLIC_BUNDLE: &str = "/.well-known/laneway/bootstrap/";
const PRIVATE_BUNDLE: &str = "/v1/bootstrap-bundles/";
const CLIENT_IP: &str = "x-laneway-public-client-ip";
const PROXY_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CONSOLE_REQUEST: usize = 256 * 1024;
const MAX_CONSOLE_RESPONSE: usize = 8 * 1024 * 1024;
type Reply = Response<Full<Bytes>>;

pub(crate) struct PublicHttps {
    pub(crate) tls: PublicTls,
    server_name: String,
    slots: Semaphore,
    controller: Arc<Client>,
    bootstrap: Mutex<BootstrapLimit>,
    platform: Option<reqwest::Client>,
    platform_limit: Mutex<BootstrapLimit>,
}

impl PublicHttps {
    pub(crate) fn new(
        config: &PublicHttpsConfig,
        controller: Arc<Client>,
    ) -> Result<(Self, Option<Renewal>)> {
        let (tls, renewal) = PublicTls::new(config)?;
        let platform = config
            .platform_socket
            .as_ref()
            .map(|socket| {
                reqwest::Client::builder()
                    .unix_socket(socket.clone())
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(8))
                    .build()
            })
            .transpose()?;
        Ok((
            Self {
                tls,
                server_name: config.server_name.clone(),
                slots: Semaphore::new(32),
                controller,
                bootstrap: Mutex::new(BootstrapLimit::default()),
                platform,
                platform_limit: Mutex::new(BootstrapLimit::default()),
            },
            renewal,
        ))
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

    async fn handle(&self, mut request: Request<Incoming>, peer: IpAddr) -> Reply {
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
        if let Some(platform) = &self.platform
            && matches!(
                uri.path(),
                "/" | "/tenants" | "/platform/sign-in" | "/platform/sign-out"
            )
        {
            if !self
                .platform_limit
                .lock()
                .is_ok_and(|mut limit| limit.allow(peer, Instant::now()))
            {
                return plain(S::TOO_MANY_REQUESTS, "rate limit exceeded\n", head);
            }
            return match self.forward_platform(platform, request).await {
                Ok(reply) => reply,
                Err(status) => plain(status, "Platform request could not be completed\n", head),
            };
        }
        if !matches!(route, Route::Console) {
            let mut response = if request.method() != Method::GET
                || uri.query().is_some_and(|q| !q.is_empty())
                || forbidden_credential(request.headers(), false, false)
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
        let app = public_application::route_allowed(request.method().as_str(), uri.path());
        if (self.platform.is_some()
            && request
                .headers()
                .get_all(header::AUTHORIZATION)
                .iter()
                .any(|value| {
                    value.to_str().ok().is_some_and(|value| {
                        value.split_once(' ').is_some_and(|(scheme, credential)| {
                            scheme.eq_ignore_ascii_case("basic")
                                && credential.trim_start().starts_with("b3BlcmF0b3I6")
                        })
                    })
                }))
            || forbidden_credential(request.headers(), oauth_token, app)
            || !connection_headers_are_safe(request.headers())
        {
            return plain(
                S::UNAUTHORIZED,
                "credential not accepted on this endpoint\n",
                head,
            );
        }
        if self.platform.is_some() {
            let cookies = platform_cookies(request.headers(), false);
            request.headers_mut().remove(header::COOKIE);
            for value in cookies {
                request.headers_mut().append(header::COOKIE, value);
            }
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

    async fn forward_platform(
        &self,
        client: &reqwest::Client,
        request: Request<Incoming>,
    ) -> Result<Reply, S> {
        const LOCAL: &str = "http://127.0.0.1:4177";
        let (parts, body) = request.into_parts();
        let path = parts.uri.path();
        match (&parts.method, path) {
            (&Method::GET, "/" | "/platform/sign-in") => {}
            (&Method::POST, "/tenants" | "/platform/sign-in" | "/platform/sign-out") => {
                let mut origins = parts.headers.get_all(header::ORIGIN).iter();
                let expected = format!("https://{}", self.server_name);
                if origins.next().and_then(|origin| origin.to_str().ok()) != Some(expected.as_str())
                    || origins.next().is_some()
                {
                    return Err(S::FORBIDDEN);
                }
            }
            _ => return Err(S::METHOD_NOT_ALLOWED),
        }
        let post = parts.method == Method::POST;
        let body = Limited::new(body, 512)
            .collect()
            .await
            .map_err(|_| S::PAYLOAD_TOO_LARGE)?
            .to_bytes();
        let mut outgoing = client
            .request(parts.method, format!("{LOCAL}{path}"))
            .body(body);
        for value in platform_cookies(&parts.headers, true) {
            outgoing = outgoing.header(header::COOKIE, value);
        }
        let mut types = parts.headers.get_all(header::CONTENT_TYPE).iter();
        if let Some(value) = types.next() {
            if types.next().is_some() {
                return Err(S::BAD_REQUEST);
            }
            outgoing = outgoing.header(header::CONTENT_TYPE, value.clone());
        }
        if post {
            outgoing = outgoing.header(header::ORIGIN, LOCAL);
        }
        let upstream = outgoing.send().await.map_err(|_| S::BAD_GATEWAY)?;
        let status = upstream.status();
        let mut headers = upstream.headers().clone();
        remove_transport_headers(&mut headers);
        headers.remove(header::CONTENT_LENGTH);
        let body = bounded_response(upstream, MAX_CONSOLE_RESPONSE)
            .await
            .map_err(|_| S::BAD_GATEWAY)?;
        let mut reply = Response::new(Full::new(body));
        *reply.status_mut() = status;
        *reply.headers_mut() = headers;
        Ok(reply)
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
        if public_application::route_allowed(parts.method.as_str(), path)
            && let Some(mut bearer) = parts.headers.remove(header::AUTHORIZATION)
        {
            // The controller checks the installation and the existing operation
            // and network grants. Do not forward a generic bearer even to an
            // older upstream that doesn't implement the application lane.
            bearer.set_sensitive(true);
            parts
                .headers
                .insert(public_application::ACCESS_HEADER, bearer);
        }
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

fn platform_cookies(headers: &HeaderMap, only_platform: bool) -> Vec<header::HeaderValue> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|raw| {
            let pairs = raw
                .to_str()
                .ok()?
                .split(';')
                .map(str::trim)
                .filter(|pair| {
                    pair.split_once('=')
                        .is_some_and(|(name, _)| name == "__Host-laneway-platform")
                        == only_platform
                })
                .collect::<Vec<_>>();
            if pairs.is_empty() {
                return None;
            }
            let mut value: header::HeaderValue = pairs.join("; ").parse().ok()?;
            value.set_sensitive(true);
            Some(value)
        })
        .collect()
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

fn forbidden_credential(headers: &HeaderMap, oauth: bool, app: bool) -> bool {
    let mut auth = headers.get_all(header::AUTHORIZATION).iter();
    headers.contains_key(header::PROXY_AUTHORIZATION)
        || auth.next().is_some_and(|value| {
            !(oauth && value.as_bytes().starts_with(b"Basic ")
                || app
                    && value
                        .to_str()
                        .ok()
                        .and_then(public_application::candidate)
                        .is_some()
                    && !headers.contains_key(header::COOKIE)
                    && !headers.contains_key(header::ORIGIN)
                    && !headers
                        .keys()
                        .any(|name| name.as_str().starts_with("sec-fetch-")))
        })
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
        public_application::ACCESS_HEADER,
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
