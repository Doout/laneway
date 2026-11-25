use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{
    ALLOW, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, COOKIE, ORIGIN, X_CONTENT_TYPE_OPTIONS,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use laneway_config::Config;
use laneway_protocol::Id;
use rustls::{ServerConfig, pki_types::CertificateDer, sign::SingleCertAndKey, version::TLS13};
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::{enrollment::EnrollmentAuthority, serve_enrollment::Enrollment, startup, store::Store};

const NETWORKS: &str = "/v1/admin/networks";
const NETWORK_PREFIX: &str = "/v1/admin/networks/";
const ROOT_PROBE: &str = "/v1/admin/auth/root";
const REQUEST_ID: &str = "x-laneway-request-id";
const HEADER_DEADLINE: Duration = Duration::from_secs(5);
const CONNECTION_DEADLINE: Duration = Duration::from_secs(15);

type Reply = Response<Full<Bytes>>;

pub(crate) fn run(
    config_file: &Path,
    diagnostics: Option<&str>,
    enroll: bool,
    full: bool,
) -> Result<()> {
    let config = Config::load(config_file)?;
    let diagnostics = diagnostics
        .filter(|address| !address.is_empty())
        .map(loopback)
        .transpose()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_async(config, diagnostics, enroll, full))
}

async fn run_async(
    config: Config,
    diagnostics: Option<SocketAddr>,
    enroll: bool,
    full: bool,
) -> Result<()> {
    let enrollment = enroll
        .then(|| EnrollmentAuthority::from_config(&config))
        .transpose()?
        .map(Enrollment::new)
        .map(Arc::new);
    let prepared = startup::open(&config)?;
    let principal = prepared.store.root_principal()?;
    let quic = if full {
        Some(
            crate::serve_quic::listen(
                &config.controller.quic_listen,
                prepared.certificate.clone(),
                prepared.roots.clone(),
            )
            .await?,
        )
    } else {
        None
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls =
        ServerConfig::builder_with_provider(provider.clone()).with_protocol_versions(&[&TLS13])?;
    let tls = if full {
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(prepared.roots),
            provider,
        )
        .allow_unauthenticated()
        .build()?;
        tls.with_client_cert_verifier(verifier)
    } else {
        tls.with_no_client_auth()
    };
    let mut tls = tls.with_cert_resolver(Arc::new(SingleCertAndKey::from(prepared.certificate)));
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));

    let address = if config.controller.listen.starts_with(':') {
        format!("0.0.0.0{}", config.controller.listen)
    } else {
        config.controller.listen
    };
    let listener = TcpListener::bind(&address)
        .await
        .context("bind controller HTTPS listener")?;
    let diagnostics = if let Some(address) = diagnostics {
        Some(
            TcpListener::bind(address)
                .await
                .context("bind diagnostics listener")?,
        )
    } else {
        None
    };
    let mut term = signal(SignalKind::terminate())?;
    let metrics = Arc::new(Metrics::default());
    let store = Arc::new(Mutex::new(prepared.store));
    let quic_authority = enrollment.clone();
    let service = Arc::new(Service {
        bearer_digest: prepared.bearer_digest,
        principal,
        store: store.clone(),
        enrollment,
        full,
        metrics: metrics.clone(),
    });
    let listen = listener.local_addr()?;
    let diagnostics_address = diagnostics
        .as_ref()
        .map(TcpListener::local_addr)
        .transpose()?
        .map_or_else(|| "disabled".to_owned(), |address| address.to_string());
    let mode = if full {
        "controller-candidate"
    } else if enroll {
        "enrollment-candidate"
    } else {
        "read-only"
    };
    let quic_address = quic
        .as_ref()
        .map(|endpoint| endpoint.local_addr())
        .transpose()?
        .map_or_else(|| "disabled".to_owned(), |address| address.to_string());
    println!(
        "laneway-controller HTTPS={listen} QUIC={quic_address} diagnostics={diagnostics_address} mode={mode}"
    );
    tokio::select! {
        result = serve_https(listener, acceptor, service) => result,
        result = crate::serve_quic::serve(quic, prepared.identity.network_id, store, quic_authority) => result,
        result = serve_diagnostics(diagnostics, metrics) => result,
        result = tokio::signal::ctrl_c() => result.context("wait for controller interrupt"),
        _ = term.recv() => Ok(()),
    }
}

fn loopback(address: &str) -> Result<SocketAddr> {
    if let Some((host, port)) = address.rsplit_once(':')
        && host.eq_ignore_ascii_case("localhost")
    {
        return Ok(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port.parse()?,
        ));
    }
    let parsed: SocketAddr = address
        .parse()
        .context("invalid diagnostics socket address")?;
    ensure!(
        parsed.ip().is_loopback(),
        "diagnostics address must be loopback-only"
    );
    Ok(parsed)
}

async fn serve_https(listener: TcpListener, tls: TlsAcceptor, service: Arc<Service>) -> Result<()> {
    let slots = Arc::new(Semaphore::new(64));
    loop {
        let (socket, peer) = listener
            .accept()
            .await
            .context("accept controller connection")?;
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let tls = tls.clone();
        let service = service.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let _ = timeout(CONNECTION_DEADLINE, async move {
                let stream = tls.accept(socket).await?;
                let verified_leaf = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|chain| chain.first())
                    .cloned();
                serve_connection(stream, |request| {
                    let service = service.clone();
                    let verified_leaf = verified_leaf.clone();
                    async move { service.handle(request, peer.ip(), verified_leaf).await }
                })
                .await
            })
            .await;
        });
    }
}

async fn serve_diagnostics(listener: Option<TcpListener>, metrics: Arc<Metrics>) -> Result<()> {
    let Some(listener) = listener else {
        return std::future::pending().await;
    };
    let slots = Arc::new(Semaphore::new(8));
    loop {
        let (socket, _) = listener.accept().await?;
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let _ = timeout(
                CONNECTION_DEADLINE,
                serve_connection(socket, |request| {
                    let metrics = metrics.clone();
                    async move { metrics.handle(request) }
                }),
            )
            .await;
        });
    }
}

async fn serve_connection<I, H, F>(stream: I, handle: H) -> Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin,
    H: Fn(Request<Incoming>) -> F,
    F: std::future::Future<Output = Reply>,
{
    http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_DEADLINE)
        .max_buf_size(16 << 10)
        .keep_alive(false)
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |request| {
                let result = handle(request);
                async move { Ok::<_, Infallible>(result.await) }
            }),
        )
        .await
        .context("serve HTTP connection")
}

struct Service {
    bearer_digest: [u8; 32],
    principal: Id,
    store: Arc<Mutex<Store>>,
    enrollment: Option<Arc<Enrollment>>,
    full: bool,
    metrics: Arc<Metrics>,
}

impl Service {
    async fn handle(
        self: Arc<Self>,
        request: Request<Incoming>,
        peer: IpAddr,
        verified_leaf: Option<CertificateDer<'static>>,
    ) -> Reply {
        self.metrics.requests.fetch_add(1, Relaxed);
        let mut random = [0u8; 16];
        let request_id = if getrandom::fill(&mut random).is_ok() {
            hex::encode(random)
        } else {
            static FALLBACK: AtomicU64 = AtomicU64::new(0);
            let request_id = format!("{:032x}", FALLBACK.fetch_add(1, Relaxed) + 1);
            self.metrics.record(StatusCode::INTERNAL_SERVER_ERROR);
            return finish(error(ApiError::Internal, &request_id), &request_id);
        };
        let head = request.method() == Method::HEAD;
        let mut reply = if let Some(enrollment) = &self.enrollment
            && request.uri().path() == "/v1/enroll"
        {
            enrollment
                .clone()
                .handle(self.store.clone(), request, peer)
                .await
        } else if self.enrollment.is_some() && request.uri().path() == "/v1/admin/enrollment-tokens"
        {
            if self.authorized(&request) {
                crate::serve_enrollment::issue_token(
                    self.store.clone(),
                    self.principal,
                    request,
                    &request_id,
                )
                .await
            } else {
                error(ApiError::Unauthenticated, &request_id)
            }
        } else if self.full && request.uri().path() == "/v1/renew" {
            if let (Some(enrollment), Some(leaf)) = (&self.enrollment, verified_leaf) {
                enrollment
                    .clone()
                    .handle_renew(self.store.clone(), leaf.as_ref().to_vec(), request)
                    .await
            } else {
                crate::serve_enrollment::renewal_unauthenticated()
            }
        } else if self.full
            && let Some(serial) = request.uri().path().strip_prefix("/v1/revocations/")
        {
            if serial.is_empty() || serial.contains('/') {
                error(ApiError::Missing("route not found"), &request_id)
            } else if matches!(*request.method(), Method::GET | Method::HEAD) {
                let serial = serial.to_owned();
                let store = self.store.clone();
                match tokio::task::spawn_blocking(move || {
                    let now = crate::serve_quic::now()?;
                    let mut store = store
                        .lock()
                        .map_err(|_| anyhow::anyhow!("controller store lock is poisoned"))?;
                    Ok::<_, anyhow::Error>(crate::policy::revocation_response(
                        &mut store,
                        verified_leaf.as_ref().map(|leaf| leaf.as_ref()),
                        &serial,
                        now,
                    ))
                })
                .await
                {
                    Ok(Ok(reply)) => reply,
                    _ => error(ApiError::Internal, &request_id),
                }
            } else {
                error(ApiError::Method, &request_id)
            }
        } else if self.full && crate::acl_admin::matches(request.uri().path()) {
            if self.authorized(&request) {
                crate::acl_admin::handle(self.store.clone(), self.principal, request, &request_id)
                    .await
            } else {
                error(ApiError::Unauthenticated, &request_id)
            }
        } else {
            match self.route(&request).await {
                Ok(reply) => reply,
                Err(problem) => error(problem, &request_id),
            }
        };
        if head {
            *reply.body_mut() = Full::new(Bytes::new());
        }
        self.metrics.record(reply.status());
        finish(reply, &request_id)
    }

    async fn route(
        self: &Arc<Self>,
        request: &Request<Incoming>,
    ) -> std::result::Result<Reply, ApiError> {
        let path = request.uri().path();
        if path.contains(['%', '\\'])
            || path.contains("//")
            || path.ends_with('/')
            || path.split('/').any(|segment| matches!(segment, "." | ".."))
        {
            return Err(ApiError::Malformed("administrator path must be canonical"));
        }
        let network = path
            .strip_prefix(NETWORK_PREFIX)
            .filter(|tail| !tail.contains('/'));
        if path != ROOT_PROBE && path != NETWORKS && network.is_none() {
            return Err(ApiError::Missing("route not found"));
        }
        if !matches!(*request.method(), Method::GET | Method::HEAD) {
            return Err(ApiError::Method);
        }
        if !self.authorized(request) {
            return Err(ApiError::Unauthenticated);
        }

        let route = if path == ROOT_PROBE {
            Route::RootProbe
        } else if let Some(text) = network {
            Route::Network(
                text.parse()
                    .map_err(|_| ApiError::Malformed("invalid network_id"))?,
            )
        } else {
            let query = request.uri().query().unwrap_or_default();
            let raw = form_urlencoded::parse(query.as_bytes())
                .find(|(key, _)| key == "limit")
                .map(|(_, value)| value);
            let limit = match raw.as_deref() {
                Some(raw) if !raw.is_empty() => raw
                    .parse::<usize>()
                    .ok()
                    .filter(|limit| (1..=1000).contains(limit))
                    .ok_or(ApiError::Malformed(
                        "limit must be an integer from 1 through 1000",
                    ))?,
                _ => 100,
            };
            Route::List(limit)
        };
        let service = self.clone();
        tokio::task::spawn_blocking(move || service.read(route))
            .await
            .map_err(|_| ApiError::Internal)?
    }

    fn authorized(&self, request: &Request<Incoming>) -> bool {
        let headers = request.headers();
        if headers.contains_key(ORIGIN)
            || headers
                .keys()
                .any(|name| name.as_str().starts_with("sec-fetch-"))
        {
            return false;
        }
        if headers.get_all(COOKIE).iter().any(|cookie| {
            cookie.as_bytes().split(|byte| *byte == b';').any(|part| {
                let name = part
                    .split(|byte| *byte == b'=')
                    .next()
                    .unwrap_or_default()
                    .trim_ascii();
                name == b"__Host-laneway_admin_session"
            })
        }) {
            return false;
        }
        let mut values = headers.get_all(AUTHORIZATION).iter();
        let Some(value) = values.next() else {
            return false;
        };
        let Some(token) = value.as_bytes().strip_prefix(b"Bearer ") else {
            return false;
        };
        if values.next().is_some()
            || token.is_empty()
            || token
                .iter()
                .any(|byte| byte.is_ascii_whitespace() || *byte == b',')
        {
            return false;
        }
        let actual: [u8; 32] = Sha256::digest(value.as_bytes()).into();
        bool::from(actual.ct_eq(&self.bearer_digest))
    }

    fn read(&self, route: Route) -> std::result::Result<Reply, ApiError> {
        let store = self.store.lock().map_err(|_| ApiError::Internal)?;
        if store.root_principal().map_err(|_| ApiError::Internal)? != self.principal {
            return Err(ApiError::Unauthenticated);
        }
        match route {
            Route::RootProbe => Ok(response(
                StatusCode::NO_CONTENT,
                "application/json",
                Bytes::new(),
            )),
            Route::Network(id) => json_response(
                StatusCode::OK,
                &store
                    .network_view(id)
                    .map_err(|_| ApiError::Internal)?
                    .ok_or(ApiError::Missing("record not found"))?,
            ),
            Route::List(limit) => json_response(
                StatusCode::OK,
                &serde_json::json!({"networks": store.network_views(limit).map_err(|_| ApiError::Internal)?}),
            ),
        }
    }
}

enum Route {
    RootProbe,
    Network(Id),
    List(usize),
}

enum ApiError {
    Unauthenticated,
    Malformed(&'static str),
    Missing(&'static str),
    Method,
    Internal,
}

fn error(problem: ApiError, request_id: &str) -> Reply {
    let (status, code, detail) = match problem {
        ApiError::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            "ERROR_CODE_UNAUTHENTICATED",
            "authentication failed",
        ),
        ApiError::Malformed(detail) => (StatusCode::BAD_REQUEST, "ERROR_CODE_MALFORMED", detail),
        ApiError::Missing(detail) => (StatusCode::NOT_FOUND, "ERROR_CODE_MALFORMED", detail),
        ApiError::Method => (
            StatusCode::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
        ),
        ApiError::Internal => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERROR_CODE_INTERNAL",
            "internal controller error",
        ),
    };
    let body = serde_json::json!({"code": code, "detail": detail, "retryable": status.is_server_error(),
        "request_id": request_id});
    let mut reply = response(status, "application/json", Bytes::from(body.to_string()));
    if status == StatusCode::METHOD_NOT_ALLOWED {
        reply
            .headers_mut()
            .insert(ALLOW, "GET, HEAD".parse().expect("static header"));
    }
    reply
}

fn json_response(
    status: StatusCode,
    value: &impl Serialize,
) -> std::result::Result<Reply, ApiError> {
    let raw = serde_json::to_vec(value).map_err(|_| ApiError::Internal)?;
    Ok(response(status, "application/json", Bytes::from(raw)))
}

fn response(status: StatusCode, content_type: &'static str, body: Bytes) -> Reply {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .body(Full::new(body))
        .expect("static response metadata")
}

fn finish(mut reply: Reply, request_id: &str) -> Reply {
    reply
        .headers_mut()
        .insert(REQUEST_ID, request_id.parse().expect("hex-encoded ID"));
    reply
        .headers_mut()
        .insert(CACHE_CONTROL, "no-store".parse().expect("static header"));
    reply.headers_mut().insert(
        X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().expect("static header"),
    );
    reply
}

#[derive(Default)]
struct Metrics {
    requests: AtomicU64,
    successful: AtomicU64,
    malformed: AtomicU64,
    unauthorized: AtomicU64,
    internal: AtomicU64,
}

impl Metrics {
    fn record(&self, status: StatusCode) {
        let counter = match status {
            status if status.is_success() => &self.successful,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => &self.unauthorized,
            status if status.is_server_error() => &self.internal,
            _ => &self.malformed,
        };
        counter.fetch_add(1, Relaxed);
    }

    fn handle(&self, request: Request<Incoming>) -> Reply {
        if request.uri().path() != "/metrics" {
            return response(
                StatusCode::NOT_FOUND,
                "text/plain",
                Bytes::from_static(b"404 page not found\n"),
            );
        }
        if !matches!(*request.method(), Method::GET | Method::HEAD) {
            return response(StatusCode::METHOD_NOT_ALLOWED, "text/plain", Bytes::new());
        }
        let metrics = if request.method() == Method::HEAD {
            String::new()
        } else {
            format!(
                "laneway_authorization_failures_total {}\nlaneway_controller_requests_total {}\nlaneway_controller_up 1\nlaneway_internal_failures_total {}\nlaneway_malformed_input_total {}\nlaneway_successful_responses_total {}\n",
                self.unauthorized.load(Relaxed),
                self.requests.load(Relaxed),
                self.internal.load(Relaxed),
                self.malformed.load(Relaxed),
                self.successful.load(Relaxed),
            )
        };
        response(
            StatusCode::OK,
            "text/plain; version=0.0.4; charset=utf-8",
            Bytes::from(metrics),
        )
    }
}
