//! The lab listener exposes authenticated inventory only. Never dispatch to
//! the unrestricted operator commands, including when a credential is absent.
use bytes::Bytes;
use http_body_util::Full;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, header};
use laneway_controller::{ListError, RootCredential, SessionError, SessionStore, bearer_inventory};
use serde_json::json;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::Semaphore;
mod login;
mod mutations;

const COOKIE: &str = "__Host-laneway_admin_session";
const CSRF: &str = "__Host-laneway_admin_csrf";
const REQUEST_ID: &str = "x-laneway-request-id";
type Reply = Response<Full<Bytes>>;

#[derive(Clone)]
pub struct State {
    database: Arc<PathBuf>,
    queries: Arc<Semaphore>,
    root: Option<Arc<RootCredential>>,
    discovery: Arc<std::sync::Mutex<crate::discovery_limit::Limiter>>,
    logins: Arc<std::sync::Mutex<crate::discovery_limit::Limiter>>,
    passwords: Arc<laneway_controller::password::PasswordVerifier>,
}
impl State {
    pub fn new(database: PathBuf, root: Option<RootCredential>) -> anyhow::Result<Self> {
        Ok(Self {
            database: Arc::new(database),
            queries: Arc::new(Semaphore::new(8)),
            root: root.map(Arc::new),
            discovery: Default::default(),
            logins: Arc::new(std::sync::Mutex::new(
                crate::discovery_limit::Limiter::login(),
            )),
            passwords: Arc::new(laneway_controller::password::PasswordVerifier::new()?),
        })
    }
}

struct Failure(StatusCode, &'static str, &'static str, bool);
const AUTH: Failure = Failure(
    StatusCode::UNAUTHORIZED,
    "ERROR_CODE_UNAUTHENTICATED",
    "authentication failed",
    false,
);
const INTERNAL: Failure = Failure(
    StatusCode::INTERNAL_SERVER_ERROR,
    "ERROR_CODE_INTERNAL",
    "internal controller error",
    true,
);
fn malformed(detail: &'static str) -> Failure {
    Failure(
        StatusCode::BAD_REQUEST,
        "ERROR_CODE_MALFORMED",
        detail,
        false,
    )
}
impl Failure {
    fn reply(self, id: &str, head: bool) -> Reply {
        let data = json!({"code":self.1,"detail":self.2,"retryable":self.3,"request_id":id});
        let mut response = response(self.0, id, data.to_string().into_bytes(), head);
        if self.0 == StatusCode::METHOD_NOT_ALLOWED {
            response
                .headers_mut()
                .insert(header::ALLOW, "GET, HEAD".parse().unwrap());
        }
        response
    }
}

fn response(status: StatusCode, id: &str, data: Vec<u8>, head: bool) -> Reply {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(REQUEST_ID, id)
        .header(header::CONTENT_LENGTH, data.len())
        .body(Full::new(if head {
            Bytes::new()
        } else {
            Bytes::from(data)
        }))
        .unwrap()
}

enum Credential {
    Session(String),
    Bearer(String),
}

fn cookie<'a>(headers: &'a HeaderMap, wanted: &str) -> Result<Option<&'a str>, Failure> {
    let mut token = None;
    for value in headers.get_all(header::COOKIE) {
        for pair in value.to_str().map_err(|_| AUTH)?.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name == wanted {
                let raw = value
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap_or(value);
                if raw.is_empty() || token.replace(raw).is_some() {
                    return Err(AUTH);
                }
            }
        }
    }
    Ok(token)
}
fn credential(headers: &HeaderMap) -> Result<Credential, Failure> {
    let token = cookie(headers, COOKIE)?;
    let mut authorization = headers.get_all(header::AUTHORIZATION).iter();
    if let Some(value) = authorization.next() {
        if token.is_some()
            || authorization.next().is_some()
            || headers.contains_key(header::ORIGIN)
            || headers
                .keys()
                .any(|name| name.as_str().starts_with("sec-fetch-"))
        {
            return Err(AUTH);
        }
        let raw = value.to_str().map_err(|_| AUTH)?;
        let (scheme, secret) = raw.split_once(' ').ok_or(AUTH)?;
        if !scheme.eq_ignore_ascii_case("bearer")
            || secret.is_empty()
            || secret.bytes().any(|b| b.is_ascii_whitespace() || b == b',')
        {
            return Err(AUTH);
        }
        return Ok(Credential::Bearer(raw.to_owned()));
    }
    token.map(|s| Credential::Session(s.to_owned())).ok_or(AUTH)
}

fn query_limit(raw: Option<&str>) -> Result<usize, ListError> {
    // Go's URL.Query discards individual fields with invalid escapes or raw
    // semicolons. Keep the first valid limit, like url.Values.Get.
    let limit = raw
        .unwrap_or_default()
        .split('&')
        .filter(|field| {
            !field.contains(';')
                && field.bytes().enumerate().all(|(i, b)| {
                    b != b'%'
                        || field
                            .as_bytes()
                            .get(i + 1..i + 3)
                            .is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit))
                })
        })
        .flat_map(|field| form_urlencoded::parse(field.as_bytes()))
        .find(|(k, _)| k == "limit")
        .map(|(_, v)| v.into_owned())
        .filter(|s| !s.is_empty())
        .map(|v| v.parse::<usize>().map_err(|_| ListError::Limit))
        .transpose()?
        .unwrap_or(100);
    if !(1..=1000).contains(&limit) {
        return Err(ListError::Limit);
    }
    Ok(limit)
}

pub async fn handle(
    req: Request<hyper::body::Incoming>,
    state: State,
    peer: std::net::IpAddr,
) -> Reply {
    let head = req.method() == Method::HEAD;
    let mut random = [0; 16];
    if getrandom::fill(&mut random).is_err() {
        static FALLBACK: AtomicU64 = AtomicU64::new(1);
        return INTERNAL.reply(
            &format!("{:032x}", FALLBACK.fetch_add(1, Ordering::Relaxed)),
            head,
        );
    }
    let id = hex::encode(random);
    match dispatch(req, state, &id, head, peer).await {
        Ok(resp) => resp,
        Err(err) => err.reply(&id, head),
    }
}

async fn dispatch(
    req: Request<hyper::body::Incoming>,
    state: State,
    id: &str,
    head: bool,
    peer: std::net::IpAddr,
) -> Result<Reply, Failure> {
    let path = req.uri().path();
    if path.contains('%')
        || path.contains("//")
        || path.ends_with('/')
        || path.split('/').any(|p| matches!(p, "." | ".."))
    {
        return Err(malformed("administrator path must be canonical"));
    }
    let pieces: Vec<_> = path.split('/').collect();
    let root_probe = path == "/v1/admin/auth/root";
    let logout = path == "/v1/admin/auth/logout";
    let rotate = path == "/v1/admin/auth/session/rotate";
    let login = path == "/v1/admin/auth/login";
    let discovery = path == "/v1/admin/auth/state";
    let session_view = path == "/v1/admin/auth/session";
    let network = match pieces.as_slice() {
        _ if root_probe || discovery || session_view || logout || rotate || login => None,
        ["", "v1", "admin", "networks"] => None,
        ["", "v1", "admin", "networks", network, "nodes"] => Some(*network),
        _ => {
            return Err(Failure(
                StatusCode::NOT_FOUND,
                "ERROR_CODE_MALFORMED",
                "route not found",
                false,
            ));
        }
    };
    if (logout || rotate || login) && req.method() != Method::POST {
        let mut r = Failure(
            StatusCode::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
            false,
        )
        .reply(id, head);
        r.headers_mut()
            .insert(header::ALLOW, "POST".parse().unwrap());
        return Ok(r);
    }
    if !(logout || rotate || login || head) && req.method() != Method::GET {
        return Err(Failure(
            StatusCode::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
            false,
        ));
    }
    if login {
        return login::handle(req, state, id, peer).await;
    }
    if discovery {
        // This loopback listener does not authenticate relay client certificates.
        // Never trust a forwarded address on this transport.
        if req.headers().contains_key("x-laneway-public-client-ip") {
            return Err(AUTH);
        }
        let allowed = state
            .discovery
            .lock()
            .map_err(|_| INTERNAL)?
            .check(peer, std::time::Instant::now());
        if let Err(wait) = allowed {
            let mut r = Failure(
                StatusCode::TOO_MANY_REQUESTS,
                "ERROR_CODE_RESOURCE_EXHAUSTED",
                "authentication temporarily unavailable",
                true,
            )
            .reply(id, head);
            r.headers_mut().insert(header::RETRY_AFTER, wait.into());
            return Ok(r);
        }
    }
    let network = network
        .map(|n| n.parse().map_err(|_| ListError::NetworkId))
        .transpose();
    let limit = query_limit(req.uri().query());
    // Keep this permit in the blocking closure even if the socket disappears.
    let permit = Arc::clone(&state.queries)
        .try_acquire_owned()
        .map_err(|_| {
            Failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERROR_CODE_RESOURCE_EXHAUSTED",
                "controller busy",
                true,
            )
        })?;
    if discovery {
        let v = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            laneway_controller::auth_state(&state.database)
        })
        .await
        .map_err(|_| INTERNAL)?
        .map_err(|_| INTERNAL)?;
        return Ok(response(
            StatusCode::OK,
            id,
            json!({"state":v}).to_string().into_bytes(),
            head,
        ));
    }
    let credential = credential(req.headers())?;
    if logout || rotate {
        let Credential::Session(token) = credential else {
            return Err(AUTH);
        };
        return mutations::session(state, permit, id, token, req.headers(), rotate).await;
    }
    let csrf = if session_view {
        cookie(req.headers(), CSRF)
            .ok()
            .flatten()
            .map(str::to_owned)
    } else {
        None
    };
    if session_view && !matches!(credential, Credential::Session(_)) {
        return Err(AUTH);
    }
    if root_probe {
        let (Credential::Bearer(header), Some(root)) = (credential, state.root) else {
            return Err(AUTH);
        };
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            root.probe(&header, &state.database)
        })
        .await
        .map_err(|_| INTERNAL)?
        .map_err(|_| AUTH)?;
        return Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
            .header(REQUEST_ID, id)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }
    let (list, metadata) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _permit = permit;
        match credential {
            Credential::Session(token) if session_view => {
                let mut r = SessionStore::open(&state.database)?.view(&token, csrf.as_deref())?;
                r.list["idle_expires_at_unix_seconds"] = json!(r.idle);
                r.list["absolute_expires_at_unix_seconds"] = json!(r.absolute);
                Ok((
                    serde_json::to_vec(&r.list)?,
                    Some((r.id, r.idle, r.absolute)),
                ))
            }
            Credential::Session(token) => {
                let query = network.and_then(|n| limit.map(|l| (n, l)));
                let r = SessionStore::open(&state.database)?.inventory(&token, query)?;
                Ok((
                    serde_json::to_vec(&r.list)?,
                    Some((r.id, r.idle, r.absolute)),
                ))
            }
            Credential::Bearer(header) => Ok((
                serde_json::to_vec(&bearer_inventory(
                    &state.database,
                    &header,
                    state.root.as_deref(),
                    network,
                    limit,
                )?)?,
                None,
            )),
        }
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(|e| {
        if let Some(problem) = e.downcast_ref::<ListError>() {
            return match problem {
                ListError::NetworkId => malformed("invalid network_id"),
                ListError::Limit => malformed("limit must be an integer from 1 through 1000"),
                ListError::Missing => Failure(
                    StatusCode::NOT_FOUND,
                    "ERROR_CODE_MALFORMED",
                    "record not found",
                    false,
                ),
            };
        }
        match e.downcast_ref::<SessionError>() {
            Some(SessionError::Invalid | SessionError::Expired) => AUTH,
            Some(SessionError::Denied) => Failure(
                StatusCode::FORBIDDEN,
                "ERROR_CODE_PERMISSION_DENIED",
                "permission denied",
                false,
            ),
            None => INTERNAL,
        }
    })?;
    let mut reply = response(StatusCode::OK, id, list, head);
    let Some((session, idle, absolute)) = metadata else {
        return Ok(reply);
    };
    for (name, value) in [
        ("x-laneway-session-id", session.to_string()),
        ("x-laneway-session-idle-expires-at", idle.to_string()),
        (
            "x-laneway-session-absolute-expires-at",
            absolute.to_string(),
        ),
    ] {
        reply
            .headers_mut()
            .insert(name, value.parse().map_err(|_| INTERNAL)?);
    }
    Ok(reply)
}
