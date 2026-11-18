//! The lab listener exposes authenticated inventory only. Never dispatch to
//! the unrestricted operator commands, including when a credential is absent.
use bytes::Bytes;
use http_body_util::Full;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, header};
use laneway_controller::{ListError, SessionError, SessionStore};
use laneway_protocol::Id;
use serde_json::json;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::Semaphore;

const COOKIE: &str = "__Host-laneway_admin_session";
const REQUEST_ID: &str = "x-laneway-request-id";
type Reply = Response<Full<Bytes>>;

#[derive(Clone)]
pub struct State {
    database: Arc<PathBuf>,
    queries: Arc<Semaphore>,
}
impl State {
    pub fn new(database: PathBuf) -> Self {
        Self {
            database: Arc::new(database),
            queries: Arc::new(Semaphore::new(8)),
        }
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

fn cookie(headers: &HeaderMap) -> Result<&str, Failure> {
    // Bearer support needs independent root/automation authorization.
    // In particular a mixed request must never downgrade to its cookie.
    if headers.contains_key(header::AUTHORIZATION) {
        return Err(AUTH);
    }
    let mut token = None;
    for value in headers.get_all(header::COOKIE) {
        for pair in value.to_str().map_err(|_| AUTH)?.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name == COOKIE {
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
    token.ok_or(AUTH)
}

fn query(network: Option<&str>, raw: Option<&str>) -> Result<(Option<Id>, usize), ListError> {
    let network = network
        .map(|n| n.parse().map_err(|_| ListError::NetworkId))
        .transpose()?;
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
    Ok((network, limit))
}

pub async fn handle<B>(req: Request<B>, state: State) -> Reply {
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
    match dispatch(req, state, &id, head).await {
        Ok(resp) => resp,
        Err(err) => err.reply(&id, head),
    }
}

async fn dispatch<B>(
    req: Request<B>,
    state: State,
    id: &str,
    head: bool,
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
    let network = match pieces.as_slice() {
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
    if !head && req.method() != Method::GET {
        return Err(Failure(
            StatusCode::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
            false,
        ));
    }
    let token = cookie(req.headers())?.to_owned();
    let query = query(network, req.uri().query());
    // Keep this permit in the blocking closure even if the socket disappears.
    let permit = state.queries.try_acquire_owned().map_err(|_| {
        Failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERROR_CODE_RESOURCE_EXHAUSTED",
            "controller busy",
            true,
        )
    })?;
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        SessionStore::open(&state.database)?.inventory(&token, query)
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
    let mut reply = response(
        StatusCode::OK,
        id,
        serde_json::to_vec(&result.list).map_err(|_| INTERNAL)?,
        head,
    );
    for (name, value) in [
        ("x-laneway-session-id", result.id.to_string()),
        ("x-laneway-session-idle-expires-at", result.idle.to_string()),
        (
            "x-laneway-session-absolute-expires-at",
            result.absolute.to_string(),
        ),
    ] {
        reply
            .headers_mut()
            .insert(name, value.parse().map_err(|_| INTERNAL)?);
    }
    Ok(reply)
}
