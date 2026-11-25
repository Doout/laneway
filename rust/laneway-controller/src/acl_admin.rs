//! Root-bearer ACL management for the explicit controller candidate.
mod selector;

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering::Relaxed},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::{Method, Request, Response, StatusCode, body::Incoming, header};
use laneway_protocol::{Id, v1::TrafficSelector};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::store::Store;
pub(crate) use selector::decode_selector_json;

const NETWORK_PREFIX: &str = "/v1/admin/networks/";
const RULE_PREFIX: &str = "/v1/admin/acl-rules/";
const MAX_BODY: usize = 128 << 10;
const MAX_SELECTOR: usize = 16 << 10;
type Reply = Response<Full<Bytes>>;

pub(crate) fn matches(path: &str) -> bool {
    target(path).is_some()
}

fn target(path: &str) -> Option<(bool, &str)> {
    if let Some(network) = path
        .strip_prefix(NETWORK_PREFIX)
        .and_then(|p| p.strip_suffix("/acl-rules"))
        && !network.is_empty()
        && !network.contains('/')
    {
        return Some((true, network));
    }
    path.strip_prefix(RULE_PREFIX)
        .filter(|p| !p.is_empty() && !p.contains('/'))
        .map(|rule| (false, rule))
}

pub(crate) async fn handle(
    store: Arc<Mutex<Store>>,
    principal: Id,
    request: Request<Incoming>,
    request_id: &str,
) -> Reply {
    let result = execute(store, principal, request).await;
    match result {
        Ok((status, value)) => reply(status, value),
        Err(error) => error.response(request_id),
    }
}

async fn execute(
    store: Arc<Mutex<Store>>,
    principal: Id,
    request: Request<Incoming>,
) -> Result<(StatusCode, Value), Problem> {
    let (network, raw) = target(request.uri().path()).ok_or(Problem::Missing)?;
    let id = raw.parse::<Id>().map_err(|_| {
        Problem::Malformed(if network {
            "invalid network_id"
        } else {
            "invalid rule_id"
        })
    })?;
    let operation = match (network, request.method()) {
        (true, &Method::GET | &Method::HEAD) => {
            Operation::List(id, query_limit(request.uri().query())?)
        }
        (true, &Method::POST) => Operation::Create(id, decode_request(request, true).await?),
        (false, &Method::PUT) => Operation::Update(id, decode_request(request, false).await?),
        (false, &Method::DELETE) => Operation::Delete(id),
        (true, _) => return Err(Problem::Method("GET, HEAD, POST")),
        (false, _) => return Err(Problem::Method("PUT, DELETE")),
    };
    let canceled = Arc::new(AtomicBool::new(false));
    let _guard = CancelOnDrop(canceled.clone());
    tokio::task::spawn_blocking(move || {
        let mut store = store.lock().map_err(|_| Problem::Internal)?;
        apply(&mut store, principal, operation, &canceled)
    })
    .await
    .map_err(|_| Problem::Internal)?
}

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Relaxed);
    }
}

fn query_limit(query: Option<&str>) -> Result<usize, Problem> {
    let value = form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .find(|(key, _)| key == "limit")
        .map(|(_, value)| value);
    match value.as_deref() {
        None | Some("") => Ok(100),
        Some(value) => value
            .parse()
            .ok()
            .filter(|limit| (1..=1000).contains(limit))
            .ok_or(Problem::Malformed(
                "limit must be an integer from 1 through 1000",
            )),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    priority: Option<u32>,
    action: Option<String>,
    selector: Option<selector::Object<selector::Input>>,
    description: Option<String>,
    #[serde(default, deserialize_with = "enabled")]
    enabled: Option<bool>,
}

fn enabled<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<Option<bool>, D::Error> {
    Ok(Some(Option::<bool>::deserialize(decoder)?.unwrap_or(false)))
}

struct Rule {
    priority: u32,
    action: String,
    selector: Value,
    selector_json: String,
    description: String,
    enabled: bool,
}

async fn decode_request(request: Request<Incoming>, create: bool) -> Result<Rule, Problem> {
    let mut headers = request.headers().get_all(header::CONTENT_TYPE).iter();
    let media = headers
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<mime::Mime>().ok());
    if headers.next().is_some()
        || !media.is_some_and(|media| media.essence_str() == "application/json")
    {
        return Err(Problem::UnsupportedMedia);
    }
    let bytes = Limited::new(request.into_body(), MAX_BODY)
        .collect()
        .await
        .map_err(|error| {
            if error.is::<LengthLimitError>() {
                Problem::Large
            } else {
                Problem::Malformed("could not read request body")
            }
        })?
        .to_bytes();
    parse_rule(&bytes, create)
}

fn parse_rule(bytes: &[u8], create: bool) -> Result<Rule, Problem> {
    let selector::Object(input) = serde_json::from_slice::<selector::Object<Input>>(bytes)
        .map_err(|_| Problem::Malformed("malformed JSON request"))?;
    if create && input.enabled.is_some() {
        return Err(Problem::Malformed("malformed JSON request"));
    }
    let action = input.action.unwrap_or_default();
    if !matches!(action.as_str(), "accept" | "deny") {
        return Err(Problem::Malformed("action must be accept or deny"));
    }
    let selector: TrafficSelector = input
        .selector
        .ok_or(Problem::Malformed("selector is required"))?
        .0
        .try_into()
        .map_err(|_| Problem::Malformed("selector must be strict TrafficSelector protojson"))?;
    selector::validate(&selector).map_err(|error| Problem::Selector(error.to_string()))?;
    let selector = selector::canonical(&selector);
    let selector_json = selector.to_string();
    let description = input.description.unwrap_or_default();
    if selector_json.len() > MAX_SELECTOR || description.len() > 1024 || description.contains('\0')
    {
        return Err(Problem::Malformed("invalid request"));
    }
    Ok(Rule {
        priority: input.priority.unwrap_or_default(),
        action,
        selector,
        selector_json,
        description,
        enabled: create || input.enabled.unwrap_or(false),
    })
}

enum Operation {
    List(Id, usize),
    Create(Id, Rule),
    Update(Id, Rule),
    Delete(Id),
}

fn apply(
    store: &mut Store,
    actor: Id,
    operation: Operation,
    canceled: &AtomicBool,
) -> Result<(StatusCode, Value), Problem> {
    if canceled.load(Relaxed) {
        return Err(Problem::Internal);
    }
    let tx = store.enrollment_transaction()?;
    let root: Vec<u8> = tx.query_row(
        "SELECT root_service_principal_id FROM administrator_auth_state WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if root.as_slice() != actor.as_bytes() {
        return Err(Problem::Unauthenticated);
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let result = match operation {
        Operation::List(network, limit) => (StatusCode::OK, list(&tx, network, limit)?),
        Operation::Create(network, rule) => {
            network_epoch(&tx, network)?;
            let id = random_id()?;
            tx.execute(
                "INSERT INTO acl_rules (id,network_id,priority,action,selector_json,description,enabled,created_at,updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,1,?7,?7)",
                params![id.as_bytes(), network.as_bytes(), rule.priority, rule.action, rule.selector_json, rule.description, now],
            )?;
            let epoch = mutate_effect(&tx, actor, network, id, "acl_rule.create", "{}", now)?;
            (StatusCode::CREATED, rule.response(id, network, epoch))
        }
        Operation::Update(id, rule) => {
            let network = rule_network(&tx, id)?;
            tx.execute(
                "UPDATE acl_rules SET priority=?1,action=?2,selector_json=?3,description=?4,enabled=?5,updated_at=?6 WHERE id=?7",
                params![rule.priority, rule.action, rule.selector_json, rule.description, rule.enabled, now, id.as_bytes()],
            )?;
            let details = if rule.enabled {
                r#"{"enabled":true}"#
            } else {
                r#"{"enabled":false}"#
            };
            let epoch = mutate_effect(&tx, actor, network, id, "acl_rule.update", details, now)?;
            (StatusCode::OK, rule.response(id, network, epoch))
        }
        Operation::Delete(id) => {
            let network = rule_network(&tx, id)?;
            tx.execute("DELETE FROM acl_rules WHERE id=?1", [id.as_bytes()])?;
            let epoch = mutate_effect(&tx, actor, network, id, "acl_rule.delete", "{}", now)?;
            (StatusCode::OK, json!({"configuration_epoch":epoch}))
        }
    };
    if canceled.load(Relaxed) {
        return Err(Problem::Internal);
    }
    tx.commit()?;
    Ok(result)
}

impl Rule {
    fn response(&self, id: Id, network: Id, epoch: u64) -> Value {
        json!({
            "rule_id": id.to_string(), "network_id": network.to_string(), "priority": self.priority,
            "action": self.action, "selector": self.selector, "description": self.description,
            "enabled": self.enabled, "configuration_epoch": epoch,
        })
    }
}

fn list(tx: &Transaction<'_>, network: Id, limit: usize) -> Result<Value, Problem> {
    let epoch = network_epoch(tx, network)?;
    let mut statement = tx.prepare(
        "SELECT id,priority,action,selector_json,description,enabled
         FROM acl_rules WHERE network_id=?1 ORDER BY priority,id LIMIT ?2",
    )?;
    let mut rows = statement.query(params![network.as_bytes(), limit])?;
    let mut rules = Vec::new();
    while let Some(row) = rows.next()? {
        let id: Vec<u8> = row.get(0)?;
        let id = Id::from_slice(&id).map_err(|_| Problem::Internal)?;
        let text: String = row.get(3)?;
        let selector: Value = serde_json::from_str(&text).map_err(|_| Problem::Internal)?;
        let priority: u32 = row.get(1)?;
        let action: String = row.get(2)?;
        let description: String = row.get(4)?;
        let enabled: bool = row.get(5)?;
        rules.push(json!({
            "rule_id": id.to_string(), "network_id": network.to_string(), "priority": priority,
            "action": action, "selector": selector, "description": description,
            "enabled": enabled, "configuration_epoch": epoch,
        }));
    }
    Ok(json!({"acl_rules": rules}))
}

fn network_epoch(tx: &Transaction<'_>, network: Id) -> Result<u64, Problem> {
    tx.query_row(
        "SELECT configuration_epoch FROM networks WHERE id=?1",
        [network.as_bytes()],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(Problem::Missing)
}

fn rule_network(tx: &Transaction<'_>, id: Id) -> Result<Id, Problem> {
    let raw: Vec<u8> = tx
        .query_row(
            "SELECT network_id FROM acl_rules WHERE id=?1",
            [id.as_bytes()],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(Problem::Missing)?;
    Id::from_slice(&raw).map_err(|_| Problem::Internal)
}

fn mutate_effect(
    tx: &Transaction<'_>,
    actor: Id,
    network: Id,
    rule: Id,
    action: &str,
    details: &str,
    now: i64,
) -> Result<u64, Problem> {
    let epoch: u64 = tx
        .query_row(
            "UPDATE networks SET configuration_epoch=configuration_epoch+1
         WHERE id=?1 AND configuration_epoch < 9223372036854775807 RETURNING configuration_epoch",
            [network.as_bytes()],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(Problem::Conflict)?;
    tx.execute(
        "INSERT INTO audit_events (id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
         VALUES (?1,?2,'service_principal',?3,?4,'acl_rule',?5,?6,?7)",
        params![random_id()?.as_bytes(), network.as_bytes(), actor.as_bytes(), action, rule.as_bytes(), details, now],
    )?;
    Ok(epoch)
}

fn random_id() -> Result<Id> {
    loop {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).context("generate ACL identifier")?;
        if let Ok(id) = Id::new(bytes) {
            return Ok(id);
        }
    }
}

#[derive(Debug)]
enum Problem {
    Unauthenticated,
    Missing,
    Conflict,
    Malformed(&'static str),
    Selector(String),
    Method(&'static str),
    UnsupportedMedia,
    Large,
    Internal,
}

impl Problem {
    fn response(self, request_id: &str) -> Reply {
        let (status, code, detail) = match &self {
            Self::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                "ERROR_CODE_UNAUTHENTICATED",
                "authentication failed",
            ),
            Self::Missing => (
                StatusCode::NOT_FOUND,
                "ERROR_CODE_MALFORMED",
                "record not found",
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "ERROR_CODE_PERMISSION_DENIED",
                "request conflicts with controller state",
            ),
            Self::Malformed(detail) => (StatusCode::BAD_REQUEST, "ERROR_CODE_MALFORMED", *detail),
            Self::Selector(detail) => (
                StatusCode::BAD_REQUEST,
                "ERROR_CODE_MALFORMED",
                detail.as_str(),
            ),
            Self::Method(_) => (
                StatusCode::METHOD_NOT_ALLOWED,
                "ERROR_CODE_MALFORMED",
                "method not allowed",
            ),
            Self::UnsupportedMedia => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "ERROR_CODE_MALFORMED",
                "Content-Type must be application/json",
            ),
            Self::Large => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "ERROR_CODE_RESOURCE_EXHAUSTED",
                "request body exceeds limit",
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERROR_CODE_INTERNAL",
                "internal controller error",
            ),
        };
        let mut response = reply(
            status,
            json!({
                "code":code, "detail":detail, "retryable":status.is_server_error(), "request_id":request_id
            }),
        );
        if let Self::Method(allowed) = self {
            response
                .headers_mut()
                .insert(header::ALLOW, header::HeaderValue::from_static(allowed));
        }
        response
    }
}

impl From<anyhow::Error> for Problem {
    fn from(_: anyhow::Error) -> Self {
        Self::Internal
    }
}
impl From<rusqlite::Error> for Problem {
    fn from(_: rusqlite::Error) -> Self {
        Self::Internal
    }
}

fn reply(status: StatusCode, value: Value) -> Reply {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(value.to_string())))
        .expect("static ACL response metadata")
}

#[cfg(test)]
mod tests;
