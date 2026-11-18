use super::{
    Credential, Failure, INTERNAL, Reply, State, credential, malformed, query_limit, response,
    valid_query_field, with_session_headers,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming};
use laneway_controller::{
    ListError, SessionStore,
    audit::{AuditQuery, Cursor, CursorError, bearer_audit},
};
use laneway_protocol::Id;

pub(super) struct Route<'a> {
    network: Option<&'a str>,
    paged: bool,
}

impl<'a> Route<'a> {
    pub(super) fn parse(path: &[&'a str]) -> Option<Self> {
        let (network, paged) = match path {
            ["", "v1", "admin", "audit"] => (None, false),
            ["", "v1", "admin", "audit", "page"] => (None, true),
            ["", "v1", "admin", "networks", net, "audit"] => (Some(*net), false),
            ["", "v1", "admin", "networks", net, "audit", "page"] => (Some(*net), true),
            _ => return None,
        };
        Some(Self { network, paged })
    }

    fn query(self, query: Option<&str>) -> anyhow::Result<AuditQuery> {
        let network = self
            .network
            .map(str::parse::<Id>)
            .transpose()
            .map_err(|_| ListError::NetworkId)?;
        let (limit, before) = if self.paged {
            parse_page_query(query.unwrap_or_default(), network)?
        } else {
            (query_limit(query)?, None)
        };
        Ok(AuditQuery {
            network,
            limit,
            before,
            paged: self.paged,
        })
    }
}

fn parse_page_query(query: &str, network: Option<Id>) -> anyhow::Result<(usize, Option<Cursor>)> {
    if !query.split('&').all(valid_query_field) {
        return Err(malformed("audit query is malformed").into());
    }
    let (mut limit, mut cursor) = (None, None);
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        let slot = match key.as_ref() {
            "limit" => &mut limit,
            "cursor" => &mut cursor,
            _ => return Err(malformed("audit query supports only limit and cursor").into()),
        };
        if slot.replace(value).is_some() {
            return Err(malformed("audit query parameters must not be repeated").into());
        }
    }
    let limit = limit
        .filter(|v| !v.is_empty())
        .map(|v| v.parse::<usize>().map_err(|_| ListError::Limit))
        .transpose()?
        .unwrap_or(100);
    if !(1..=1000).contains(&limit) {
        return Err(ListError::Limit.into());
    }
    let before = match cursor {
        Some(value) if value.is_empty() => {
            return Err(malformed("cursor must be a non-empty opaque audit cursor").into());
        }
        Some(value) => Some(Cursor::decode(&value, network)?),
        None => None,
    };
    Ok((limit, before))
}

pub(super) async fn handle(
    req: Request<Incoming>,
    state: State,
    id: &str,
    route: Route<'_>,
) -> Result<Reply, Failure> {
    let head = req.method() == Method::HEAD;
    if !head && req.method() != Method::GET {
        return Err(Failure(
            S::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
            false,
        ));
    }
    let auth = credential(req.headers())?;
    let query = route.query(req.uri().query());
    let permit = state.queries.try_acquire_owned().map_err(|_| {
        Failure(
            S::SERVICE_UNAVAILABLE,
            "ERROR_CODE_RESOURCE_EXHAUSTED",
            "controller busy",
            true,
        )
    })?;
    let (data, meta) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _permit = permit;
        let (page, meta) = match auth {
            Credential::Session(token) => {
                let r = SessionStore::open(&state.database)?.audit(&token, query)?;
                (r.list, Some((r.id, r.idle, r.absolute)))
            }
            Credential::Bearer(header) => (
                bearer_audit(&state.database, &header, state.root.as_deref(), query)?,
                None,
            ),
        };
        Ok((serde_json::to_vec(&page)?, meta))
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    with_session_headers(response(S::OK, id, data, head), meta)
}

fn failure(err: anyhow::Error) -> Failure {
    match err.downcast_ref::<ListError>() {
        Some(ListError::NetworkId) => return malformed("invalid network_id"),
        Some(ListError::Limit) => return malformed("limit must be an integer from 1 through 1000"),
        Some(ListError::Missing) => {
            return Failure(
                S::NOT_FOUND,
                "ERROR_CODE_MALFORMED",
                "record not found",
                false,
            );
        }
        None => {}
    }
    match err.downcast_ref::<CursorError>() {
        Some(CursorError::Invalid) => malformed("cursor is not a valid opaque audit cursor"),
        Some(CursorError::Scope) => malformed("cursor does not belong to this audit scope"),
        None => super::access_admin::failure(err),
    }
}
