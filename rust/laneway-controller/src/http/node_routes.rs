use super::{
    AUTH, Failure, INTERNAL, Reply, State,
    access_admin::{failure, parse},
    form::required_json_form,
    malformed,
    mutations::DENIED,
    response,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    SessionStore,
    access_admin::{NodeRouteRequest, RouteKind, RouteMode, RouteSpec},
    enrollment::{EnrollError, renewal::NodeCredential},
};
use rustls::pki_types::CertificateDer;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdvertiseForm {
    prefix: String,
    kind: RouteKind,
    mode: RouteMode,
    #[serde(default)]
    metric: u32,
    #[serde(default)]
    valid_until_unix_seconds: i64,
}

pub(super) async fn handle(
    mut req: Request<Incoming>,
    state: State,
    id: &str,
    route: Option<&str>,
) -> Result<Reply, Failure> {
    let (expected, allow, status) = if route.is_some() {
        (Method::DELETE, "DELETE", S::OK)
    } else {
        (Method::POST, "POST", S::CREATED)
    };
    if *req.method() != expected {
        let mut reply = Failure(
            S::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
            false,
        )
        .reply(id, req.method() == Method::HEAD);
        reply
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static(allow));
        return Ok(reply);
    }
    let leaf = req
        .extensions_mut()
        .remove::<CertificateDer<'static>>()
        .ok_or(AUTH)?;
    let peer = NodeCredential::from_verified_peer(leaf.as_ref()).map_err(|_| AUTH)?;
    let request = decode(req, route).await.map_err(anyhow::Error::from);
    let permit = state
        .queries
        .try_acquire_owned()
        .map_err(|_| crate::http::QUERY_BUSY)?;
    let data = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut store = SessionStore::open(&state.database)?;
        store.node_route(&peer, request)
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(|err| match err.downcast_ref::<EnrollError>() {
        Some(EnrollError::Denied) => DENIED,
        Some(EnrollError::Invalid) => AUTH,
        _ => failure(err),
    })?;
    Ok(response(
        status,
        id,
        serde_json::to_vec(&data).map_err(|_| INTERNAL)?,
        false,
    ))
}

async fn decode(req: Request<Incoming>, route: Option<&str>) -> Result<NodeRouteRequest, Failure> {
    if let Some(route) = route {
        return Ok(NodeRouteRequest::Withdraw(parse(route)?));
    }
    let f = required_json_form::<AdvertiseForm>(req).await?;
    let prefix: ipnet::IpNet = f
        .prefix
        .parse()
        .map_err(|_| malformed("invalid route prefix"))?;
    if prefix.to_string() != f.prefix {
        return Err(malformed("prefix must be a canonical CIDR prefix"));
    }
    Ok(NodeRouteRequest::Advertise(
        RouteSpec {
            prefix,
            mode: f.mode,
            metric: f.metric,
        },
        f.kind,
        (f.valid_until_unix_seconds != 0).then_some(f.valid_until_unix_seconds),
    ))
}
