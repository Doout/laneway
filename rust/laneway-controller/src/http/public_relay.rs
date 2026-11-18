use super::{AUTH, Failure, INTERNAL, State};
use hyper::{
    Method, Request, StatusCode,
    body::Incoming,
    header::{self, HeaderValue},
};
use laneway_controller::{
    PUBLIC_APPLICATION_SCHEME, SessionStore, enrollment::relay_configuration::RelayCredential,
};
use laneway_protocol::public_application;
use rustls::pki_types::CertificateDer;
use std::net::IpAddr;

const CLIENT_IP: &str = "x-laneway-public-client-ip";
const BUSY: Failure = Failure(
    StatusCode::SERVICE_UNAVAILABLE,
    "ERROR_CODE_RESOURCE_EXHAUSTED",
    "relay verification temporarily unavailable",
    true,
);

pub(super) async fn client_address(
    request: &mut Request<Incoming>,
    state: &State,
    direct: IpAddr,
) -> Result<IpAddr, Failure> {
    let headers = request.headers();
    let authorization = headers.get_all(header::AUTHORIZATION);
    // Only this ingress gate can assign the installation-only credential
    // context. Never accept an internal authorization scheme from the wire.
    if authorization.iter().any(|value| {
        value
            .to_str()
            .ok()
            .and_then(|raw| raw.split_once(' '))
            .is_some_and(|(scheme, _)| scheme == PUBLIC_APPLICATION_SCHEME)
    }) {
        return Err(AUTH);
    }
    let mut app_headers = headers.get_all(public_application::ACCESS_HEADER).iter();
    let application = app_headers.next();
    let mut values = headers.get_all(CLIENT_IP).iter();
    let Some(value) = values.next() else {
        if application.is_some() {
            return Err(AUTH);
        }
        return Ok(direct);
    };
    let path = request.uri().path();
    // Only console and application authorization endpoints delegate client
    // address. Transport-facing APIs continue to use the socket peer.
    if values.next().is_some()
        || !(path.starts_with("/v1/admin/")
            || path.starts_with("/oauth/")
            || path == "/applications/new"
            || path == "/v1/application-registrations/exchange")
    {
        return Err(AUTH);
    }
    let mut forwarded_auth = authorization.iter();
    if forwarded_auth.next().is_some_and(|auth| {
        application.is_some()
            || request.method() != Method::POST
            || !matches!(path, "/oauth/token" | "/oauth/revoke")
            || !auth.as_bytes().starts_with(b"Basic ")
    }) || forwarded_auth.next().is_some()
    {
        return Err(AUTH);
    }
    let application = if let Some(value) = application {
        if app_headers.next().is_some()
            || !public_application::route_allowed(request.method().as_str(), path)
            || headers.contains_key(header::COOKIE)
            || headers.contains_key(header::ORIGIN)
            || headers
                .keys()
                .any(|name| name.as_str().starts_with("sec-fetch-"))
        {
            return Err(AUTH);
        }
        let token = value
            .to_str()
            .ok()
            .and_then(public_application::candidate)
            .ok_or(AUTH)?;
        let mut value = HeaderValue::from_str(&format!("{PUBLIC_APPLICATION_SCHEME} {token}"))
            .map_err(|_| AUTH)?;
        value.set_sensitive(true);
        Some(value)
    } else {
        None
    };
    let client = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<IpAddr>().ok())
        .map(|value| value.to_canonical())
        .filter(|value| !value.is_unspecified() && !value.is_multicast())
        .ok_or(AUTH)?;
    let cert = request
        .extensions()
        .get::<CertificateDer<'static>>()
        .ok_or(AUTH)?
        .clone();
    let relay = RelayCredential::from_verified_peer(cert.as_ref()).map_err(|_| AUTH)?;
    let permit = state
        .queries
        .clone()
        .try_acquire_owned()
        .map_err(|_| BUSY)?;
    let database = state.database.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        SessionStore::open(&database)
            .map_err(|_| INTERNAL)?
            .check_relay_peer(&relay)
            .map_err(|_| AUTH)
    })
    .await
    .map_err(|_| INTERNAL)??;
    request.headers_mut().remove(CLIENT_IP);
    request
        .headers_mut()
        .remove(public_application::ACCESS_HEADER);
    if let Some(authorization) = application {
        request
            .headers_mut()
            .insert(header::AUTHORIZATION, authorization);
    }
    Ok(client)
}
