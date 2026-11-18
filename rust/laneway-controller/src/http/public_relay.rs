use super::{AUTH, Failure, INTERNAL, State};
use hyper::{Request, StatusCode, body::Incoming};
use laneway_controller::{SessionStore, enrollment::relay_configuration::RelayCredential};
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
    let mut values = headers.get_all(CLIENT_IP).iter();
    let Some(value) = values.next() else {
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
    Ok(client)
}
