use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use laneway_protocol::{
    AuthenticatedIdentity, DEFAULT_MAX_CONTROL_PAYLOAD, Id, Role, identity_from_certificate_der,
    v1::{ControllerEnvelope, ErrorCode, ProtocolError, controller_envelope::Body},
};
use prost::Message;
use quinn::{
    Connection, Endpoint, RecvStream, SendStream, TransportConfig, crypto::rustls::QuicServerConfig,
};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::CertificateDer,
    server::WebPkiClientVerifier,
    sign::{CertifiedKey, SingleCertAndKey},
    version::TLS13,
};
use tokio::{net::lookup_host, sync::Semaphore, time::timeout};
use x509_parser::parse_x509_certificate;

use crate::{enrollment, serve_enrollment::Enrollment, snapshots, store::Store};

const ALPN: &[u8] = b"laneway-control/1";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CONNECTIONS: usize = 256;
const AUTHENTICATION: u32 = 0x102;
const INVALID_REQUEST: u32 = 0x103;

pub(crate) async fn listen(
    address: &str,
    certificate: CertifiedKey,
    roots: RootCertStore,
) -> Result<Endpoint> {
    let address = if address.starts_with(':') {
        format!("0.0.0.0{address}")
    } else {
        address.to_owned()
    };
    let address = lookup_host(address)
        .await?
        .next()
        .context("QUIC address did not resolve")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .context("configure mandatory QUIC client authentication")?;
    let mut tls = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certificate)));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;

    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(1_u32.into())
        .max_concurrent_uni_streams(0_u32.into())
        .max_idle_timeout(Some(Duration::from_secs(60).try_into()?))
        .keep_alive_interval(Some(Duration::from_secs(20)))
        .stream_receive_window(((DEFAULT_MAX_CONTROL_PAYLOAD + 4) as u32).into())
        .datagram_receive_buffer_size(None)
        .datagram_send_buffer_size(0);
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    config.transport_config(Arc::new(transport));
    Endpoint::server(config, address).context("bind authenticated controller QUIC listener")
}

pub(crate) async fn serve(
    endpoint: Option<Endpoint>,
    network: Id,
    store: Arc<Mutex<Store>>,
    enrollment: Option<Arc<Enrollment>>,
) -> Result<()> {
    let Some(endpoint) = endpoint else {
        return std::future::pending().await;
    };
    let enrollment = enrollment.context("QUIC server requires validated enrollment authority")?;
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let workers = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    while let Some(incoming) = endpoint.accept().await {
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
        let store = store.clone();
        let enrollment = enrollment.clone();
        let workers = workers.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let Ok(Ok(connection)) = timeout(HANDSHAKE_TIMEOUT, async { incoming.await }).await
            else {
                return;
            };
            serve_connection(connection, network, store, enrollment, workers).await;
        });
    }
    Ok(())
}

async fn serve_connection(
    connection: Connection,
    network: Id,
    store: Arc<Mutex<Store>>,
    enrollment: Arc<Enrollment>,
    workers: Arc<Semaphore>,
) {
    let peer = match Peer::from_connection(&connection, network) {
        Ok(peer) => Arc::new(peer),
        Err(_) => {
            connection.close(
                AUTHENTICATION.into(),
                b"client identity is outside controller network or role",
            );
            return;
        }
    };
    while let Ok((mut send, mut receive)) = connection.accept_bi().await {
        let canceled = CancelOnDrop(Arc::new(AtomicBool::new(false)));
        let result = timeout(
            REQUEST_TIMEOUT,
            exchange(
                &mut send,
                &mut receive,
                peer.clone(),
                store.clone(),
                enrollment.clone(),
                canceled.0.clone(),
                workers.clone(),
            ),
        )
        .await;
        if !matches!(result, Ok(Ok(()))) {
            let _ = receive.stop(INVALID_REQUEST.into());
            let _ = send.reset(INVALID_REQUEST.into());
            connection.close(INVALID_REQUEST.into(), b"invalid controller request");
            return;
        }
    }
}

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

struct Peer {
    identity: AuthenticatedIdentity,
    leaf: CertificateDer<'static>,
    not_before: i64,
    not_after: i64,
}

impl Peer {
    fn from_connection(connection: &Connection, network: Id) -> Result<Self> {
        let certificates = connection
            .peer_identity()
            .context("verified client certificate required")?
            .downcast::<Vec<CertificateDer<'static>>>()
            .map_err(|_| anyhow::anyhow!("unexpected QUIC peer identity"))?;
        let leaf = certificates
            .first()
            .context("verified client leaf is missing")?
            .clone();
        let identity = identity_from_certificate_der(leaf.as_ref())?;
        ensure!(
            identity.network_id == network && matches!(identity.role, Role::Node | Role::Relay),
            "QUIC client identity is outside controller authority"
        );
        let (_, x509) = parse_x509_certificate(leaf.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid QUIC client certificate"))?;
        let not_before = x509.validity().not_before.timestamp();
        let not_after = x509.validity().not_after.timestamp();
        Ok(Self {
            identity,
            leaf,
            not_before,
            not_after,
        })
    }

    fn currently_valid(&self, now: i64) -> bool {
        self.not_before <= now && now < self.not_after
    }
}

async fn exchange(
    send: &mut SendStream,
    receive: &mut RecvStream,
    peer: Arc<Peer>,
    store: Arc<Mutex<Store>>,
    enrollment: Arc<Enrollment>,
    canceled: Arc<AtomicBool>,
    workers: Arc<Semaphore>,
) -> Result<()> {
    ensure!(
        peer.currently_valid(now()?),
        "client certificate is outside its validity interval"
    );
    let mut prefix = [0; 4];
    receive.read_exact(&mut prefix).await?;
    let length = frame_length(prefix)?;
    let mut payload = vec![0; length];
    receive.read_exact(&mut payload).await?;
    ensure!(
        receive.read_to_end(0).await?.is_empty(),
        "trailing request bytes"
    );
    let (request_id, body) = decode_request(&payload, peer.identity.role)?;
    let validity = peer.clone();
    let response = if let Ok(worker) = workers.try_acquire_owned() {
        tokio::task::spawn_blocking(move || {
            let _worker = worker;
            let Ok(mut store) = store.lock() else {
                return internal();
            };
            let Ok(now) = now() else {
                return internal();
            };
            if canceled.load(Ordering::Acquire) {
                return internal();
            }
            dispatch(&mut store, &enrollment, &peer, now, body, &canceled)
        })
        .await?
    } else {
        protocol_error(
            ErrorCode::ResourceExhausted,
            "controller request capacity exhausted",
            true,
        )
    };
    ensure!(
        validity.currently_valid(now()?),
        "client certificate expired during operation"
    );
    let response = ControllerEnvelope {
        schema_version: 1,
        request_id,
        body: Some(response),
    };
    let length = response.encoded_len();
    ensure!(
        length > 0 && length <= DEFAULT_MAX_CONTROL_PAYLOAD,
        "controller response exceeds frame limit"
    );
    send.write_all(&(length as u32).to_be_bytes()).await?;
    send.write_all(&response.encode_to_vec()).await?;
    send.finish()?;
    Ok(())
}

pub(crate) fn now() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}

fn frame_length(prefix: [u8; 4]) -> Result<usize> {
    let length = u32::from_be_bytes(prefix) as usize;
    ensure!(
        length > 0 && length <= DEFAULT_MAX_CONTROL_PAYLOAD,
        "invalid QUIC frame length"
    );
    Ok(length)
}

fn decode_request(payload: &[u8], role: Role) -> Result<(u64, Body)> {
    let request = ControllerEnvelope::decode(payload).context("decode controller QUIC envelope")?;
    ensure!(
        request.schema_version == 1 && request.request_id != 0,
        "invalid controller schema version or request ID"
    );
    let body = request.body.context("controller request body is missing")?;
    let required = match body {
        Body::ConfigurationRequest(_) | Body::RenewalRequest(_) => Role::Node,
        Body::RelayConfigurationRequest(_) => Role::Relay,
        _ => bail!("unsupported controller QUIC operation"),
    };
    ensure!(
        role == required,
        "controller operation is not permitted for client certificate role"
    );
    Ok((request.request_id, body))
}

fn dispatch(
    store: &mut Store,
    enrollment: &Enrollment,
    peer: &Peer,
    now: i64,
    body: Body,
    canceled: &AtomicBool,
) -> Body {
    if !peer.currently_valid(now) {
        return protocol_error(ErrorCode::PermissionDenied, "permission denied", false);
    }
    // Snapshot and renewal handlers revalidate durable authorization in the
    // same transaction as their operation. The shared mutex covers dispatch.
    match body {
        Body::ConfigurationRequest(request) => snapshots::node(
            store,
            peer.leaf.as_ref(),
            request.known_configuration_epoch,
            now,
        )
        .unwrap_or_else(|error| protocol_error(error.code, error.detail, error.retryable)),
        Body::RelayConfigurationRequest(request) => snapshots::relay(
            store,
            peer.leaf.as_ref(),
            request.known_configuration_epoch,
            now,
        )
        .unwrap_or_else(|error| protocol_error(error.code, error.detail, error.retryable)),
        Body::RenewalRequest(request) => enrollment::renew(
            store,
            &enrollment.authority,
            peer.leaf.as_ref(),
            request,
            canceled,
        )
        .map(Body::RenewalResponse)
        .unwrap_or_else(|error| protocol_error(error.code, error.detail, error.retryable)),
        _ => internal(),
    }
}

fn protocol_error(code: ErrorCode, detail: &str, retryable: bool) -> Body {
    Body::Error(ProtocolError {
        code: code as i32,
        detail: detail.to_owned(),
        retryable,
    })
}

fn internal() -> Body {
    protocol_error(ErrorCode::Internal, "internal controller error", true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use laneway_protocol::v1::{
        ConfigurationRequest, EnrollmentRequest, RelayConfigurationRequest,
    };

    #[test]
    fn validates_frame_bounds_and_schema_before_dispatch() {
        assert!(frame_length([0; 4]).is_err());
        assert!(frame_length(((DEFAULT_MAX_CONTROL_PAYLOAD + 1) as u32).to_be_bytes()).is_err());
        assert_eq!(
            frame_length((DEFAULT_MAX_CONTROL_PAYLOAD as u32).to_be_bytes()).unwrap(),
            DEFAULT_MAX_CONTROL_PAYLOAD
        );
        assert!(decode_request(&[0xff], Role::Node).is_err());
        let mut request = ControllerEnvelope {
            schema_version: 1,
            request_id: 0,
            body: Some(Body::ConfigurationRequest(ConfigurationRequest::default())),
        };
        assert!(decode_request(&request.encode_to_vec(), Role::Node).is_err());
        request.request_id = 19;
        assert_eq!(
            decode_request(&request.encode_to_vec(), Role::Node)
                .unwrap()
                .0,
            19
        );
        assert!(decode_request(&request.encode_to_vec(), Role::Relay).is_err());
        request.body = Some(Body::RelayConfigurationRequest(
            RelayConfigurationRequest::default(),
        ));
        assert!(decode_request(&request.encode_to_vec(), Role::Relay).is_ok());
        assert!(decode_request(&request.encode_to_vec(), Role::Controller).is_err());
        request.body = Some(Body::EnrollmentRequest(EnrollmentRequest::default()));
        assert!(decode_request(&request.encode_to_vec(), Role::Node).is_err());
        request.body = None;
        assert!(decode_request(&request.encode_to_vec(), Role::Node).is_err());
    }

    #[test]
    fn rejects_connection_certificate_at_expiry_boundary() {
        let peer = Peer {
            identity: AuthenticatedIdentity {
                network_id: Id::from_slice(&[1; 16]).unwrap(),
                subject_id: Id::from_slice(&[2; 16]).unwrap(),
                role: Role::Node,
            },
            leaf: CertificateDer::from(vec![2]),
            not_before: 10,
            not_after: 90,
        };
        assert!(!peer.currently_valid(9));
        assert!(peer.currently_valid(10));
        assert!(peer.currently_valid(89));
        assert!(!peer.currently_valid(90));
    }
}
