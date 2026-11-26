//! Stable-v1 reliable control streams. Enrollment and browser credentials never
//! enter this transport: the peer identity comes exclusively from mutual TLS.
use crate::http::State;
use anyhow::{Context, Result, ensure};
use laneway_controller::{
    SessionStore,
    enrollment::{
        EnrollError,
        configuration::ConfigurationError,
        relay_configuration::{RelayCredential, RelayReply},
        renewal::{NodeCredential, RenewalTransport},
    },
};
use laneway_protocol::{
    DEFAULT_MAX_CONTROL_PAYLOAD, Id, Role, identity_from_certificate_der,
    v1::{ControllerEnvelope, ErrorCode, ProtocolError, controller_envelope::Body},
};
use prost::Message;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rustls::pki_types::CertificateDer;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{task::JoinSet, time::timeout};

pub(super) fn config(tls: rustls::ServerConfig) -> Result<quinn::ServerConfig> {
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(1u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .max_idle_timeout(Some(Duration::from_secs(60).try_into()?))
        .keep_alive_interval(Some(Duration::from_secs(20)))
        .datagram_receive_buffer_size(None)
        .stream_receive_window((DEFAULT_MAX_CONTROL_PAYLOAD as u32 + 4).into())
        .receive_window((DEFAULT_MAX_CONTROL_PAYLOAD as u32 + 4).into());
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

type Exits = Arc<Mutex<HashMap<Id, Connection>>>;
#[derive(Clone)]
enum ControlPeer {
    Node(Arc<NodeCredential>),
    Relay(Arc<RelayCredential>),
}
struct Claim(Exits, Id, usize);
impl Drop for Claim {
    fn drop(&mut self) {
        if let Ok(mut exits) = self.0.lock()
            && exits
                .get(&self.1)
                .is_some_and(|active| active.stable_id() == self.2)
        {
            exits.remove(&self.1);
        }
    }
}
fn claim(exits: &Exits, node: Id, conn: &Connection, suspect: bool) -> Result<Claim> {
    let mut map = exits
        .lock()
        .map_err(|_| anyhow::anyhow!("control session lock failed"))?;
    if let Some(other) = map.get(&node) {
        ensure!(
            suspect || other.close_reason().is_some(),
            "ephemeral Exit already connected"
        );
        other.close(0x105u32.into(), b"superseded control session");
    }
    map.insert(node, conn.clone());
    Ok(Claim(exits.clone(), node, conn.stable_id()))
}

pub(super) async fn serve(ep: &Endpoint, network: Id, state: State) -> Result<()> {
    let mut connections = JoinSet::new();
    let exits = Exits::default();
    loop {
        tokio::select! {
            biased;
            Some(_)=connections.join_next(),if !connections.is_empty()=>{},
            incoming=ep.accept()=>{
                let incoming=incoming.context("controller UDP listener stopped")?;
                if connections.len()>=256 {incoming.refuse();continue;}
                let exits=exits.clone();
                let state=state.clone();
                connections.spawn(async move{
                    let Ok(Ok(conn))=timeout(Duration::from_secs(10),async{incoming.await}).await else{return};
                    if connection(&conn,network,state,exits).await.is_err(){
                        conn.close(0x103u32.into(),b"controller request not accepted");
                    }
                });
            }
        }
    }
}

async fn connection(conn: &Connection, network: Id, state: State, exits: Exits) -> Result<()> {
    let certs = conn
        .peer_identity()
        .and_then(|c| c.downcast::<Vec<CertificateDer<'static>>>().ok())
        .context("missing verified peer")?;
    let cert = certs.first().context("empty verified chain")?;
    let id = identity_from_certificate_der(cert.as_ref())?;
    ensure!(
        id.network_id == network,
        "peer is not in controller network"
    );
    let peer = match id.role {
        Role::Node => {
            ControlPeer::Node(Arc::new(NodeCredential::from_verified_peer(cert.as_ref())?))
        }
        Role::Relay => ControlPeer::Relay(Arc::new(RelayCredential::from_verified_peer(
            cert.as_ref(),
        )?)),
        _ => anyhow::bail!("client role is not allowed"),
    };
    let permit = state.queries.clone().try_acquire_owned()?;
    let admitted = {
        let db = state.database.clone();
        let peer = peer.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut store = SessionStore::open(&db)?;
            match peer {
                ControlPeer::Node(peer) => store.node_control_admission(&peer),
                ControlPeer::Relay(peer) => store.check_relay_peer(&peer).map(|_| None),
            }
        })
        .await??
    };
    let claim = admitted
        .map(|suspect| claim(&exits, id.subject_id, conn, suspect))
        .transpose()?;
    loop {
        let (send, recv) = conn.accept_bi().await?;
        tokio::select! {
            _=conn.closed()=>return Ok(()),
            result=timeout(Duration::from_secs(15),request(send,recv,&state,peer.clone(),conn,claim.is_some()))=>result??,
        }
    }
}

async fn request(
    mut send: SendStream,
    mut recv: RecvStream,
    state: &State,
    peer: ControlPeer,
    conn: &Connection,
    holds_exit_claim: bool,
) -> Result<()> {
    let mut prefix = [0; 4];
    recv.read_exact(&mut prefix).await?;
    let length = u32::from_be_bytes(prefix) as usize;
    ensure!(
        (1..=DEFAULT_MAX_CONTROL_PAYLOAD).contains(&length),
        "invalid control frame length"
    );
    let mut data = vec![0; length];
    recv.read_exact(&mut data).await?;
    ensure!(
        recv.read_to_end(0).await?.is_empty(),
        "trailing control data"
    );
    let envelope = ControllerEnvelope::decode(&data[..])?;
    ensure!(
        envelope.schema_version == 1 && envelope.request_id != 0,
        "invalid control envelope"
    );
    let operation = envelope.body.context("missing control operation")?;
    ensure!(
        matches!(
            (&peer, &operation),
            (
                ControlPeer::Node(_),
                Body::RenewalRequest(_) | Body::ConfigurationRequest(_)
            ) | (ControlPeer::Relay(_), Body::RelayConfigurationRequest(_))
        ),
        "unsupported control operation"
    );
    let issuer = state.issuer.clone();
    let locations = state.locations.clone();
    let validity = state.snapshot_validity;
    let body = if let Ok(permit) = state.queries.clone().try_acquire_owned() {
        let db = state.database.clone();
        let conn = conn.clone();
        let (cancel, _alive) = tokio::sync::oneshot::channel::<()>();
        match tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut store = SessionStore::open(&db)?;
            let cancelled = || cancel.is_closed() || conn.close_reason().is_some();
            match (peer, operation) {
                (ControlPeer::Node(peer), Body::RenewalRequest(req)) => store
                    .renew_certificate(
                        &peer,
                        req,
                        issuer.as_deref().context("node issuer unavailable")?,
                        RenewalTransport::Quic { holds_exit_claim },
                        cancelled,
                    )
                    .map(Body::RenewalResponse),
                (ControlPeer::Node(peer), Body::ConfigurationRequest(req)) => {
                    let snapshot = store.node_configuration(
                        &peer,
                        req,
                        holds_exit_claim,
                        validity,
                        cancelled,
                    )?;
                    if !cancelled() {
                        crate::http::record_presence(
                            &mut store,
                            &peer,
                            conn.remote_address().ip(),
                            locations.as_deref(),
                        );
                    }
                    Ok(snapshot)
                }
                (ControlPeer::Relay(peer), Body::RelayConfigurationRequest(req)) => store
                    .relay_configuration(&peer, req, validity, cancelled)
                    .map(|r| match r {
                        RelayReply::Snapshot(cfg) => Body::RelayConfiguration(cfg),
                        RelayReply::Lease(lease) => Body::ConfigurationLease(lease),
                    }),
                _ => anyhow::bail!("unsupported operation"),
            }
        })
        .await?
        {
            Ok(r) => r,
            Err(e) => {
                let (code, detail, retry) = match e.downcast_ref::<EnrollError>() {
                    Some(EnrollError::Invalid | EnrollError::Expired) => {
                        (ErrorCode::Unauthenticated, "invalid credential", false)
                    }
                    Some(EnrollError::Malformed(_)) => {
                        (ErrorCode::Malformed, "malformed control request", false)
                    }
                    Some(EnrollError::Denied | EnrollError::Conflict) => {
                        (ErrorCode::PermissionDenied, "control request denied", false)
                    }
                    _ if e.is::<ConfigurationError>() => {
                        match e.downcast_ref::<ConfigurationError>().unwrap() {
                            ConfigurationError::StaleEpoch => (
                                ErrorCode::StaleEpoch,
                                "known epoch is ahead of controller",
                                false,
                            ),
                        }
                    }
                    _ => (ErrorCode::Internal, "internal controller error", true),
                };
                error(code, detail, retry)
            }
        }
    } else {
        error(ErrorCode::ResourceExhausted, "controller busy", true)
    };
    let response = ControllerEnvelope {
        schema_version: 1,
        request_id: envelope.request_id,
        body: Some(body),
    }
    .encode_to_vec();
    ensure!(
        response.len() <= DEFAULT_MAX_CONTROL_PAYLOAD,
        "oversized controller response"
    );
    send.write_all(&(response.len() as u32).to_be_bytes())
        .await?;
    send.write_all(&response).await?;
    send.finish()?;
    Ok(())
}
fn error(code: ErrorCode, detail: &str, retryable: bool) -> Body {
    Body::Error(ProtocolError {
        code: code as i32,
        detail: detail.into(),
        retryable,
    })
}
