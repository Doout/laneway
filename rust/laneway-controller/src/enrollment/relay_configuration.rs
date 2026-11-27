//! Relay authorization is derived from the verified service leaf and its live
//! registration. Each snapshot and its epoch share one SQLite view.
use super::{
    EnrollError,
    configuration::{
        advertised_routes, certificate_health, clock, configuration_deadline, configuration_epoch,
        maintain_configuration, revocations,
    },
    snapshot_policy,
};
use crate::{
    SessionStore, check_snapshot,
    node_pki::{NodeIssuer, VerifiedCsr},
};
use anyhow::{Context, Result, ensure};
use laneway_protocol::v1::{RenewalRequest, RenewalResponse};
use laneway_protocol::{
    AuthenticatedIdentity, DEFAULT_MAX_CONTROL_PAYLOAD, Id, Role, identity_from_certificate_der,
    policy::prefix_from_wire,
    service_names,
    v1::{
        CertificateHealth, ConfigurationLease, IpPrefix, RelayConfiguration,
        RelayConfigurationRequest, RelayPeerAuthorization,
    },
};
use prost::Message;
use rusqlite::{Transaction, TransactionBehavior};
use std::collections::BTreeMap;

pub struct RelayCredential {
    identity: AuthenticatedIdentity,
    health: CertificateHealth,
}

pub enum RelayReply {
    Snapshot(RelayConfiguration),
    Lease(ConfigurationLease),
}

impl RelayCredential {
    /// The verified leaf comes from the TLS connection, not request headers.
    pub fn from_verified_peer(der: &[u8]) -> Result<Self> {
        let identity = identity_from_certificate_der(der).map_err(|_| EnrollError::Invalid)?;
        ensure!(identity.role == Role::Relay, EnrollError::Invalid);
        Ok(Self {
            identity,
            health: certificate_health(der)?,
        })
    }

    fn authorize(&self, tx: &Transaction<'_>, now: i64) -> Result<()> {
        ensure!(
            i64::try_from(self.health.not_after_unix_seconds)? > now,
            EnrollError::Denied
        );
        let enabled:bool=tx.query_row("SELECT
            EXISTS(SELECT 1 FROM relays WHERE network_id=?1 AND service_id=?2 AND enabled=1)
            AND NOT EXISTS(SELECT 1 FROM certificates WHERE network_id=?1 AND serial=?3 AND revoked_at IS NOT NULL)",
            (self.identity.network_id.as_bytes(),self.identity.subject_id.as_bytes(),&self.health.presented_serial),|r|r.get(0))?;
        ensure!(enabled, EnrollError::Denied);
        Ok(())
    }
}

impl SessionStore {
    pub fn renew_relay_tls(
        &mut self,
        verified_leaf: &[u8],
        req: RenewalRequest,
        issuer: &NodeIssuer,
    ) -> Result<RenewalResponse> {
        let peer = RelayCredential::from_verified_peer(verified_leaf)?;
        ensure!(
            req.wireguard_public_key.is_empty(),
            EnrollError::Malformed("relay renewal does not carry a WireGuard key")
        );
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now = clock(&tx)?;
        peer.authorize(&tx, now)?;
        ensure!(
            peer.health.renew_after_unix_seconds <= u64::try_from(now)?,
            EnrollError::Denied
        );
        let network = peer.identity.network_id;
        let service = peer.identity.subject_id;
        let recent: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM audit_events
            WHERE network_id=?1 AND created_at>=?2 AND action='relay.certificate_renew' AND target_id=?3)",
            (network.as_bytes(), now.saturating_sub(60), service.as_bytes()), |row| row.get(0))?;
        ensure!(!recent, EnrollError::Conflict);
        let names = service_names::from_der(verified_leaf)
            .map_err(|_| EnrollError::Invalid)?
            .into_iter()
            .map(|name| {
                Ok(match name {
                    service_names::Name::Dns(dns) => rcgen::SanType::DnsName(dns.try_into()?),
                    service_names::Name::Ip(ip) => rcgen::SanType::IpAddress(ip),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let csr = VerifiedCsr::parse(&req.pkcs10_csr_der)
            .map_err(|_| EnrollError::Malformed("invalid signed relay CSR"))?;
        let remaining = i64::try_from(peer.health.not_after_unix_seconds)?.saturating_sub(now);
        let chain = issuer.issue_relay(&csr, peer.identity, &names, now, remaining + 300)?;
        super::audit(
            &tx,
            network,
            None,
            "relay.certificate_renew",
            ("relay", service),
            serde_json::json!({"previous_serial":hex::encode(&peer.health.presented_serial),
                "expires_at_unix_seconds":chain.not_after_unix_seconds}),
            now,
        )?;
        tx.commit()?;
        Ok(RenewalResponse {
            certificate_chain: Some(chain),
            wireguard_public_key: Vec::new(),
        })
    }

    pub fn check_relay_peer(&mut self, peer: &RelayCredential) -> Result<()> {
        let tx = self.db.transaction()?;
        check_snapshot(&tx)?;
        peer.authorize(&tx, clock(&tx)?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn relay_configuration(
        &mut self,
        peer: &RelayCredential,
        req: RelayConfigurationRequest,
        validity: u64,
        cancelled: impl Fn() -> bool,
    ) -> Result<RelayReply> {
        let net = peer.identity.network_id;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now = clock(&tx)?;
        peer.authorize(&tx, now)?;
        ensure!(!cancelled(), "relay configuration cancelled");
        maintain_configuration(&tx, net, now)?;
        tx.commit()?;

        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now = clock(&tx)?;
        peer.authorize(&tx, now)?;
        let epoch = configuration_epoch(&tx, net, req.known_configuration_epoch)?;
        let end = configuration_deadline(&tx, net, now, validity, &peer.health)?;
        let valid_until_unix_seconds = end.try_into()?;
        let reply = if req.known_configuration_epoch == epoch {
            RelayReply::Lease(ConfigurationLease {
                configuration_epoch: epoch,
                valid_until_unix_seconds,
                ..Default::default()
            })
        } else {
            let mut policy = snapshot_policy::compile(&tx, net, epoch)?;
            crate::gateway_overlay::apply_policy(&tx, net, &mut policy)?;
            let cfg = RelayConfiguration {
                network_id: net.as_bytes().to_vec(),
                configuration_epoch: epoch,
                valid_until_unix_seconds,
                peers: authorizations(&tx, net, now)?,
                policy: Some(policy),
                revoked_certificate_serials: revocations(&tx, net, now)?,
                certificate_health: Some(peer.health.clone()),
            };
            ensure!(
                cfg.encoded_len() + 64 <= DEFAULT_MAX_CONTROL_PAYLOAD,
                "relay configuration exceeds frame limit"
            );
            RelayReply::Snapshot(cfg)
        };
        ensure!(
            clock(&tx)? < end && !cancelled(),
            "relay configuration expired or cancelled before publication"
        );
        tx.commit()?;
        Ok(reply)
    }
}

fn authorizations(tx: &Transaction<'_>, net: Id, now: i64) -> Result<Vec<RelayPeerAuthorization>> {
    let mut stmt=tx.prepare("SELECT n.id,a.address,a.prefix_length FROM nodes n
        JOIN overlay_addresses a ON a.node_id=n.id AND a.network_id=n.network_id AND a.released_at IS NULL
        WHERE n.network_id=?1 AND n.revoked_at IS NULL AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?2)
        ORDER BY n.id,a.address LIMIT 16385")?;
    let mut rows = stmt.query((net.as_bytes(), now))?;
    let mut peers = BTreeMap::new();
    let mut count = 0;
    while let Some(row) = rows.next()? {
        count += 1;
        ensure!(count <= 16384, "too many relay overlay addresses");
        let id: Vec<u8> = row.get(0)?;
        let id = Id::from_slice(&id)?;
        let address: Vec<u8> = row.get(1)?;
        let prefix = IpPrefix {
            address: address.clone(),
            prefix_length: row.get(2)?,
        };
        ensure!(
            prefix.prefix_length as usize == address.len() * 8,
            "invalid overlay host prefix"
        );
        prefix_from_wire(prefix.clone())?;
        let peer = peers.entry(id).or_insert_with(|| RelayPeerAuthorization {
            node_id: id.as_bytes().to_vec(),
            ..Default::default()
        });
        peer.overlay_addresses.push(address);
        peer.authorized_prefixes.push(prefix);
    }
    for route in advertised_routes(tx, net, now)? {
        if let Some(peer) = peers.get_mut(&Id::from_slice(&route.via_node_id)?) {
            peer.authorized_prefixes
                .push(route.destination.context("route missing prefix")?);
        }
    }
    Ok(peers.into_values().collect())
}
