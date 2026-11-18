//! Best-effort opt-in topology from real, authorized ingress; no active probes.
use crate::{
    controller::{Client, Snapshot},
    state::State,
};
use anyhow::Result;
use bytes::Bytes;
use laneway_protocol::{
    Id,
    topology::{MAX_PEERS, Path, Peer, Report, TTL_SECONDS},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Default)]
pub(crate) struct Observations(Mutex<HashMap<Id, Contact>>);

struct Contact {
    when: Instant,
    unix_seconds: i64,
    path: Path,
    direct_serial: Option<Bytes>,
}

impl Observations {
    pub(crate) fn received(&self, peer: Id, direct_serial: Option<Bytes>) {
        let when = Instant::now();
        let Ok(since_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return;
        };
        let Ok(unix_seconds) = i64::try_from(since_epoch.as_secs()) else {
            return;
        };
        let path = if direct_serial.is_some() {
            Path::Direct
        } else {
            Path::Relay
        };
        self.store(
            peer,
            Contact {
                when,
                unix_seconds,
                path,
                direct_serial,
            },
        );
    }

    fn store(&self, peer: Id, contact: Contact) {
        // Telemetry must not block packet delivery or retain unbounded peers.
        let Ok(mut contacts) = self.0.try_lock() else {
            return;
        };
        if let Some(old) = contacts.get(&peer) {
            if old.when > contact.when {
                return;
            }
        } else if contacts.len() >= MAX_PEERS
            && let Some((&oldest, _)) = contacts.iter().min_by_key(|(id, old)| (old.when, **id))
        {
            contacts.remove(&oldest);
        }
        contacts.insert(peer, contact);
    }

    pub(crate) fn report(&self, snapshot: Option<&Snapshot>) -> Report {
        let live = snapshot.filter(|s| !s.local_certificate_revoked && !s.expired());
        let mut report = Report {
            enabled: true,
            peers: Vec::new(),
        };
        if let Ok(mut contacts) = self.0.lock() {
            let monotonic = Instant::now();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|v| i64::try_from(v.as_secs()).ok())
                .unwrap_or(0);
            contacts.retain(|peer, c| {
                live.is_some_and(|s| {
                    s.peers.contains_key(peer)
                        && !c.direct_serial.as_ref().is_some_and(|serial| {
                            s.revoked_serials.contains::<[u8]>(serial.as_ref())
                        })
                }) && monotonic.saturating_duration_since(c.when)
                    < Duration::from_secs(TTL_SECONDS as u64)
                    && c.unix_seconds > now.saturating_sub(TTL_SECONDS)
                    && c.unix_seconds <= now
            });
            report.peers.extend(contacts.iter().map(|(id, c)| Peer {
                peer_id: id.to_string(),
                path: c.path,
                latency_ms: None, // QUIC relay RTT is not end-to-end peer RTT.
                last_contact_unix_seconds: c.unix_seconds,
            }));
            report
                .peers
                .sort_unstable_by(|a, b| a.peer_id.cmp(&b.peer_id));
        }
        report
    }
}

pub(crate) async fn run(client: Arc<Client>, state: Arc<State>) -> Result<()> {
    let mut pulse = tokio::time::interval(Duration::from_secs(30));
    pulse.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        pulse.tick().await;
        let Some(observations) = &state.topology else {
            return Ok(());
        };
        let current = state.authority_snapshot();
        let report = observations.report(current.as_deref());
        if let Err(error) = client.report_topology(&report).await {
            // Reporting never changes authority, readiness, or forwarding.
            tracing::debug!(%error, "node topology report not delivered");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::{CandidateExchangeAuthority, Peer as AuthorizedPeer};
    use laneway_protocol::{
        policy::CompiledPolicy,
        v1::{PolicyAction, PolicySnapshot},
    };

    fn snapshot(peers: &[Id], now: i64) -> Snapshot {
        let network = Id::new([255; 16]).unwrap();
        let policy = CompiledPolicy::compile(
            PolicySnapshot {
                network_id: network.as_bytes().to_vec(),
                configuration_epoch: 1,
                default_action: PolicyAction::Deny as i32,
                rules: vec![],
            },
            network,
            1,
        )
        .unwrap();
        Snapshot {
            epoch: 1,
            valid_until: (now + 60) as u64,
            identity_lease_expires_at: 0,
            ephemeral_exit: None,
            overlays: vec![],
            peers: peers
                .iter()
                .map(|&id| {
                    (
                        id,
                        AuthorizedPeer {
                            node: id,
                            name: String::new(),
                            overlays: vec![],
                            wireguard_key: None,
                        },
                    )
                })
                .collect(),
            routes: vec![],
            policy,
            enabled_capabilities: 0,
            revoked_serials: Default::default(),
            local_certificate_revoked: false,
            relays: Default::default(),
            candidate_exchange: CandidateExchangeAuthority {
                enabled: false,
                max_candidates: 0,
                ttl: Duration::ZERO,
            },
            authorized_exits: Default::default(),
            certificate_renew_after: u64::MAX - 1,
            certificate_not_after: u64::MAX,
        }
    }

    #[test]
    fn configured_peers_are_not_contacts_and_revocations_filter_observations() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let direct = Id::new([1; 16]).unwrap();
        let relay = Id::new([2; 16]).unwrap();
        let stale = Id::new([3; 16]).unwrap();
        let absent = Id::new([4; 16]).unwrap();
        let mut authority = snapshot(&[direct, relay, stale], now);
        let evidence = Observations::default();
        assert!(evidence.report(Some(&authority)).peers.is_empty());
        let serial = Bytes::from_static(b"known-serial");
        evidence.received(direct, Some(serial.clone()));
        evidence.received(relay, None);
        evidence.received(absent, None);
        evidence.store(
            stale,
            Contact {
                when: Instant::now(),
                unix_seconds: now - TTL_SECONDS,
                path: Path::Relay,
                direct_serial: None,
            },
        );
        let report = evidence.report(Some(&authority));
        assert_eq!(report.peers.len(), 2);
        assert_eq!(report.peers[0].path, Path::Direct);
        assert_eq!(report.peers[1].path, Path::Relay);
        assert!(report.peers.iter().all(|p| p.latency_ms.is_none()));
        authority.revoked_serials.insert(serial.to_vec());
        assert_eq!(evidence.report(Some(&authority)).peers.len(), 1);
        authority.local_certificate_revoked = true;
        assert!(evidence.report(Some(&authority)).peers.is_empty());
    }

    #[test]
    fn busy_transport_cannot_store_unbounded_contacts() {
        let evidence = Observations::default();
        for i in 1..=MAX_PEERS + 1 {
            evidence.received(Id::new([i as u8; 16]).unwrap(), None);
        }
        assert_eq!(evidence.0.lock().unwrap().len(), MAX_PEERS);
    }
}
