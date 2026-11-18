//! Opt-in private directory resolver. No recursion or platform DNS changes.
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{
        DNSClass, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use laneway_protocol::Id;
use serde::Deserialize;
use tokio::{
    net::UdpSocket,
    time::{Instant, timeout},
};

use crate::{config::private_dns_loopback, controller::Client};

const REFRESH: Duration = Duration::from_secs(5);
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_QUERY: usize = 1232;
const MAX_RESPONSE: usize = 512;

pub(crate) struct Server {
    socket: UdpSocket,
    zone: String,
}

impl Server {
    pub(crate) async fn bind(address: SocketAddr, network: Id) -> Result<Self> {
        ensure!(
            private_dns_loopback(address),
            "private DNS listener must be loopback"
        );
        Ok(Self {
            socket: UdpSocket::bind(address)
                .await
                .context("bind private DNS listener")?,
            zone: zone(network),
        })
    }

    pub(crate) async fn run(self, client: &Client, certificate_end: u64) -> Result<()> {
        self.serve(|| client.private_dns(), certificate_end, REFRESH)
            .await
    }

    async fn serve<F, Fut>(
        self,
        mut fetch: F,
        certificate_end: u64,
        refresh: Duration,
    ) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<Catalog>>,
    {
        let mut cache = None;
        let mut next_refresh = Instant::now();
        let mut datagram = [0; MAX_QUERY + 1];
        loop {
            let (n, sender) = self
                .socket
                .recv_from(&mut datagram)
                .await
                .context("receive private DNS query")?;
            if n > MAX_QUERY || !sender.ip().is_loopback() {
                continue;
            }
            let Ok(request) = Message::from_vec(&datagram[..n]) else {
                continue;
            };
            let Some(mut reply) = Reply::new(request, &self.zone) else {
                continue;
            };
            if reply.name.is_some() {
                if Instant::now() >= next_refresh && wall_remaining(certificate_end).is_some() {
                    // Never keep stale data when an attempted refresh fails, including timeout.
                    cache = timeout(FETCH_TIMEOUT, fetch())
                        .await
                        .ok()
                        .and_then(Result::ok);
                    next_refresh = Instant::now() + refresh;
                }
                reply.resolve(cache.as_ref(), certificate_end, next_refresh);
            }
            if let Ok(bytes) = reply.encode() {
                let _ = self.socket.send_to(&bytes, sender).await;
            }
        }
    }
}

fn zone(network: Id) -> String {
    format!("{network}.laneway.internal")
}

#[derive(Deserialize)]
struct WireCatalog {
    network_id: String,
    zone: String,
    valid_until_unix_seconds: u64,
    records: Vec<WireRecord>,
}

#[derive(Deserialize)]
struct WireRecord {
    name: String,
    addresses: Vec<IpAddr>,
}

pub(crate) struct Catalog {
    valid_until: u64,
    records: HashMap<String, Vec<IpAddr>>,
}

impl Catalog {
    pub(crate) fn decode(bytes: &[u8], network: Id) -> Result<Self> {
        let data: WireCatalog =
            serde_json::from_slice(bytes).context("decode private DNS catalog")?;
        ensure!(
            data.network_id.parse::<Id>()? == network && data.zone == zone(network),
            "controller returned a different private DNS zone"
        );
        ensure!(
            wall_remaining(data.valid_until_unix_seconds).is_some(),
            "controller returned an expired private DNS catalog"
        );
        let suffix = format!(".{}", data.zone);
        let mut records = HashMap::with_capacity(data.records.len());
        for record in data.records {
            let label = record
                .name
                .strip_suffix(&suffix)
                .context("private DNS record outside the network zone")?;
            ensure!(
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
                "invalid private DNS record name"
            );
            let v4 = record.addresses.iter().filter(|p| p.is_ipv4()).count();
            ensure!(
                v4 <= 1
                    && record.addresses.len() - v4 <= 1
                    && !record.addresses.iter().any(|p| {
                        p.is_unspecified()
                            || p.is_multicast()
                            || matches!(p, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
                    }),
                "invalid private DNS overlay addresses"
            );
            ensure!(
                records.insert(record.name, record.addresses).is_none(),
                "duplicate private DNS name"
            );
        }
        Ok(Self {
            valid_until: data.valid_until_unix_seconds,
            records,
        })
    }
}

struct Reply {
    message: Message,
    name: Option<String>,
}

impl Reply {
    fn new(request: Message, zone: &str) -> Option<Self> {
        if request.metadata.message_type != MessageType::Query {
            return None;
        }
        let mut message = Message::response(request.metadata.id, request.metadata.op_code);
        message.metadata.recursion_desired = request.metadata.recursion_desired;
        if request.metadata.op_code != OpCode::Query || request.queries.len() != 1 {
            message.metadata.response_code = ResponseCode::FormErr;
            return Some(Self {
                message,
                name: None,
            });
        }
        message.queries = request.queries;
        let question = &message.queries[0];
        let name = question
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let in_zone = name
            .strip_suffix(zone)
            .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'));
        let name = if !in_zone || question.query_class() != DNSClass::IN {
            message.metadata.response_code = ResponseCode::Refused;
            None
        } else if !matches!(question.query_type(), RecordType::A | RecordType::AAAA) {
            message.metadata.response_code = ResponseCode::NotImp;
            None
        } else {
            Some(name)
        };
        Some(Self { message, name })
    }

    fn resolve(&mut self, catalog: Option<&Catalog>, certificate_end: u64, refresh_at: Instant) {
        let Some(name) = self.name.as_ref() else {
            return;
        };
        let remaining = || {
            let catalog = catalog?;
            let remaining = wall_remaining(catalog.valid_until.min(certificate_end))?;
            let cache_time = refresh_at.checked_duration_since(Instant::now())?;
            Some((
                catalog,
                remaining.min(cache_time).min(REFRESH).as_secs() as u32,
            ))
        };
        let Some((catalog, ttl)) = remaining() else {
            self.message.metadata.response_code = ResponseCode::ServFail;
            return;
        };
        self.message.metadata.authoritative = true;
        let Some(addrs) = catalog.records.get(name).filter(|a| !a.is_empty()) else {
            self.message.metadata.response_code = ResponseCode::NXDomain;
            return;
        };
        let question = &self.message.queries[0];
        for addr in addrs {
            let payload = match (question.query_type(), *addr) {
                (RecordType::A, IpAddr::V4(addr)) => RData::A(A(addr)),
                (RecordType::AAAA, IpAddr::V6(addr)) => RData::AAAA(AAAA(addr)),
                _ => continue,
            };
            self.message
                .answers
                .push(Record::from_rdata(question.name().clone(), ttl, payload));
        }
    }

    fn encode(mut self) -> Result<Vec<u8>> {
        let reply = self.message.to_vec()?;
        if reply.len() <= MAX_RESPONSE {
            return Ok(reply);
        }
        self.message.answers.clear();
        self.message.metadata.truncation = true;
        Ok(self.message.to_vec()?)
    }
}

fn wall_remaining(until: u64) -> Option<Duration> {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(until))?
        .duration_since(SystemTime::now())
        .ok()
        .filter(|d| !d.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{op::Query, rr::Name};
    use serde_json::json;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn fixture() -> (Id, String, u64) {
        let net = Id::new([1; 16]).unwrap();
        let until = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 30;
        (net, format!("laptop.{}", zone(net)), until)
    }

    fn catalog(net: Id, host: &str, until: u64) -> Result<Catalog> {
        Catalog::decode(
            &serde_json::to_vec(&json!({
                "network_id": net.to_string(), "zone": zone(net), "valid_until_unix_seconds": until,
                "records": [{"name": host, "addresses": ["100.96.0.2", "fd00::2"]}], "services": [],
            }))?,
            net,
        )
    }

    fn query(name: &str, kind: RecordType) -> Message {
        let mut message = Message::new(42, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(
            Name::from_ascii(format!("{name}.")).unwrap(),
            kind,
        ));
        message
    }

    #[test]
    fn validates_catalog_zone_and_declines_expired_certificate_or_directory() -> Result<()> {
        let (net, host, valid) = fixture();
        assert!(catalog(net, "laptop.other.invalid", valid).is_err());
        assert!(catalog(net, &host, 1).is_err());
        let refresh_at = Instant::now() + REFRESH;
        let mut stale = catalog(net, &host, valid)?;
        stale.valid_until = 1;
        for (data, cert) in [(&stale, valid), (&catalog(net, &host, valid)?, 1)] {
            let mut reply = Reply::new(query(&host, RecordType::A), &zone(net)).unwrap();
            reply.resolve(Some(data), cert, refresh_at);
            assert_eq!(reply.message.metadata.response_code, ResponseCode::ServFail);
            assert!(reply.message.answers.is_empty());
        }
        Ok(())
    }

    #[tokio::test]
    async fn serves_a_and_aaaa_on_loopback_and_drops_cache_on_refresh_failure() -> Result<()> {
        let (net, host, valid) = fixture();
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        let server = Server {
            socket,
            zone: zone(net),
        };
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let fetches = Arc::new(AtomicUsize::new(0));
        let requests = Arc::clone(&fetches);
        let target = host.clone();
        let cadence = Duration::from_secs(1);
        let task = tokio::spawn(server.serve(
            move || {
                let n = requests.fetch_add(1, Ordering::SeqCst);
                std::future::ready(if n == 0 {
                    catalog(net, &target, valid)
                } else {
                    Err(anyhow::anyhow!("offline"))
                })
            },
            valid,
            cadence,
        ));
        async fn lookup(udp: &UdpSocket, address: SocketAddr, q: Message) -> Result<Message> {
            udp.send_to(&q.to_vec()?, address).await?;
            let mut buf = [0; MAX_RESPONSE];
            let (count, sender) = timeout(FETCH_TIMEOUT, udp.recv_from(&mut buf)).await??;
            assert_eq!(sender, address);
            let msg = Message::from_vec(&buf[..count])?;
            assert_eq!(msg.metadata.id, q.metadata.id);
            assert_eq!(msg.queries, q.queries);
            assert!(!msg.metadata.recursion_available);
            Ok(msg)
        }
        let reply = lookup(&udp, address, query("outside.invalid", RecordType::A)).await?;
        assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
        let reply = lookup(&udp, address, query(&host, RecordType::SOA)).await?;
        assert_eq!(reply.metadata.response_code, ResponseCode::NotImp);
        assert_eq!(fetches.load(Ordering::SeqCst), 0);
        for (kind, expected) in [(RecordType::A, "100.96.0.2"), (RecordType::AAAA, "fd00::2")] {
            let reply = lookup(&udp, address, query(&host.to_ascii_uppercase(), kind)).await?;
            assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
            assert!(reply.metadata.authoritative);
            assert_eq!(reply.answers[0].data.to_string(), expected);
            assert!(reply.answers[0].ttl <= 5);
        }
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        tokio::time::sleep(cadence).await;
        let reply = lookup(&udp, address, query(&host, RecordType::A)).await?;
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
        assert!(reply.answers.is_empty());
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(UdpSocket::bind(address).await.is_ok());
        Ok(())
    }
}
