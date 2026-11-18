//! Optional signed, public-only alert notifications. No network I/O in SQLite transactions.
use crate::http::State;
use anyhow::{Context, Result, ensure};
use laneway_controller::{SessionStore, operational_alerts::Delivery};
use reqwest::{
    Client, Url,
    dns::{Name, Resolve, Resolving},
    redirect,
};
use ring::hmac;
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, LazyLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{MissedTickBehavior, interval, timeout};

pub(crate) struct Webhook {
    url: Url,
    key: hmac::Key,
}

impl Webhook {
    pub(crate) fn load(url: &Path, secret: &Path) -> Result<Self> {
        let url = private_file(url, 2050)?;
        let secret = private_file(secret, 4096)?;
        let url = std::str::from_utf8(&url)
            .map_err(|_| anyhow::anyhow!("invalid alert webhook URL file"))?;
        let secret = std::str::from_utf8(&secret)
            .map_err(|_| anyhow::anyhow!("invalid alert webhook secret file"))?;
        Self::new(url.trim(), secret.trim().as_bytes())
    }

    fn new(raw: &str, secret: &[u8]) -> Result<Self> {
        ensure!(
            (32..=4096).contains(&secret.len()),
            "alert webhook secret must contain at least 32 bytes"
        );
        let authority = raw
            .strip_prefix("https://")
            .and_then(|value| value.split(['/', '?', '#']).next());
        ensure!(
            (1..=2048).contains(&raw.len())
                && authority.is_some_and(|a| !a.is_empty() && !a.contains(['@', '\\']))
                && !raw
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control()),
            "alert webhook requires a public HTTPS URL without credentials"
        );
        let url = Url::parse(raw).map_err(|_| anyhow::anyhow!("invalid alert webhook URL"))?;
        ensure!(
            url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && url.port_or_known_default() == Some(443)
                && url.fragment().is_none(),
            "alert webhook requires HTTPS port 443 without credentials or a fragment"
        );
        let host = host(&url)?;
        if let Ok(address) = host.parse::<IpAddr>() {
            ensure!(
                public_ip(address),
                "alert webhook destination must be public"
            );
        }
        Ok(Self {
            url,
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
        })
    }

    fn signature(&self, timestamp: &str, event: &str, body: &[u8]) -> String {
        let mut mac = hmac::Context::with_key(&self.key);
        for part in [timestamp.as_bytes(), b".", event.as_bytes(), b".", body] {
            mac.update(part);
        }
        format!("v1={}", hex::encode(mac.sign().as_ref()))
    }

    async fn deliver(&self, event: &Delivery) -> bool {
        // The deadline includes DNS. Details of failures and the complete
        // response are withheld even from local logs.
        timeout(Duration::from_secs(8), async {
            let host = host(&self.url)?;
            let addresses = match host.parse::<IpAddr>() {
                Ok(ip) => vec![SocketAddr::new(ip, 443)],
                Err(_) => tokio::net::lookup_host((host, 443))
                    .await?
                    .take(17)
                    .collect(),
            };
            let client = pinned_client(host, &addresses)?.build()?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs()
                .to_string();
            self.send(&client, &now, &event.id, &event.payload).await
        })
        .await
        .is_ok_and(|value| value.unwrap_or(false))
    }

    async fn send(&self, client: &Client, timestamp: &str, id: &str, body: &str) -> Result<bool> {
        let signature = self.signature(timestamp, id, body.as_bytes());
        let response = client
            .post(self.url.clone())
            .header("Content-Type", "application/json")
            .header("X-Laneway-Event-ID", id)
            .header("X-Laneway-Timestamp", timestamp)
            .header("X-Laneway-Signature", signature)
            .body(body.to_owned())
            .send()
            .await?;
        Ok(response.status().is_success())
    }
}

fn host(url: &Url) -> Result<&str> {
    Ok(url
        .host_str()
        .context("alert webhook host is missing")?
        .trim_start_matches('[')
        .trim_end_matches(']'))
}

struct NoFallbackDns;
impl Resolve for NoFallbackDns {
    fn resolve(&self, _name: Name) -> Resolving {
        Box::pin(async {
            Err(std::io::Error::other("webhook has no validated DNS address").into())
        })
    }
}

fn pinned_client(host: &str, addresses: &[SocketAddr]) -> Result<reqwest::ClientBuilder> {
    ensure!(
        (1..=16).contains(&addresses.len())
            && addresses
                .iter()
                .all(|addr| addr.port() == 443 && public_ip(addr.ip())),
        "alert webhook must resolve exclusively to bounded public destinations"
    );
    let mut client = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(redirect::Policy::none())
        .referer(false)
        .pool_max_idle_per_host(0)
        .retry(reqwest::retry::never())
        .http1_only()
        .connect_timeout(Duration::from_secs(3))
        .dns_resolver(Arc::new(NoFallbackDns));
    if let Ok(ip) = host.parse::<IpAddr>() {
        ensure!(
            addresses == [SocketAddr::new(ip, 443)],
            "webhook address differs from its URL"
        );
    } else {
        // The request URL remains unmodified, so TLS verifies the original
        // hostname even though the TCP connect uses the vetted addresses.
        client = client.resolve_to_addrs(host, addresses);
    }
    Ok(client)
}

fn public_ip(addr: IpAddr) -> bool {
    use ipnet::{Ipv4Net, Ipv6Net};
    // IANA special-purpose registries; err on the side of rejecting entire
    // overlapping protocol-assignment ranges, as the Go controller does.
    static BLOCK_V4: LazyLock<Vec<Ipv4Net>> = LazyLock::new(|| {
        [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/3",
        ]
        .into_iter()
        .map(|prefix| prefix.parse().expect("constant IPv4 prefix"))
        .collect()
    });
    static BLOCK_V6: LazyLock<Vec<Ipv6Net>> = LazyLock::new(|| {
        ["2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"]
            .into_iter()
            .map(|prefix| prefix.parse().expect("constant IPv6 prefix"))
            .collect()
    });
    match addr.to_canonical() {
        IpAddr::V4(addr) => !BLOCK_V4.iter().any(|net| net.contains(&addr)),
        IpAddr::V6(addr) => {
            addr.segments()[0] & 0xe000 == 0x2000 && !BLOCK_V6.iter().any(|net| net.contains(&addr))
        }
    }
}

#[cfg(unix)]
fn private_file(path: &Path, max: usize) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use rustix::fs::{Mode, OFlags, open};
    use std::{io::Read, os::unix::fs::MetadataExt};
    let file = std::fs::File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| anyhow::anyhow!("open private alert webhook file"))?,
    );
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1 && metadata.mode() & 0o077 == 0,
        "alert webhook configuration must be a private regular file (0600 or 0400)"
    );
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= max,
        "alert webhook configuration exceeds its size limit"
    );
    Ok(bytes)
}

#[cfg(not(unix))]
fn private_file(_path: &Path, _max: usize) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    anyhow::bail!("alert webhook configuration files currently require Unix")
}

async fn database<T: Send + 'static>(
    state: &State,
    op: impl FnOnce(&mut SessionStore) -> Result<T> + Send + 'static,
) -> Result<T> {
    let permit = timeout(
        Duration::from_secs(2),
        Arc::clone(&state.queries).acquire_owned(),
    )
    .await??;
    let path = state.database.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        op(&mut SessionStore::open(&path)?)
    })
    .await?
}

pub(crate) async fn run(state: State, webhook: Option<Webhook>) {
    let reconcile = async {
        let mut clock = interval(Duration::from_secs(60));
        clock.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            clock.tick().await;
            if database(&state, SessionStore::reconcile_operational_alerts)
                .await
                .is_err()
            {
                eprintln!("Operational alert reconciliation unavailable; will retry");
            }
        }
    };
    let deliver = async {
        let mut clock = interval(Duration::from_secs(5));
        clock.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            clock.tick().await;
            if process(&state, webhook.as_ref()).await.is_err() {
                eprintln!("Operational alert outbox unavailable; will retry");
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        }
    };
    tokio::join!(reconcile, deliver);
}

async fn process(state: &State, webhook: Option<&Webhook>) -> Result<()> {
    let enabled = webhook.is_some();
    for _ in 0..20 {
        let Some(event) = database(state, move |s| s.reserve_operational_delivery(enabled)).await?
        else {
            break;
        };
        let sent = match webhook {
            Some(webhook) => webhook.deliver(&event).await,
            None => false,
        };
        // Drop the database permit during the send. Shutdown or a busy store
        // leaves the reserved attempt and the same event ID in the outbox.
        database(state, move |s| s.finish_operational_delivery(&event, sent)).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_matches_raw_body_vector() {
        let hook = Webhook::new("https://notify.example/", &[42; 32]).unwrap();
        assert_eq!(
            hook.signature(
                "1700000000",
                "11111111111111111111111111111111",
                br#"{"ok":true}"#
            ),
            "v1=f44e2e3c91ffca35f2112e0df54498db6ab98c9264b4f18185c15b2556fc9e0f"
        );
    }

    #[test]
    fn every_address_must_be_public_without_a_dns_fallback() {
        let public: SocketAddr = "8.8.8.8:443".parse().unwrap();
        for value in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.4.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.31.2.3",
            "192.0.2.1",
            "192.168.0.1",
            "198.19.1.1",
            "198.51.100.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "2001::3",
            "2001:db8::1",
            "2002:a00:1::1",
            "3fff::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            let ip: IpAddr = value.parse().unwrap();
            assert!(!public_ip(ip), "{value}");
            assert!(pinned_client("notify.example", &[public, SocketAddr::new(ip, 443)]).is_err());
        }
        assert!(pinned_client("notify.example", &[]).is_err());
        assert!(pinned_client("notify.example", &[public; 17]).is_err());
        assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn validates_operator_target_without_external_io() {
        let key = [42; 32];
        for value in [
            "http://example.com/send",
            "https://localhost:8080/",
            "https://localhost@notify.example/",
            "https://@notify.example/",
            "https://notify.example/#frag",
            "https://127.0.0.1/",
            "https://[::1]/",
        ] {
            assert!(Webhook::new(value, &key).is_err(), "{value}");
        }
        assert!(Webhook::new("https://notify.example/send?q=test", &key).is_ok());
        assert!(Webhook::new("https://notify.example/", &key[..31]).is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires integration/rust-lab/alert-webhook.sh"]
    async fn sends_exact_signed_bytes_to_pinned_tls_and_does_not_redirect() -> Result<()> {
        use http_body_util::{BodyExt, Full};
        use hyper::{
            Method, Request, Response, StatusCode, body::Incoming, server::conn::http1,
            service::service_fn,
        };
        use hyper_util::rt::TokioIo;
        use rustls::pki_types::PrivatePkcs8KeyDer;
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;
        ensure!(
            std::env::var("LANEWAY_LAB_ALERT_WEBHOOK").as_deref() == Ok("1")
                && Path::new("/.dockerenv").is_file(),
            "requires the isolated webhook lab"
        );
        const HOST: &str = "notify.laneway.test";
        const ID: &str = "11111111111111111111111111111111";
        const STAMP: &str = "1700000000";
        const BODY: &str = r#"{"ok":true}"#;
        const SIGNATURE: &str =
            "v1=f44e2e3c91ffca35f2112e0df54498db6ab98c9264b4f18185c15b2556fc9e0f";
        let address: SocketAddr = "8.8.4.4:443".parse()?;
        // This address is bound to loopback in the network-none test namespace.
        // If the local bind is unavailable, never attempt an outbound request.
        let listener = TcpListener::bind(address).await?;
        let issued = rcgen::generate_simple_self_signed(vec![HOST.into()])?;
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![issued.cert.der().clone()],
            PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der()).into(),
        )?;
        let server = TlsAcceptor::from(Arc::new(tls));
        let client = pinned_client(HOST, &[address])?
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_der(issued.cert.der())?)
            .timeout(Duration::from_secs(5))
            .build()?;
        let fixture = tokio::spawn(async move {
            for status in [StatusCode::NO_CONTENT, StatusCode::TEMPORARY_REDIRECT] {
                let (socket, _) = listener.accept().await?;
                let socket = server.accept(socket).await?;
                assert_eq!(socket.get_ref().1.server_name(), Some(HOST));
                http1::Builder::new()
                    .keep_alive(false)
                    .serve_connection(
                        TokioIo::new(socket),
                        service_fn(move |req: Request<Incoming>| async move {
                            assert_eq!(req.method(), Method::POST);
                            assert_eq!(req.uri().path(), "/notify");
                            assert_eq!(req.headers()["X-Laneway-Event-ID"], ID);
                            assert_eq!(req.headers()["X-Laneway-Timestamp"], STAMP);
                            assert_eq!(req.headers()["X-Laneway-Signature"], SIGNATURE);
                            assert_eq!(req.into_body().collect().await.unwrap().to_bytes(), BODY);
                            let mut reply = Response::builder().status(status);
                            if status.is_redirection() {
                                reply = reply.header("Location", "/not-allowed");
                            }
                            Ok::<_, std::convert::Infallible>(
                                reply
                                    .body(Full::<bytes::Bytes>::new(bytes::Bytes::new()))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await?;
            }
            Ok::<_, anyhow::Error>(())
        });
        let webhook = Webhook::new(&format!("https://{HOST}/notify"), &[42; 32])?;
        assert!(webhook.send(&client, STAMP, ID, BODY).await?);
        assert!(!webhook.send(&client, STAMP, ID, BODY).await?);
        timeout(Duration::from_secs(5), fixture).await???;
        Ok(())
    }
}
