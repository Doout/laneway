//! Read-only network assertions used by the disposable integration labs.
#[path = "inspect_probe_main/benchmark.rs"]
mod benchmark;
#[cfg(all(target_os = "linux", feature = "network-fixtures"))]
#[path = "inspect_probe_main/kernel.rs"]
mod kernel;
#[path = "inspect_probe_main/stream.rs"]
mod stream;

use std::{
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RData, RecordType},
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[cfg(feature = "network-fixtures")]
    EndpointHealth {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        node_id: laneway_protocol::Id,
        #[arg(long)]
        public_ip: Option<IpAddr>,
        #[arg(long)]
        location: Option<String>,
        #[arg(long)]
        product_version: Option<String>,
    },
    Metric {
        #[arg(long, default_value = "http://127.0.0.1:6060/metrics")]
        url: reqwest::Url,
        #[arg(long)]
        name: String,
    },
    UdpBenchClient(benchmark::Options),
    #[cfg(all(target_os = "linux", feature = "network-fixtures"))]
    ExitClient(kernel::ExitClient),
    #[cfg(all(target_os = "linux", feature = "network-fixtures"))]
    ExitGateway(kernel::ExitGateway),
    CertificateInfo {
        #[arg(long)]
        cert: PathBuf,
    },
    Dns {
        #[arg(long, default_value = "127.0.0.1:5354")]
        address: SocketAddr,
        #[arg(long)]
        name: Name,
        #[arg(long = "type", default_value = "A")]
        record: RecordType,
        #[arg(long)]
        answer: Option<IpAddr>,
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=15))]
        rcode: u8,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    if std::env::args_os()
        .nth(1)
        .and_then(|arg| {
            arg.to_str().map(|command| {
                matches!(
                    command,
                    "tcp-server" | "tcp-client" | "udp-server" | "udp-client" | "udp-echo-server"
                )
            })
        })
        .unwrap_or(false)
    {
        return stream::run().map_err(|error| anyhow::anyhow!("{error}"));
    }
    match Cli::parse_from(std::env::args_os().map(normalize)).command {
        #[cfg(feature = "network-fixtures")]
        Command::EndpointHealth {
            database,
            node_id,
            public_ip,
            location,
            product_version,
        } => endpoint_health(
            &database,
            node_id,
            public_ip,
            location.as_deref(),
            product_version.as_deref(),
        ),
        Command::Metric { url, name } => metric(url, &name).await,
        Command::UdpBenchClient(options) => benchmark::run(options).await,
        #[cfg(all(target_os = "linux", feature = "network-fixtures"))]
        Command::ExitClient(options) => kernel::client(options).await,
        #[cfg(all(target_os = "linux", feature = "network-fixtures"))]
        Command::ExitGateway(options) => kernel::gateway(options).await,
        Command::CertificateInfo { cert } => certificate(&cert),
        Command::Dns {
            address,
            name,
            record,
            answer,
            rcode,
        } => dns(address, name, record, answer, rcode),
    }
}

fn normalize(arg: std::ffi::OsString) -> std::ffi::OsString {
    match arg.to_str() {
        Some(flag) if flag.starts_with('-') && !flag.starts_with("--") && flag != "-h" => {
            format!("-{flag}").into()
        }
        _ => arg,
    }
}

async fn metric(url: reqwest::Url, name: &str) -> Result<()> {
    let mut response = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .build()?
        .get(url)
        .send()
        .await?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "metrics status {}",
        response.status()
    );
    const LIMIT: usize = 1 << 20;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= LIMIT - body.len(),
            "oversized metrics response"
        );
        body.extend_from_slice(&chunk);
    }
    for line in std::str::from_utf8(&body)?.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some(name)
            && let Some(value) = fields.next()
            && fields.next().is_none()
        {
            value
                .parse::<u64>()
                .with_context(|| format!("invalid value for {name}"))?;
            println!("{value}");
            return Ok(());
        }
    }
    anyhow::bail!("metric {name:?} not found")
}

fn certificate(path: &Path) -> Result<()> {
    const LIMIT: usize = 1 << 20;
    let mut body = Vec::new();
    File::open(path)?
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut body)?;
    ensure!(body.len() <= LIMIT, "oversized PEM certificate chain");
    let leaf = rustls_pemfile::certs(&mut body.as_slice())
        .next()
        .context("missing leaf certificate")??;
    let identity = laneway_protocol::identity_from_certificate_der(&leaf)?;
    ensure!(
        identity.role == laneway_protocol::Role::Node,
        "expected a node certificate"
    );
    let serial = laneway_protocol::certificate_serial_from_der(&leaf)?;
    println!(
        "network={} node={} serial={}",
        identity.network_id,
        identity.subject_id,
        hex::encode(serial)
    );
    Ok(())
}

fn dns(
    address: SocketAddr,
    mut name: Name,
    record: RecordType,
    answer: Option<IpAddr>,
    rcode: u8,
) -> Result<()> {
    ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "expected a loopback DNS resolver"
    );
    ensure!(
        matches!(record, RecordType::A | RecordType::AAAA),
        "unsupported DNS query type"
    );
    name.set_fqdn(true);
    let question = Query::query(name, record);
    let mut request = Message::new(18455, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(question.clone());
    let socket = UdpSocket::bind(if address.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    })?;
    socket.connect(address)?;
    socket.set_read_timeout(Some(Duration::from_secs(4)))?;
    socket.set_write_timeout(Some(Duration::from_secs(4)))?;
    socket.send(&request.to_vec()?)?;
    let mut buffer = [0; 513];
    let count = socket.recv(&mut buffer)?;
    ensure!(count <= 512, "oversized private DNS reply");
    let reply = Message::from_vec(&buffer[..count])?;
    ensure!(
        reply.metadata.message_type == MessageType::Response
            && reply.metadata.id == request.metadata.id
            && !reply.metadata.recursion_available
            && reply.queries.as_slice() == [question],
        "invalid private DNS reply"
    );
    ensure!(
        u16::from(reply.metadata.response_code) == u16::from(rcode)
            && (rcode != 0 || reply.metadata.authoritative),
        "unexpected private DNS response code or authority flag"
    );
    match (reply.answers.as_slice(), answer) {
        ([], None) => Ok(()),
        ([actual], Some(expected)) => {
            let received = match &actual.data {
                RData::A(ip) => IpAddr::V4(ip.0),
                RData::AAAA(ip) => IpAddr::V6(ip.0),
                _ => anyhow::bail!("unexpected private DNS record type"),
            };
            ensure!(
                received == expected
                    && actual.ttl <= 5
                    && actual.record_type() == record
                    && &actual.name == request.queries[0].name(),
                "unexpected private DNS answer"
            );
            Ok(())
        }
        _ => anyhow::bail!("unexpected private DNS answer count"),
    }
}

#[cfg(feature = "network-fixtures")]
fn endpoint_health(
    database: &Path,
    node: laneway_protocol::Id,
    ip: Option<IpAddr>,
    location: Option<&str>,
    version: Option<&str>,
) -> Result<()> {
    use rusqlite::{Connection, OpenFlags, params};

    let db = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let carrier: String = db.query_row(
        "SELECT s.carrier_state FROM endpoint_status_latest s
        JOIN node_locations l ON l.node_id=s.node_id
        WHERE s.node_id=?1 AND s.platform='linux' AND s.configuration_state='current'
          AND s.route_state='ready' AND s.expires_at>unixepoch() AND l.observed_at>unixepoch()-30
          AND (?2 IS NULL OR l.public_ip=?2)
          AND (?3 IS NULL OR json_extract(l.automatic_json,'$.label')=?3)
          AND (?4 IS NULL OR s.product_version=?4)",
        params![
            node.as_bytes().as_slice(),
            ip.map(|ip| ip.to_string()),
            location,
            version
        ],
        |row| row.get(0),
    )?;
    println!("{carrier}");
    Ok(())
}
