#![forbid(unsafe_code)]

use std::{
    fs,
    io::Read,
    net::{Ipv4Addr, SocketAddrV4},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};
use tokio_rustls::TlsConnector;

const USAGE: &str =
    "usage: laneway-healthcheck (-tcp 127.0.0.1:PORT | -unix /absolute/socket) [-timeout 2s]";
const MAX_CA_BYTES: u64 = 1024 * 1024;
const MAX_SERVICES_BYTES: u64 = 1024 * 1024;
#[cfg(unix)]
const MAX_STATUS_LINE_BYTES: u64 = 4096;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(std::env::args().skip(1)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("laneway-healthcheck: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: impl IntoIterator<Item = String>) -> Result<()> {
    let mut tcp_address = String::new();
    let mut unix_path = String::new();
    let mut tls_ca = String::new();
    let mut tls_server_name = String::new();
    let mut duration = Duration::from_secs(2);
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        if arg == "--" {
            ensure!(args.next().is_none(), "{USAGE}");
            break;
        }
        let Some(flag) = arg.strip_prefix('-') else {
            bail!("{USAGE}");
        };
        let flag = flag.strip_prefix('-').unwrap_or(flag);
        let (name, value) = flag
            .split_once('=')
            .map_or((flag, None), |(name, value)| (name, Some(value)));
        let destination = match name {
            "tcp" => &mut tcp_address,
            "unix" => &mut unix_path,
            "tls-ca" => &mut tls_ca,
            "tls-server-name" => &mut tls_server_name,
            "timeout" => {
                let value = flag_value(name, value, &mut args)?;
                duration = parse_duration(&value)
                    .with_context(|| format!("invalid value {value:?} for flag -timeout"))?;
                continue;
            }
            "h" | "help" => {
                eprintln!(
                    "{USAGE}\n  -tcp TCP listen address to probe\n  -unix Unix socket serving the local status API\n  -tls-ca optional PEM trust bundle for a TLS readiness handshake\n  -tls-server-name expected TLS DNS identity\n  -timeout connect timeout (default 2s)"
                );
                bail!("flag: help requested");
            }
            "" => bail!("{USAGE}"),
            _ => bail!("flag provided but not defined: -{name}"),
        };
        *destination = flag_value(name, value, &mut args)?;
    }

    ensure!(
        tcp_address.is_empty() != unix_path.is_empty()
            && !duration.is_zero()
            && duration <= Duration::from_secs(10),
        "{USAGE}"
    );
    if !unix_path.is_empty() {
        return probe_unix(&unix_path, duration).await;
    }
    let port = tcp_address
        .strip_prefix("127.0.0.1:")
        .or_else(|| tcp_address.strip_prefix("[127.0.0.1]:"))
        .filter(|port| !port.is_empty() && !port.contains(':'))
        .context("-tcp must be a 127.0.0.1:PORT address")?;
    ensure!(
        tls_ca.is_empty() == tls_server_name.is_empty(),
        "-tls-ca and -tls-server-name must be provided together"
    );

    let tls = if tls_ca.is_empty() {
        None
    } else {
        Some(tls_connector(&tls_ca, &tls_server_name)?)
    };
    timeout(duration, probe_tcp(port, tls))
        .await
        .context("TCP readiness deadline exceeded")
        .and_then(|result| result)
        .with_context(|| format!("probe {tcp_address}"))
}

fn flag_value(
    name: &str,
    value: Option<&str>,
    args: &mut impl Iterator<Item = String>,
) -> Result<String> {
    value
        .map(str::to_owned)
        .or_else(|| args.next())
        .with_context(|| format!("flag needs an argument: -{name}"))
}

// Accept the original duration syntax, including fractional and compound units.
fn parse_duration(value: &str) -> Result<Duration> {
    let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
    if unsigned == "0" {
        return Ok(Duration::ZERO);
    }
    ensure!(!unsigned.is_empty(), "invalid duration");
    let mut remaining = unsigned;
    let mut nanos = 0_u64;
    while !remaining.is_empty() {
        let number_end = remaining
            .find(|ch: char| !ch.is_ascii_digit() && ch != '.')
            .unwrap_or(remaining.len());
        let (number, rest) = remaining.split_at(number_end);
        let unit_end = rest
            .find(|ch: char| ch.is_ascii_digit() || ch == '.')
            .unwrap_or(rest.len());
        let (unit, rest) = rest.split_at(unit_end);
        remaining = rest;
        let scale = match unit {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => bail!("unknown duration unit {unit:?}"),
        };
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        ensure!(
            !(whole.is_empty() && fraction.is_empty())
                && fraction.bytes().all(|digit| digit.is_ascii_digit()),
            "invalid duration number {number:?}"
        );
        let integer = if whole.is_empty() {
            0
        } else {
            whole.parse::<u64>()?
        };
        let fractional_nanos = fraction.bytes().rev().fold(0, |fraction, digit| {
            (u64::from(digit - b'0') * scale + fraction) / 10
        });
        nanos = integer
            .checked_mul(scale)
            .and_then(|value| value.checked_add(fractional_nanos))
            .and_then(|value| nanos.checked_add(value))
            .filter(|nanos| *nanos <= (i64::MAX as u64) + u64::from(value.starts_with('-')))
            .context("duration overflow")?;
    }
    if value.starts_with('-') {
        return Ok(Duration::ZERO);
    }
    Ok(Duration::from_nanos(nanos))
}

fn tls_connector(ca_path: &str, server_name: &str) -> Result<(TlsConnector, ServerName<'static>)> {
    let ca_file = read_limited_file(ca_path, MAX_CA_BYTES).context("read TLS CA")?;
    let mut roots = RootCertStore::empty();
    let mut pem = ca_file.as_slice();
    let certificates = rustls_pemfile::certs(&mut pem).filter_map(Result::ok);
    roots.add_parsable_certificates(certificates);
    ensure!(!roots.is_empty(), "TLS CA contains no certificates");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(server_name.to_owned()).context("invalid TLS server name")?;
    Ok((TlsConnector::from(Arc::new(config)), name))
}

fn read_limited_file(path: &str, limit: u64) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut data)?;
    ensure!(data.len() as u64 <= limit, "file exceeds {limit} bytes");
    Ok(data)
}

async fn probe_tcp(port: &str, tls: Option<(TlsConnector, ServerName<'static>)>) -> Result<()> {
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, tcp_port(port)?);
    let connection = TcpStream::connect(address).await?;
    if let Some((connector, name)) = tls {
        let mut connection = connector.connect(name, connection).await?;
        connection.shutdown().await?;
    }
    Ok(())
}

fn tcp_port(port: &str) -> Result<u16> {
    let digits = port.strip_prefix(['+', '-']).unwrap_or(port);
    if digits.bytes().all(|digit| digit.is_ascii_digit()) {
        if digits.bytes().all(|digit| digit == b'0') {
            return Ok(0);
        }
        return port.parse().context("invalid TCP port");
    }

    // Scratch images have no /etc/services. Keep the fallback service names
    // the previous probe accepted there and use the system database elsewhere.
    let port = port.to_ascii_lowercase();
    let builtin = match port.as_str() {
        "ftp" => 21,
        "ftps" => 990,
        "gopher" => 70,
        "http" => 80,
        "https" => 443,
        "imap2" => 143,
        "imap3" => 220,
        "imaps" => 993,
        "pop3" => 110,
        "pop3s" => 995,
        "smtp" => 25,
        "submissions" => 465,
        "ssh" => 22,
        "telnet" => 23,
        _ => 0,
    };
    if builtin != 0 {
        return Ok(builtin);
    }

    if let Ok(services) = read_limited_file("/etc/services", MAX_SERVICES_BYTES)
        && let Ok(services) = std::str::from_utf8(&services)
    {
        for line in services.lines() {
            let mut fields = line
                .split('#')
                .next()
                .unwrap_or_default()
                .split_whitespace();
            let (Some(name), Some(endpoint)) = (fields.next(), fields.next()) else {
                continue;
            };
            if let Some(port_number) = endpoint.strip_suffix("/tcp")
                && (name.eq_ignore_ascii_case(&port)
                    || fields.any(|alias| alias.eq_ignore_ascii_case(&port)))
            {
                return port_number.parse().context("invalid TCP service port");
            }
        }
    }
    bail!("unknown TCP service {port:?}");
}

#[cfg(unix)]
async fn probe_unix(path: &str, duration: Duration) -> Result<()> {
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, BufReader},
        net::UnixStream,
    };

    validate_socket_path(path)?;
    let mut connection = timeout(duration, UnixStream::connect(path))
        .await
        .context("connect timeout")
        .and_then(|result| result.map_err(Into::into))
        .context("probe Unix status socket")?;
    timeout(duration, async {
        connection
            .write_all(b"GET /v1/status HTTP/1.1\r\nHost: lanewayd\r\nConnection: close\r\n\r\n")
            .await
            .context("write Unix status probe")?;
        let mut line = String::new();
        BufReader::new(connection.take(MAX_STATUS_LINE_BYTES + 1))
            .read_line(&mut line)
            .await
            .context("read Unix status probe")?;
        ensure!(
            line.len() as u64 <= MAX_STATUS_LINE_BYTES,
            "Unix status line exceeds {MAX_STATUS_LINE_BYTES} bytes"
        );
        ensure!(
            line.ends_with('\n'),
            "read Unix status probe: unexpected EOF"
        );
        ensure!(
            line.trim() == "HTTP/1.1 200 OK",
            "unexpected Unix status line"
        );
        Ok(())
    })
    .await
    .context("Unix status probe deadline exceeded")?
}

#[cfg(unix)]
fn validate_socket_path(path: &str) -> Result<()> {
    ensure!(
        path.len() <= 4096
            && !path.contains('\0')
            && path.strip_prefix('/').is_some_and(|relative| {
                relative.is_empty()
                    || relative
                        .split('/')
                        .all(|part| !matches!(part, "" | "." | ".."))
            }),
        "-unix must be a clean absolute socket path"
    );
    Ok(())
}

#[cfg(not(unix))]
async fn probe_unix(_path: &str, _duration: Duration) -> Result<()> {
    bail!("Unix status sockets are unavailable on this platform");
}

#[cfg(test)]
mod tests;
