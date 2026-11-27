//! TCP and UDP echo probe for the isolated Linux namespace fixtures.
use std::{
    env,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket},
    thread,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const BUFFER: usize = 2048;
const ATTEMPT: Duration = Duration::from_millis(500);
const RETRY: Duration = Duration::from_millis(50);

#[derive(Default)]
struct Options {
    address: String,
    message: Option<String>,
    duration: Option<Duration>,
    packets: Option<u64>,
    source_port: u16,
    once: bool,
}

fn parse() -> Result<(String, Options)> {
    let mut arguments = env::args().skip(1);
    let operation = arguments
        .next()
        .ok_or("expected a TCP or UDP probe command")?;
    let server = matches!(
        operation.as_str(),
        "tcp-server" | "udp-server" | "udp-echo-server"
    );
    let client = matches!(operation.as_str(), "tcp-client" | "udp-client");
    if !server && !client {
        return Err(format!("unknown probe {operation:?}").into());
    }
    let mut options = Options::default();
    while let Some(flag) = arguments.next() {
        let flag = flag.trim_start_matches('-');
        let (name, inline) = flag
            .split_once('=')
            .map_or((flag, None), |(name, value)| (name, Some(value)));
        if name == "once" && operation == "udp-client" {
            options.once = inline.map_or(Ok(true), str::parse)?;
            continue;
        }
        let value = inline
            .map(str::to_owned)
            .or_else(|| arguments.next())
            .ok_or_else(|| format!("missing value for {name}"))?;
        match name {
            "listen" if server => options.address = value,
            "target" if client => options.address = value,
            "message" if client => options.message = Some(value),
            "timeout" if operation != "udp-echo-server" => {
                let (number, units) = value
                    .strip_suffix("ms")
                    .map(|v| (v, 1))
                    .or_else(|| value.strip_suffix('s').map(|v| (v, 1000)))
                    .or_else(|| value.strip_suffix('m').map(|v| (v, 60_000)))
                    .ok_or("expected a timeout in ms, s or m")?;
                let ms = number
                    .parse::<u64>()?
                    .checked_mul(units)
                    .ok_or("invalid timeout")?;
                if ms == 0 || ms > 300_000 {
                    return Err("probe deadline must be between zero and five minutes".into());
                }
                options.duration = Some(Duration::from_millis(ms));
            }
            "max-packets" if operation == "udp-server" => options.packets = Some(value.parse()?),
            "source-port" if operation == "udp-client" => options.source_port = value.parse()?,
            _ => return Err(format!("unknown option {name:?} for {operation}").into()),
        }
    }
    if options.address.is_empty() {
        return Err("a listen or target address is required".into());
    }
    Ok((operation, options))
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "probe deadline elapsed"))
}

fn tcp_read(stream: &mut TcpStream, buffer: &mut [u8; BUFFER]) -> Result<usize> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;
    let length = usize::from(u16::from_be_bytes(header));
    if !(1..=buffer.len()).contains(&length) {
        return Err("invalid TCP probe length".into());
    }
    stream.read_exact(&mut buffer[..length])?;
    Ok(length)
}

fn tcp_write(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    if !(1..=BUFFER).contains(&bytes.len()) {
        return Err("invalid TCP probe length".into());
    }
    stream.write_all(&u16::try_from(bytes.len())?.to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}

fn tcp_server(address: SocketAddr, duration: Duration) -> Result<()> {
    let listener = TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    println!("ready=tcp-server");
    let deadline = Instant::now() + duration;
    let (mut stream, remote) = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(remaining(deadline)?.min(RETRY));
            }
            Err(error) => return Err(error.into()),
        }
    };
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(duration))?;
    stream.set_write_timeout(Some(duration))?;
    let mut buffer = [0; BUFFER];
    let length = tcp_read(&mut stream, &mut buffer)?;
    println!(
        "remote={remote} payload={}",
        String::from_utf8_lossy(&buffer[..length])
    );
    tcp_write(&mut stream, &buffer[..length])
}

fn tcp_client(remote: SocketAddr, message: &[u8], duration: Duration) -> Result<()> {
    if !(1..=BUFFER).contains(&message.len()) {
        return Err("invalid TCP probe length".into());
    }
    let deadline = Instant::now() + duration;
    let mut buffer = [0; BUFFER];
    while let Ok(left) = remaining(deadline) {
        let attempt = left.min(ATTEMPT);
        if let Ok(mut stream) = TcpStream::connect_timeout(&remote, attempt) {
            stream.set_read_timeout(Some(attempt))?;
            stream.set_write_timeout(Some(attempt))?;
            if tcp_write(&mut stream, message).is_ok()
                && let Ok(length) = tcp_read(&mut stream, &mut buffer)
                && &buffer[..length] == message
            {
                println!(
                    "reply={remote} payload={}",
                    String::from_utf8_lossy(message)
                );
                return Ok(());
            }
        }
        thread::sleep(RETRY.min(remaining(deadline).unwrap_or_default()));
    }
    Err(format!("no valid TCP reply from {remote}").into())
}

fn udp_server(address: SocketAddr, duration: Option<Duration>, limit: u64) -> Result<()> {
    let socket = UdpSocket::bind(address)?;
    let mut buffer = vec![
        0u8;
        if duration.is_some() {
            BUFFER
        } else {
            u16::MAX.into()
        }
    ];
    let deadline = duration.map(|duration| Instant::now() + duration);
    let mut packets = 0;
    if deadline.is_some() {
        println!("ready=udp-server");
    } else {
        println!("ready=udp-echo-server");
    }
    while limit == 0 || packets < limit {
        if let Some(deadline) = deadline {
            let left = remaining(deadline)?;
            socket.set_read_timeout(Some(left))?;
            socket.set_write_timeout(Some(left))?;
        }
        let (length, remote) = socket.recv_from(&mut buffer)?;
        if deadline.is_some() {
            println!(
                "remote={remote} payload={}",
                String::from_utf8_lossy(&buffer[..length])
            );
        }
        socket.send_to(&buffer[..length], remote)?;
        packets += 1;
    }
    Ok(())
}

fn udp_client(
    remote: SocketAddr,
    options: Options,
    message: &[u8],
    duration: Duration,
) -> Result<()> {
    let local = if remote.is_ipv4() { "0.0.0.0" } else { "::" };
    let socket = UdpSocket::bind((local, options.source_port))?;
    let deadline = Instant::now() + duration;
    let mut buffer = [0; BUFFER];
    while let Ok(left) = remaining(deadline) {
        let attempt = left.min(ATTEMPT);
        socket.set_read_timeout(Some(attempt))?;
        socket.set_write_timeout(Some(attempt))?;
        if socket.send_to(message, remote).is_ok()
            && let Ok((length, source)) = socket.recv_from(&mut buffer)
            && source == remote
            && &buffer[..length] == message
        {
            println!(
                "reply={source} payload={}",
                String::from_utf8_lossy(message)
            );
            return Ok(());
        }
        if options.once {
            break;
        }
    }
    Err(format!("no valid UDP reply from {remote}").into())
}

pub(super) fn run() -> Result<()> {
    let (operation, mut options) = parse()?;
    let address = if let Some(port) = options.address.strip_prefix(':') {
        SocketAddr::from(([0, 0, 0, 0], port.parse()?))
    } else {
        options
            .address
            .to_socket_addrs()?
            .next()
            .ok_or("address resolves to no socket")?
    };
    let message = options
        .message
        .take()
        .unwrap_or_else(|| "laneway-netprobe".into());
    let duration = options.duration.unwrap_or_else(|| {
        if operation.ends_with("-client") {
            Duration::from_secs(12)
        } else {
            Duration::from_secs(20)
        }
    });
    match operation.as_str() {
        "tcp-server" => tcp_server(address, duration),
        "tcp-client" => tcp_client(address, message.as_bytes(), duration),
        "udp-server" => udp_server(address, Some(duration), options.packets.unwrap_or(1)),
        "udp-echo-server" => udp_server(address, None, 0),
        "udp-client" => udp_client(address, options, message.as_bytes(), duration),
        _ => unreachable!(),
    }
}
