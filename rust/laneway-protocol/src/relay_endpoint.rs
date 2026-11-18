//! Stable-v1 relay discovery uses canonical unicast IP or ASCII DNS endpoints.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Largest relay set one stable-v1 node snapshot may advertise.
pub const MAX_RELAY_ENDPOINTS: usize = 32;

/// Validates and normalizes a host and nonzero port without resolving DNS.
pub fn canonical_host_port(value: &str) -> Option<String> {
    if value.trim() != value {
        return None;
    }
    let (host, port) = value.rsplit_once(':')?;
    let host = if let Some(bracketed) = host.strip_prefix('[') {
        bracketed.strip_suffix(']')?
    } else {
        if host.contains(':') {
            return None;
        }
        host
    };
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port = port.parse::<u16>().ok().filter(|&port| port != 0)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_unspecified()
            || ip.is_multicast()
            || ip == IpAddr::V4(Ipv4Addr::BROADCAST)
            || matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
        {
            return None;
        }
        return Some(SocketAddr::new(ip, port).to_string());
    }
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.len() > 253
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return None;
    }
    Some(format!("{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_normalization_is_bounded_and_unicast() {
        for (input, expected) in [
            ("Relay-1.Example.:00443", "relay-1.example:443"),
            ("[2001:0DB8:0:0::2]:4433", "[2001:db8::2]:4433"),
            ("[127.0.0.1]:1", "127.0.0.1:1"),
            ("localhost:9", "localhost:9"),
            ("[fe80::a]:65535", "[fe80::a]:65535"),
        ] {
            assert_eq!(canonical_host_port(input).as_deref(), Some(expected));
        }
        for input in [
            "",
            "localhost",
            "::1:443",
            "[::]:4",
            "[::ffff:192.0.2.1]:4",
            "[fe80::1%eth0]:4",
            "[ff00::1]:4",
            "0.0.0.0:4",
            "224.0.0.1:4",
            "255.255.255.255:4",
            "r..example:42",
            "r-:42",
            "R.example:0",
            "R.example:+42",
            "R.example:65536",
            " R.example:42",
        ] {
            assert!(canonical_host_port(input).is_none(), "accepted {input}");
        }
    }
}
