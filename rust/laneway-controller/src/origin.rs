use hyper::{HeaderMap, header, http::uri::Authority};
use std::net::IpAddr;

// The outer listener is TLS-only. Compare authorities rather than a display
// URL or a forwarded host. Validate ports before supplying the HTTPS default.
fn authority(raw: &str) -> Option<(String, u16)> {
    if raw
        .bytes()
        .any(|b| matches!(b, b'@' | b'%' | b'/' | b'\\' | b'?' | b'#'))
    {
        return None;
    }
    let a: Authority = raw.parse().ok()?;
    let host = a.host();
    if host.is_empty() {
        return None;
    }
    let port = match raw.strip_prefix(host)? {
        "" => 443,
        rest => {
            let digits = rest.strip_prefix(':')?;
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let port = digits.parse().ok()?;
            if port == 0 {
                return None;
            }
            port
        }
    };
    let host = if let Some(v6) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        v6.parse::<std::net::Ipv6Addr>().ok()?.to_string()
    } else {
        host.parse::<IpAddr>()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| host.to_ascii_lowercase())
    };
    Some((host, port))
}
pub fn same_origin(headers: &HeaderMap) -> bool {
    fn single<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
        let mut values = h.get_all(name).iter();
        let value = values.next()?.to_str().ok()?;
        values.next().is_none().then_some(value)
    }
    let Some(origin) = single(headers, "origin")
        .and_then(|v| v.split_once("://"))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("https"))
        .and_then(|(_, a)| authority(a))
    else {
        return false;
    };
    single(headers, header::HOST.as_str()).and_then(authority) == Some(origin)
        && (!headers.contains_key("sec-fetch-site")
            || single(headers, "sec-fetch-site") == Some("same-origin"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn port_and_ipv6_normalization() {
        assert_eq!(authority("[0:0:0:0:0:0:0:1]:0443"), authority("[::1]"));
        assert_eq!(
            authority("HOST.example:443"),
            Some(("host.example".into(), 443))
        );
        for bad in [
            "a:0",
            "a:65536",
            "a:x",
            "a/b",
            "user@a",
            "a%00",
            "a?q",
            "a#fragment",
        ] {
            assert!(authority(bad).is_none())
        }
    }
}
