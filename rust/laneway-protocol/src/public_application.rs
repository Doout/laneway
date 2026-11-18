//! Restricted Laneway application access over the relay's public HTTPS path.
use crate::Id;

/// Relay-to-controller credential header. Never accept this header from a
/// browser or treat it as delegated authority without authenticating the relay.
pub const ACCESS_HEADER: &str = "x-laneway-relay-application-access";

/// Endpoints available to an application over public HTTPS. The controller
/// still authenticates its installation and checks operation and network grants.
pub fn route_allowed(method: &str, path: &str) -> bool {
    let mut parts = path.split('/');
    if parts.next() != Some("") || parts.next() != Some("v1") || parts.next() != Some("admin") {
        return false;
    }
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("networks"), Some(id), extension, None) if id.parse::<Id>().is_ok() => {
            match extension {
                None | Some("nodes" | "endpoint-statuses" | "routes") => {
                    matches!(method, "GET" | "HEAD")
                }
                Some("node-installers") => method == "POST",
                _ => false,
            }
        }
        (Some("routes"), Some("assign"), None, None) => method == "POST",
        _ => false,
    }
}

/// Recognize the shared service-token wire shape. This does not establish
/// that an application issued the token; the controller verifies its origin.
pub fn candidate(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let mut parts = token.split('.');
    if let (Some("lnw_spat_v1"), Some(id), Some(secret), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
        && id.parse::<Id>().is_ok()
        && secret.len() == 43
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Some(token);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_management_operations_covered_by_application_scopes_are_public() {
        const NET: &str = "01234567890123456789012345678901";
        let network = format!("/v1/admin/networks/{NET}");
        assert!(route_allowed("GET", &network));
        assert!(route_allowed("HEAD", &format!("{network}/routes")));
        assert!(route_allowed(
            "GET",
            &format!("{network}/endpoint-statuses")
        ));
        assert!(route_allowed("POST", &format!("{network}/node-installers")));
        assert!(route_allowed("POST", "/v1/admin/routes/assign"));
        for (method, path) in [
            ("DELETE", network.clone()),
            ("GET", "/v1/admin/networks".into()),
            ("POST", format!("{network}/nodes")),
            ("POST", format!("{network}/node-installers/")),
            ("GET", format!("{network}/application-installations")),
            ("HEAD", "/v1/admin/routes/assign".into()),
            ("POST", "/v1/admin/auth/root".into()),
            ("GET", "/v1/admin/networks/%2e%2e".into()),
        ] {
            assert!(!route_allowed(method, &path));
        }
        assert!(candidate(&format!("Bearer lnw_spat_v1.{NET}.{}", "A".repeat(43))).is_some());
        assert!(candidate("Bearer unscoped-root").is_none());
    }
}
