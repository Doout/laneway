#![no_main]

use laneway_protocol::parse_spiffe_uri;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(identity) = parse_spiffe_uri(value) {
        assert!(value.starts_with("spiffe://laneway/network/"));
        assert!(value.contains(&identity.network_id.to_string()));
        assert!(value.ends_with(&identity.subject_id.to_string()));
        assert!(!value.contains(['%', '?', '#']));
    }
});
