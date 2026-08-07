#![no_main]

use laneway_protocol::decode_direct_probe;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(probe) = decode_direct_probe(data) {
        assert_eq!(data.len(), 54);
        assert_ne!(probe.token, [0; 16]);
        assert_ne!(probe.sender, probe.recipient);
        assert_eq!(probe.response, data[5] == 2);
    }
});
