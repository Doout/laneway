#![no_main]

use laneway_protocol::{decode_packet, encode_packet};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((header, packet)) = decode_packet(data) {
        let mut encoded = Vec::with_capacity(data.len());
        encode_packet(header, packet, &mut encoded).expect("decoded packet must re-encode");
        assert_eq!(encoded, data);
    }
});
