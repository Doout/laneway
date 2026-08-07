#![no_main]

use std::io::Cursor;

use laneway_protocol::{read_control_frame, v1, write_control_frame};
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let maximum = data
        .first()
        .map_or(256, |value| usize::from(*value).max(1) * 16);
    let wire = data.get(1..).unwrap_or_default();
    let mut cursor = Cursor::new(wire);
    if let Ok(payload) = read_control_frame(&mut cursor, maximum) {
        let mut encoded = Vec::new();
        write_control_frame(&payload, maximum, &mut encoded)
            .expect("accepted control payload must re-encode");
        assert_eq!(&encoded, &wire[..encoded.len()]);
        let _ = v1::ControlEnvelope::decode(payload.as_slice());
    }
});
