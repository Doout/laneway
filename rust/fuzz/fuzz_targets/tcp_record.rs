#![no_main]

use laneway_protocol::{
    TcpRecordKind, decode_packet, decode_tcp_record, encode_tcp_record_prefix, v1,
};
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let Ok((kind, payload)) = decode_tcp_record(data, 1 << 20, 5 + 1280) else {
        return;
    };
    let encoded = encode_tcp_record_prefix(kind, payload.len(), 1 << 20, 5 + 1280)
        .expect("decoded record prefix must re-encode");
    assert_eq!(encoded, data[..5]);
    match kind {
        TcpRecordKind::Control => {
            let _ = v1::ControlEnvelope::decode(payload);
        }
        TcpRecordKind::Packet => {
            let _ = decode_packet(payload);
        }
        TcpRecordKind::Ping | TcpRecordKind::Pong => assert!(payload.is_empty()),
    }
});
