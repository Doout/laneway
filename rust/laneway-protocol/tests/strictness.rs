use std::{io::Cursor, str::FromStr};

use laneway_protocol::{
    Error, Id, PacketHeader, TcpRecordKind, decode_packet, decode_tcp_record,
    decode_tcp_record_prefix, encode_tcp_record_prefix, negotiate_capabilities, parse_spiffe_uri,
    read_control_frame, write_control_frame,
};

#[test]
fn identifiers_are_nonzero_lowercase_and_exact() {
    let valid = Id::from_str("000102030405060708090a0b0c0d0e0f").expect("valid ID");
    assert_eq!(valid.to_string(), "000102030405060708090a0b0c0d0e0f");
    assert_eq!(
        Id::from_str("00000000000000000000000000000000"),
        Err(Error::InvalidId)
    );
    assert_eq!(
        Id::from_str("000102030405060708090A0B0C0D0E0F"),
        Err(Error::InvalidId)
    );
    assert_eq!(Id::from_slice(&[1; 15]), Err(Error::InvalidId));
}

#[test]
fn identity_parser_rejects_ambiguous_uri_forms() {
    let valid = parse_spiffe_uri(
        "spiffe://laneway/network/000102030405060708090a0b0c0d0e0f/node/101112131415161718191a1b1c1d1e1f",
    )
    .expect("valid identity");
    assert_eq!(
        valid.network_id.to_string(),
        "000102030405060708090a0b0c0d0e0f"
    );
    for invalid in [
        "spiffe://other/network/000102030405060708090a0b0c0d0e0f/node/101112131415161718191a1b1c1d1e1f",
        "spiffe://laneway/network/000102030405060708090a0b0c0d0e0f/node/101112131415161718191a1b1c1d1e1f/extra",
        "spiffe://laneway/network/000102030405060708090a0b0c0d0e0f/node/101112131415161718191a1b1c1d1e1f?query",
        "spiffe://laneway/network/000102030405060708090a0b0c0d0e0f/unknown/101112131415161718191a1b1c1d1e1f",
    ] {
        assert_eq!(parse_spiffe_uri(invalid), Err(Error::InvalidIdentity));
    }
}

#[test]
fn capability_negotiation_is_an_intersection_and_fail_closed() {
    assert_eq!(
        negotiate_capabilities(0b111, 0b011, 0b111, 0b001),
        Ok(0b011)
    );
    assert_eq!(
        negotiate_capabilities(0b1011, 0b0011, 0b0111, 0b0001),
        Ok(0b0011)
    );
    assert_eq!(
        negotiate_capabilities(0b011, 0b010, 0b111, 0b001),
        Err(Error::IncompatibleCapabilities)
    );
}

#[test]
fn control_frames_round_trip_and_enforce_bounds_before_payload_reads() {
    let mut wire = Vec::new();
    write_control_frame(b"laneway", 32, &mut wire).expect("frame");
    assert_eq!(
        read_control_frame(&mut Cursor::new(wire), 32).expect("read"),
        b"laneway"
    );

    let mut oversized = Cursor::new([0, 0, 1, 0]);
    assert_eq!(
        read_control_frame(&mut oversized, 32),
        Err(Error::FrameTooLarge)
    );
    assert_eq!(
        write_control_frame(&[], 32, &mut Vec::new()),
        Err(Error::FrameTooLarge)
    );
}

#[test]
fn packet_decoder_rejects_reserved_bits_zero_handles_and_length_mismatch() {
    assert_eq!(
        PacketHeader {
            version: 1,
            flags: 1,
            route_handle: 1
        }
        .encode(),
        Err(Error::InvalidPacketFlags)
    );
    assert_eq!(
        PacketHeader {
            version: 1,
            flags: 0,
            route_handle: 0
        }
        .encode(),
        Err(Error::InvalidRouteHandle)
    );

    let bad_ipv4 = [
        0x10, 0, 0, 0, 1, 0x45, 0, 0, 21, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
    ];
    assert_eq!(decode_packet(&bad_ipv4), Err(Error::InvalidIpPacket));
}

#[test]
fn tcp_record_prefix_is_exact_bounded_and_round_trips() {
    let prefix = encode_tcp_record_prefix(TcpRecordKind::Packet, 25, 1024, 1280).unwrap();
    assert_eq!(prefix, [0, 0, 0, 26, 2]);
    let header = decode_tcp_record_prefix(&prefix, 1024, 1280).unwrap();
    assert_eq!(header.kind, TcpRecordKind::Packet);
    assert_eq!(header.payload_length, 25);

    let mut record = prefix.to_vec();
    record.extend_from_slice(&[0xaa; 25]);
    let (kind, payload) = decode_tcp_record(&record, 1024, 1280).unwrap();
    assert_eq!(kind, TcpRecordKind::Packet);
    assert_eq!(payload, [0xaa; 25]);

    assert_eq!(
        decode_tcp_record_prefix(&[0, 0, 0, 0, 1], 1024, 1280),
        Err(Error::InvalidTcpRecord)
    );
    assert_eq!(
        decode_tcp_record_prefix(&[0, 0, 0, 1, 99], 1024, 1280),
        Err(Error::InvalidTcpRecord)
    );
    assert_eq!(
        decode_tcp_record_prefix(&[0, 0, 0, 2, 3], 1024, 1280),
        Err(Error::FrameTooLarge)
    );
    assert_eq!(
        decode_tcp_record(&record[..record.len() - 1], 1024, 1280),
        Err(Error::InvalidTcpRecord)
    );
}
