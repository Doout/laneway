use std::{collections::HashSet, fs, net::IpAddr, path::Path, path::PathBuf, str::FromStr};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ipnet::IpNet;
use laneway_protocol::{
    Error, Id, PacketHeader, ProtocolVersion, Role, decode_packet, encode_packet,
    identity_from_certificate_der, negotiate_protocol, parse_spiffe_uri, read_control_frame, v1,
};
use prost::Message;
use serde::Deserialize;
use sha2::{Digest, Sha256};

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors")
}

fn read_hex(path: &str) -> Vec<u8> {
    let text = fs::read_to_string(vectors().join(path)).expect("read vector");
    hex::decode(text.split_whitespace().collect::<String>()).expect("decode vector")
}

#[derive(Deserialize)]
struct Manifest {
    digest_algorithm: String,
    fixtures: Vec<ManifestFixture>,
}

#[derive(Deserialize)]
struct ManifestFixture {
    path: String,
    encoding: String,
    decoded_byte_length: Option<usize>,
    stored_byte_length: Option<usize>,
    sha256: String,
}

fn collect_fixture_paths(root: &Path, directory: &Path, output: &mut HashSet<String>) {
    for entry in fs::read_dir(directory).expect("read vector directory") {
        let path = entry.expect("vector directory entry").path();
        if path.is_dir() {
            collect_fixture_paths(root, &path, output);
        } else if path
            .file_name()
            .is_some_and(|name| name != "README.md" && name != "manifest.json")
        {
            output.insert(
                path.strip_prefix(root)
                    .expect("fixture under root")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

#[test]
fn manifest_covers_and_authenticates_every_shared_fixture() {
    let root = vectors();
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).expect("read manifest"))
            .expect("decode manifest");
    assert_eq!(manifest.digest_algorithm, "sha256");
    let mut listed = HashSet::new();
    for fixture in manifest.fixtures {
        assert!(
            listed.insert(fixture.path.clone()),
            "duplicate fixture {}",
            fixture.path
        );
        let stored = fs::read(root.join(&fixture.path)).expect("read manifested fixture");
        assert_eq!(
            hex::encode(Sha256::digest(&stored)),
            fixture.sha256,
            "{} digest",
            fixture.path
        );
        match fixture.encoding.as_str() {
            "hex" => {
                let decoded = hex::decode(
                    String::from_utf8(stored)
                        .expect("hex fixture UTF-8")
                        .split_whitespace()
                        .collect::<String>(),
                )
                .expect("hex fixture");
                assert_eq!(
                    Some(decoded.len()),
                    fixture.decoded_byte_length,
                    "{} length",
                    fixture.path
                );
            }
            "json-utf8" | "utf8" => {
                assert_eq!(
                    Some(stored.len()),
                    fixture.stored_byte_length,
                    "{} length",
                    fixture.path
                );
            }
            other => panic!("unsupported manifest encoding {other}"),
        }
    }
    let mut present = HashSet::new();
    collect_fixture_paths(&root, &root, &mut present);
    assert_eq!(
        listed, present,
        "manifest coverage differs from fixture tree"
    );
}

#[test]
fn packet_golden_vector() {
    let wire = read_hex("packets/relay-ipv4-icmp.hex");
    let (header, payload) = decode_packet(&wire).expect("decode packet");
    assert_eq!(
        header,
        PacketHeader {
            version: 1,
            flags: 0,
            route_handle: 0x0102_0304
        }
    );
    assert_eq!(payload.len(), wire.len() - 5);
}

#[derive(Deserialize)]
struct PacketRejectCases {
    cases: Vec<PacketRejectCase>,
}

#[derive(Deserialize)]
struct PacketRejectCase {
    name: String,
    wire_hex: String,
    expected_error: String,
}

#[test]
fn packet_reject_vectors_fail_closed() {
    let cases: PacketRejectCases = serde_json::from_slice(
        &fs::read(vectors().join("packets/reject-cases.json")).expect("packet reject cases"),
    )
    .expect("decode packet reject cases");
    for case in cases.cases {
        let wire = hex::decode(case.wire_hex).expect("reject-case wire hex");
        let error = decode_packet(&wire).expect_err(&format!("{} was accepted", case.name));
        assert_eq!(
            packet_error_label(&error),
            case.expected_error,
            "{}",
            case.name
        );
    }
}

fn packet_error_label(error: &Error) -> &'static str {
    match error {
        Error::ShortPacket => "packet_too_short",
        Error::UnsupportedVersion => "unsupported_version",
        Error::InvalidPacketFlags => "invalid_packet_flags",
        Error::InvalidRouteHandle => "invalid_route_handle",
        Error::PacketTooLarge => "packet_too_large",
        Error::InvalidIpPacket => "invalid_ip_packet",
        other => panic!("unexpected packet error {other:?}"),
    }
}

#[derive(Deserialize)]
struct HeaderCases {
    cases: Vec<HeaderCase>,
}

#[derive(Deserialize)]
struct HeaderCase {
    name: String,
    version: u8,
    flags: u8,
    route_handle: u32,
    expected_hex: Option<String>,
    expected_error: Option<String>,
}

#[test]
fn packet_header_cases_are_exact() {
    let cases: HeaderCases = serde_json::from_slice(
        &fs::read(vectors().join("packets/header-cases.json")).expect("header cases"),
    )
    .expect("decode header cases");
    for case in cases.cases {
        let result = PacketHeader {
            version: case.version,
            flags: case.flags,
            route_handle: case.route_handle,
        }
        .encode();
        match (case.expected_hex, case.expected_error) {
            (Some(expected), None) => {
                let encoded = result.expect(&case.name);
                assert_eq!(hex::encode(encoded), expected, "{}", case.name);
                assert_eq!(
                    PacketHeader::decode(&encoded).unwrap().route_handle,
                    case.route_handle
                );
            }
            (None, Some(expected)) => {
                assert_eq!(
                    packet_error_label(&result.unwrap_err()),
                    expected,
                    "{}",
                    case.name
                );
            }
            _ => panic!("{} has invalid expectation", case.name),
        }
    }
}

#[derive(Deserialize)]
struct BoundaryCases {
    route_handle: u32,
    cases: Vec<BoundaryCase>,
}

#[derive(Deserialize)]
struct BoundaryCase {
    name: String,
    family: String,
    payload_length: usize,
    expected: Option<String>,
    expected_error: Option<String>,
}

fn generated_ip(family: &str, length: usize) -> Vec<u8> {
    let mut packet = vec![0_u8; length];
    match family {
        "ipv4" => {
            if length >= 4 {
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
            }
        }
        "ipv6" => {
            if length >= 6 {
                packet[0] = 0x60;
                packet[4..6].copy_from_slice(&(length.saturating_sub(40) as u16).to_be_bytes());
            }
        }
        other => panic!("unknown family {other}"),
    }
    packet
}

#[test]
fn packet_family_boundaries_are_declarative() {
    let cases: BoundaryCases = serde_json::from_slice(
        &fs::read(vectors().join("packets/boundary-cases.json")).expect("boundary cases"),
    )
    .expect("decode boundary cases");
    for case in cases.cases {
        let packet = generated_ip(&case.family, case.payload_length);
        let mut frame = Vec::new();
        let result = encode_packet(
            PacketHeader {
                version: 1,
                flags: 0,
                route_handle: cases.route_handle,
            },
            &packet,
            &mut frame,
        );
        match (case.expected.as_deref(), case.expected_error.as_deref()) {
            (Some("accept"), None) => {
                result.expect(&case.name);
                let (header, decoded) = decode_packet(&frame).expect(&case.name);
                assert_eq!(header.route_handle, cases.route_handle);
                assert_eq!(decoded.len(), case.payload_length);
            }
            (None, Some(expected)) => {
                assert_eq!(
                    packet_error_label(&result.unwrap_err()),
                    expected,
                    "{}",
                    case.name
                );
                assert!(frame.is_empty(), "{} partially encoded", case.name);
            }
            _ => panic!("{} has invalid expectation", case.name),
        }
    }
}

#[test]
fn protobuf_golden_vectors() {
    let hello = v1::ControlEnvelope::decode(read_hex("control/hello.envelope.hex").as_slice())
        .expect("hello");
    assert_eq!(hello.schema_version, 1);
    assert_eq!(hello.sequence, 1);
    let Some(v1::control_envelope::Body::Hello(hello)) = hello.body else {
        panic!("missing Hello body");
    };
    assert_eq!(
        hex::encode(&hello.network_id),
        "000102030405060708090a0b0c0d0e0f"
    );
    assert_eq!(
        hex::encode(&hello.node_id),
        "101112131415161718191a1b1c1d1e1f"
    );
    assert_eq!(
        hex::encode(&hello.boot_id),
        "202122232425262728292a2b2c2d2e2f"
    );
    assert_eq!(
        (
            hello.protocol_major,
            hello.protocol_minor,
            hello.capabilities
        ),
        (1, 0, 3)
    );

    let routes =
        v1::RouteSnapshot::decode(read_hex("routing/overlay-route-snapshot.hex").as_slice())
            .expect("routes");
    assert_eq!(routes.configuration_epoch, 7);
    assert_eq!(routes.routes.len(), 1);
    assert_eq!(
        routes.encode_to_vec(),
        read_hex("routing/overlay-route-snapshot.hex")
    );

    let welcome = v1::ControlEnvelope::decode(read_hex("control/welcome.envelope.hex").as_slice())
        .expect("welcome");
    let Some(v1::control_envelope::Body::Welcome(welcome)) = welcome.body else {
        panic!("missing Welcome body");
    };
    assert_eq!(welcome.configuration_epoch, 7);
    assert_eq!(welcome.max_control_payload, 1 << 20);
    assert_eq!(welcome.max_packet_payload, 1200);

    let denied =
        v1::ControlEnvelope::decode(read_hex("control/permission-denied.envelope.hex").as_slice())
            .expect("permission denied");
    let Some(v1::control_envelope::Body::Error(denied)) = denied.body else {
        panic!("missing ProtocolError body");
    };
    assert_eq!(denied.code, v1::ErrorCode::PermissionDenied as i32);
    assert_eq!(denied.detail, "denied");
}

#[test]
fn route_controller_frame_golden_vector() {
    let frame = read_hex("routing/overlay-route-controller.frame.hex");
    assert!(frame.len() >= 4);
    assert_eq!(
        u32::from_be_bytes(frame[..4].try_into().expect("four-byte frame prefix")) as usize,
        frame.len() - 4
    );
    let payload = read_control_frame(&mut frame.as_slice(), 1 << 20).expect("controller frame");
    let envelope = v1::ControllerEnvelope::decode(payload.as_slice()).expect("controller envelope");
    assert_eq!((envelope.schema_version, envelope.request_id), (1, 42));
    let Some(v1::controller_envelope::Body::NodeConfiguration(configuration)) = envelope.body
    else {
        panic!("missing NodeConfiguration body");
    };
    assert_eq!(configuration.configuration_epoch, 7);
    assert_eq!(configuration.valid_until_unix_seconds, 4_102_444_800);
    let routes = configuration.routes.as_ref().expect("route snapshot");
    assert_eq!(
        hex::encode(&routes.network_id),
        "000102030405060708090a0b0c0d0e0f"
    );
    assert_eq!(routes.configuration_epoch, 7);
    assert_eq!(routes.routes.len(), 1);
    let route = &routes.routes[0];
    let destination = route.destination.as_ref().expect("route destination");
    assert_eq!(destination.address, [100, 96, 0, 2]);
    assert_eq!(destination.prefix_length, 32);
    assert_eq!(route.kind, v1::RouteKind::Overlay as i32);
    assert_eq!(route.metric, 10);
    assert_eq!(
        hex::encode(&route.via_node_id),
        "101112131415161718191a1b1c1d1e1f"
    );
    assert_eq!(
        hex::encode(&route.route_id),
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    );

    let reencoded = v1::ControllerEnvelope {
        schema_version: 1,
        request_id: 42,
        body: Some(v1::controller_envelope::Body::NodeConfiguration(
            configuration,
        )),
    }
    .encode_to_vec();
    assert_eq!(reencoded, payload);
}

#[test]
fn additional_binary_vectors() {
    let ipv6 = read_hex("packets/relay-ipv6-empty.hex");
    let (header, packet) = decode_packet(&ipv6).expect("IPv6 packet");
    assert_eq!(header.route_handle, 0x0a0b_0c0d);
    assert_eq!(packet.len(), 40);
    assert_eq!(packet[0] >> 4, 6);

    let probe = read_hex("direct/probe-request.hex");
    let decoded_probe = laneway_protocol::decode_direct_probe(&probe).expect("direct probe");
    assert!(!decoded_probe.response);
    assert_eq!(
        decoded_probe.token,
        <[u8; 16]>::try_from((0_u8..16).collect::<Vec<_>>()).unwrap()
    );
    assert_eq!(
        decoded_probe.sender.to_string(),
        "101112131415161718191a1b1c1d1e1f"
    );
    assert_eq!(
        decoded_probe.recipient.to_string(),
        "202122232425262728292a2b2c2d2e2f"
    );

    let record = read_hex("tcp/packet-record.hex");
    assert_eq!(
        u32::from_be_bytes(record[..4].try_into().expect("length")) as usize,
        record.len() - 4
    );
    assert_eq!(record[4], 2);
    let (header, packet) = decode_packet(&record[5..]).expect("TCP packet record");
    assert_eq!(
        header,
        PacketHeader {
            version: 1,
            flags: 0,
            route_handle: 0x0102_0304
        }
    );
    assert_eq!(&packet[12..20], &[100, 96, 0, 1, 100, 96, 0, 2]);
}

#[derive(Deserialize)]
struct CapabilityCases {
    known_mask: u64,
    cases: Vec<CapabilityCase>,
}

#[derive(Deserialize)]
struct CapabilityCase {
    name: String,
    local: u64,
    remote: u64,
    required: u64,
    #[serde(default)]
    expected: u64,
    expected_error: Option<String>,
    local_version: ProtocolVersionFixture,
    remote_version: ProtocolVersionFixture,
    expected_version: Option<ProtocolVersionFixture>,
}

#[derive(Clone, Copy, Deserialize)]
struct ProtocolVersionFixture {
    major: u32,
    minor: u32,
}

#[test]
fn capability_json_cases() {
    let cases: CapabilityCases = serde_json::from_slice(
        &fs::read(vectors().join("control/capability-cases.json")).expect("capability cases"),
    )
    .expect("parse capability cases");
    assert_eq!(cases.known_mask, 255);
    for case in cases.cases {
        let result = negotiate_protocol(
            ProtocolVersion {
                major: case.local_version.major,
                minor: case.local_version.minor,
            },
            ProtocolVersion {
                major: case.remote_version.major,
                minor: case.remote_version.minor,
            },
            case.local,
            case.remote,
            cases.known_mask,
            case.required,
        );
        if let Some(expected) = case.expected_error {
            let error = result.expect_err(&format!("{} unexpectedly negotiated", case.name));
            let actual = match error {
                Error::IncompatibleVersion => "incompatible_version",
                Error::IncompatibleCapabilities => "incompatible_capabilities",
                other => panic!("unexpected negotiation error {other:?}"),
            };
            assert_eq!(actual, expected, "{}", case.name);
        } else {
            let (version, capabilities) = result.expect(&case.name);
            assert_eq!(capabilities, case.expected, "{}", case.name);
            let expected = case.expected_version.expect("successful version");
            assert_eq!(
                version,
                ProtocolVersion {
                    major: expected.major,
                    minor: expected.minor
                }
            );
        }
    }
}

#[derive(Deserialize)]
struct IdentityCases {
    network_id_hex: String,
    authenticated_node_id_hex: String,
    cases: Vec<IdentityCase>,
}

#[derive(Deserialize)]
struct IdentityCase {
    uri_sans: Vec<String>,
    message_node_id_hex: String,
    expected: String,
}

#[test]
fn identity_json_cases() {
    let cases: IdentityCases = serde_json::from_slice(
        &fs::read(vectors().join("certificates/identity-cases.json")).expect("identity cases"),
    )
    .expect("parse identity cases");
    let expected_network = Id::from_str(&cases.network_id_hex).expect("network ID");
    let expected_node = Id::from_str(&cases.authenticated_node_id_hex).expect("node ID");
    for case in cases.cases {
        let parsed = case
            .uri_sans
            .first()
            .map(|uri| parse_spiffe_uri(uri))
            .transpose();
        let outcome = match parsed {
            Ok(Some(identity)) if identity.network_id != expected_network => {
                "reject_network_mismatch"
            }
            Ok(Some(identity))
                if identity.subject_id
                    != Id::from_str(&case.message_node_id_hex).expect("message node ID") =>
            {
                "reject_node_mismatch"
            }
            Ok(Some(identity)) if identity.subject_id == expected_node => "accept",
            Ok(Some(_)) => "reject_node_mismatch",
            Ok(None) => "reject_missing_identity",
            Err(_) => "reject_malformed_identity",
        };
        assert_eq!(outcome, case.expected, "{:?}", case.uri_sans);
    }
}

#[derive(Deserialize)]
struct CertificateDerCases {
    cases: Vec<CertificateDerCase>,
}

#[derive(Deserialize)]
struct CertificateDerCase {
    name: String,
    der_base64: String,
    expected: String,
    network_id_hex: Option<String>,
    role: Option<String>,
    subject_id_hex: Option<String>,
}

#[test]
fn shared_certificate_der_cases_use_production_parser() {
    let cases: CertificateDerCases = serde_json::from_slice(
        &fs::read(vectors().join("certificates/der-cases.json")).expect("certificate DER cases"),
    )
    .expect("parse certificate DER cases");
    for case in cases.cases {
        let der = BASE64.decode(&case.der_base64).expect("fixture base64");
        let parsed = identity_from_certificate_der(&der);
        let outcome = match &parsed {
            Ok(_) => "accept",
            Err(Error::IdentitySanCount) => "reject_identity_san_count",
            Err(Error::InvalidIdentity) => "reject_malformed_identity",
            Err(Error::InvalidCertificate) => "reject_invalid_certificate",
            Err(other) => panic!("{}: unexpected error {other:?}", case.name),
        };
        assert_eq!(outcome, case.expected, "{}", case.name);
        if let Ok(identity) = parsed {
            assert_eq!(
                identity.network_id,
                Id::from_str(case.network_id_hex.as_deref().expect("accepted network ID"))
                    .expect("network ID"),
                "{} network",
                case.name
            );
            assert_eq!(
                identity.subject_id,
                Id::from_str(case.subject_id_hex.as_deref().expect("accepted subject ID"))
                    .expect("subject ID"),
                "{} subject",
                case.name
            );
            let expected_role = match case.role.as_deref() {
                Some("node") => Role::Node,
                Some("relay") => Role::Relay,
                Some("controller") => Role::Controller,
                other => panic!("{}: invalid fixture role {other:?}", case.name),
            };
            assert_eq!(identity.role, expected_role, "{} role", case.name);
        }
    }
}

#[derive(Deserialize)]
struct RoutingSemanticCases {
    routes: Vec<RoutingFixture>,
    lookups: Vec<RoutingLookup>,
    source_authorization: Vec<SourceAuthorization>,
    invalid_sets: Vec<InvalidRouteSet>,
}

#[derive(Clone, Deserialize)]
struct RoutingFixture {
    #[serde(default)]
    id: String,
    prefix: String,
    metric: u32,
    next_hop: String,
    handle: u32,
}

#[derive(Deserialize)]
struct RoutingLookup {
    name: String,
    destination: IpAddr,
    expected_route_id: Option<String>,
    expected: Option<String>,
}

#[derive(Deserialize)]
struct SourceAuthorization {
    name: String,
    source: IpAddr,
    peer: String,
    expected: bool,
}

#[derive(Deserialize)]
struct InvalidRouteSet {
    name: String,
    expected_error: String,
    routes: Vec<RoutingFixture>,
}

#[derive(Clone, Debug)]
struct CompiledRouteFixture {
    id: String,
    prefix: IpNet,
    metric: u32,
    next_hop: Id,
    handle: u32,
}

fn compile_routes(fixtures: &[RoutingFixture]) -> Result<Vec<CompiledRouteFixture>, &'static str> {
    let mut routes = Vec::with_capacity(fixtures.len());
    let mut ties = HashSet::new();
    for fixture in fixtures {
        let prefix = fixture
            .prefix
            .parse::<IpNet>()
            .map_err(|_| "invalid_prefix")?;
        if prefix.trunc() != prefix
            || matches!(prefix, IpNet::V6(value) if value.addr().to_ipv4_mapped().is_some())
        {
            return Err("invalid_prefix");
        }
        if !ties.insert((prefix, fixture.metric)) {
            return Err("ambiguous_route");
        }
        routes.push(CompiledRouteFixture {
            id: fixture.id.clone(),
            prefix,
            metric: fixture.metric,
            next_hop: fixture.next_hop.parse().map_err(|_| "invalid_next_hop")?,
            handle: fixture.handle,
        });
    }
    routes.sort_by(|left, right| {
        right
            .prefix
            .prefix_len()
            .cmp(&left.prefix.prefix_len())
            .then_with(|| left.metric.cmp(&right.metric))
            .then_with(|| left.next_hop.cmp(&right.next_hop))
            .then_with(|| left.handle.cmp(&right.handle))
    });
    Ok(routes)
}

fn select_route(routes: &[CompiledRouteFixture], address: IpAddr) -> Option<&CompiledRouteFixture> {
    routes.iter().find(|route| route.prefix.contains(&address))
}

#[test]
fn routing_semantics_cover_validation_lpm_ties_and_source_ownership() {
    let cases: RoutingSemanticCases = serde_json::from_slice(
        &fs::read(vectors().join("routing/semantic-cases.json")).expect("routing cases"),
    )
    .expect("decode routing cases");
    let routes = compile_routes(&cases.routes).expect("compile valid routes");
    for case in cases.lookups {
        let selected = select_route(&routes, case.destination);
        if case.expected.as_deref() == Some("no_match") {
            assert!(selected.is_none(), "{} unexpectedly matched", case.name);
        } else {
            assert_eq!(
                selected.map(|route| route.id.as_str()),
                case.expected_route_id.as_deref(),
                "{}",
                case.name
            );
        }
    }
    for case in cases.source_authorization {
        let peer: Id = case.peer.parse().expect("source peer");
        let authorized =
            select_route(&routes, case.source).is_some_and(|route| route.next_hop == peer);
        assert_eq!(authorized, case.expected, "{}", case.name);
    }
    for case in cases.invalid_sets {
        assert_eq!(
            compile_routes(&case.routes).unwrap_err(),
            case.expected_error,
            "{}",
            case.name
        );
    }
}
