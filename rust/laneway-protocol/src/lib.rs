#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Laneway v1 identifiers, packet framing, certificate identity,
//! capabilities, control framing, and generated Protobuf messages.

use std::{fmt, io, str::FromStr};

use thiserror::Error;
use x509_parser::{extensions::GeneralName, prelude::*};

pub mod policy;

/// Generated `laneway.v1` Protobuf messages.
#[allow(missing_docs)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/laneway.v1.rs"));
}

/// Exact length of every persistent Laneway identifier.
pub const ID_LEN: usize = 16;
/// Exact size of the Laneway v1 packet header.
pub const PACKET_HEADER_LEN: usize = 5;
/// Packet flag for an opaque, end-to-end encrypted WireGuard UDP datagram.
pub const PACKET_FLAG_E2E_ENCRYPTED: u8 = 1;
/// Maximum v1 raw IP payload supported by the language-neutral format.
pub const MAX_PACKET_PAYLOAD: usize = 65_575;
/// Default maximum length-prefixed Protobuf payload.
pub const DEFAULT_MAX_CONTROL_PAYLOAD: usize = 1 << 20;
/// Exact size of the stable-v1 TCP fallback record prefix.
pub const TCP_RECORD_PREFIX_LEN: usize = 5;

/// Errors shared by parsing and conformance operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// An identifier was zero, malformed, or noncanonical.
    #[error("invalid Laneway identifier")]
    InvalidId,
    /// A SPIFFE URI did not match the exact Laneway grammar.
    #[error("invalid Laneway SPIFFE identity")]
    InvalidIdentity,
    /// A certificate contained zero or multiple Laneway identity URI SANs.
    #[error("certificate must contain exactly one Laneway identity URI SAN")]
    IdentitySanCount,
    /// DER input was not a valid X.509 certificate.
    #[error("invalid X.509 certificate")]
    InvalidCertificate,
    /// A packet header or raw IP payload was malformed.
    #[error("invalid Laneway packet")]
    InvalidPacket,
    /// A packet was shorter than the required framing or IP header.
    #[error("Laneway packet is too short")]
    ShortPacket,
    /// The packet framing version is unsupported.
    #[error("unsupported Laneway packet version")]
    UnsupportedVersion,
    /// Reserved packet flag bits were nonzero.
    #[error("invalid Laneway packet flags")]
    InvalidPacketFlags,
    /// The session-local route handle was zero.
    #[error("invalid Laneway route handle")]
    InvalidRouteHandle,
    /// The raw IP packet exceeded the stable-v1 bound.
    #[error("Laneway packet payload is too large")]
    PacketTooLarge,
    /// The raw IPv4 or IPv6 structure was malformed.
    #[error("invalid IP packet in Laneway frame")]
    InvalidIpPacket,
    /// The opaque payload is not one exact stable WireGuard UDP message.
    #[error("invalid WireGuard packet in Laneway frame")]
    InvalidWireGuardPacket,
    /// A stable-v1 TCP fallback record had invalid framing or type.
    #[error("invalid Laneway TCP fallback record")]
    InvalidTcpRecord,
    /// A frame exceeded the configured bound.
    #[error("frame exceeds configured bound")]
    FrameTooLarge,
    /// Negotiation could not meet required known capability bits.
    #[error("incompatible Laneway capabilities")]
    IncompatibleCapabilities,
    /// The protocol major version was not stable-v1.
    #[error("incompatible Laneway protocol version")]
    IncompatibleVersion,
    /// A control frame could not be read completely.
    #[error("control frame I/O: {0}")]
    Io(String),
}

/// An immutable opaque 128-bit identifier.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Id([u8; ID_LEN]);

impl Id {
    /// Validates and constructs an identifier from its wire bytes.
    pub fn new(bytes: [u8; ID_LEN]) -> Result<Self, Error> {
        if bytes == [0; ID_LEN] {
            return Err(Error::InvalidId);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact 16-byte wire representation.
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    /// Copies a validated identifier from a wire slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; ID_LEN] = bytes.try_into().map_err(|_| Error::InvalidId)?;
        Self::new(bytes)
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for Id {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::InvalidId);
        }
        let mut bytes = [0; ID_LEN];
        hex::decode_to_slice(value, &mut bytes).map_err(|_| Error::InvalidId)?;
        Self::new(bytes)
    }
}

/// Certificate workload role encoded in a Laneway SPIFFE URI.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Role {
    /// A network node.
    Node,
    /// A packet relay service.
    Relay,
    /// A controller service.
    Controller,
}

impl Role {
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "node" => Ok(Self::Node),
            "relay" => Ok(Self::Relay),
            "controller" => Ok(Self::Controller),
            _ => Err(Error::InvalidIdentity),
        }
    }
}

/// Identity authenticated from an exact Laneway URI SAN.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct AuthenticatedIdentity {
    /// Network isolation boundary.
    pub network_id: Id,
    /// Workload profile.
    pub role: Role,
    /// Node ID for nodes, service ID otherwise.
    pub subject_id: Id,
}

/// Parses the exact `spiffe://laneway/network/...` URI profile.
pub fn parse_spiffe_uri(value: &str) -> Result<AuthenticatedIdentity, Error> {
    if value.contains(['%', '?', '#']) || !value.starts_with("spiffe://laneway/network/") {
        return Err(Error::InvalidIdentity);
    }
    let rest = &value["spiffe://laneway/network/".len()..];
    let parts: Vec<_> = rest.split('/').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(Error::InvalidIdentity);
    }
    Ok(AuthenticatedIdentity {
        network_id: parts[0].parse().map_err(|_| Error::InvalidIdentity)?,
        role: Role::parse(parts[1])?,
        subject_id: parts[2].parse().map_err(|_| Error::InvalidIdentity)?,
    })
}

/// Extracts the sole Laneway identity URI SAN from a DER certificate.
/// Chain and EKU verification remains the TLS implementation's responsibility.
pub fn identity_from_certificate_der(der: &[u8]) -> Result<AuthenticatedIdentity, Error> {
    let (_, certificate) = parse_x509_certificate(der).map_err(|_| Error::InvalidCertificate)?;
    let mut found = None;
    for extension in certificate.extensions() {
        let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() else {
            continue;
        };
        for name in &san.general_names {
            let GeneralName::URI(uri) = name else {
                continue;
            };
            if !uri.starts_with("spiffe://laneway/") {
                continue;
            }
            let parsed = parse_spiffe_uri(uri)?;
            if found.replace(parsed).is_some() {
                return Err(Error::IdentitySanCount);
            }
        }
    }
    found.ok_or(Error::IdentitySanCount)
}

/// Extracts the canonical unsigned certificate serial representation used by
/// Go `big.Int.Bytes()` and controller revocation snapshots.
pub fn certificate_serial_from_der(der: &[u8]) -> Result<Vec<u8>, Error> {
    let (_, certificate) = parse_x509_certificate(der).map_err(|_| Error::InvalidCertificate)?;
    let raw = certificate.raw_serial();
    let serial = match raw {
        [0, next, rest @ ..] if next & 0x80 != 0 => {
            let mut serial = Vec::with_capacity(1 + rest.len());
            serial.push(*next);
            serial.extend_from_slice(rest);
            serial
        }
        [0, ..] => return Err(Error::InvalidCertificate),
        _ => raw.to_vec(),
    };
    if serial.is_empty() || serial.len() > 32 {
        return Err(Error::InvalidCertificate);
    }
    Ok(serial)
}

/// Laneway packet v1 header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketHeader {
    /// Four-bit packet format version.
    pub version: u8,
    /// Four-bit flags value.
    pub flags: u8,
    /// Session-local nonzero routing handle.
    pub route_handle: u32,
}

impl PacketHeader {
    /// Encodes the exact five-byte network-order packet header.
    pub fn encode(self) -> Result<[u8; PACKET_HEADER_LEN], Error> {
        if self.version != 1 {
            return Err(Error::UnsupportedVersion);
        }
        if self.flags != 0 && self.flags != PACKET_FLAG_E2E_ENCRYPTED {
            return Err(Error::InvalidPacketFlags);
        }
        if self.route_handle == 0 {
            return Err(Error::InvalidRouteHandle);
        }
        let handle = self.route_handle.to_be_bytes();
        Ok([
            0x10 | self.flags,
            handle[0],
            handle[1],
            handle[2],
            handle[3],
        ])
    }

    /// Decodes and strictly validates a five-byte packet header.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < PACKET_HEADER_LEN {
            return Err(Error::ShortPacket);
        }
        let header = Self {
            version: bytes[0] >> 4,
            flags: bytes[0] & 0x0f,
            route_handle: u32::from_be_bytes(bytes[1..5].try_into().expect("fixed slice")),
        };
        header.encode()?;
        Ok(header)
    }
}

/// Decodes one complete framed IPv4 or IPv6 packet without allocating.
pub fn decode_packet(frame: &[u8]) -> Result<(PacketHeader, &[u8]), Error> {
    let (header, payload) = decode_frame(frame)?;
    if header.flags != 0 {
        return Err(Error::InvalidPacketFlags);
    }
    Ok((header, payload))
}

/// Decodes either a plaintext IP frame or an opaque WireGuard frame.
pub fn decode_frame(frame: &[u8]) -> Result<(PacketHeader, &[u8]), Error> {
    if frame.len() <= PACKET_HEADER_LEN {
        return Err(Error::ShortPacket);
    }
    let header = PacketHeader::decode(frame)?;
    let payload = &frame[PACKET_HEADER_LEN..];
    if payload.len() > MAX_PACKET_PAYLOAD {
        return Err(Error::PacketTooLarge);
    }
    match header.flags {
        0 => validate_ip_packet(payload)?,
        PACKET_FLAG_E2E_ENCRYPTED => validate_wireguard_packet(payload)?,
        _ => return Err(Error::InvalidPacketFlags),
    }
    Ok((header, payload))
}

/// Encodes a packet into a caller-provided vector.
pub fn encode_packet(
    header: PacketHeader,
    payload: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    if header.flags != 0 {
        return Err(Error::InvalidPacketFlags);
    }
    let encoded_header = header.encode()?;
    if payload.len() > MAX_PACKET_PAYLOAD {
        return Err(Error::PacketTooLarge);
    }
    validate_ip_packet(payload)?;
    output.extend_from_slice(&encoded_header);
    output.extend_from_slice(payload);
    Ok(())
}

/// Encodes one opaque WireGuard UDP datagram for relay carriage.
pub fn encode_wireguard_packet(
    route_handle: u32,
    payload: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    let header = PacketHeader {
        version: 1,
        flags: PACKET_FLAG_E2E_ENCRYPTED,
        route_handle,
    }
    .encode()?;
    if payload.len() > MAX_PACKET_PAYLOAD {
        return Err(Error::PacketTooLarge);
    }
    validate_wireguard_packet(payload)?;
    output.extend_from_slice(&header);
    output.extend_from_slice(payload);
    Ok(())
}

/// Validates the public shape of one stable WireGuard UDP message.
pub fn validate_wireguard_packet(packet: &[u8]) -> Result<(), Error> {
    if packet.len() < 4 || packet[1..4] != [0, 0, 0] {
        return Err(Error::InvalidWireGuardPacket);
    }
    let message_type = u32::from_le_bytes(packet[..4].try_into().expect("fixed slice"));
    let valid = match message_type {
        1 => packet.len() == 148,
        2 => packet.len() == 92,
        3 => packet.len() == 64,
        4 => packet.len() >= 32 && packet.len().is_multiple_of(16),
        _ => false,
    };
    if !valid {
        return Err(Error::InvalidWireGuardPacket);
    }
    Ok(())
}

fn validate_ip_packet(packet: &[u8]) -> Result<(), Error> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => {
            if packet.len() < 20 {
                return Err(Error::ShortPacket);
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if header_len < 20
                || header_len > packet.len()
                || total_len < header_len
                || total_len != packet.len()
            {
                return Err(Error::InvalidIpPacket);
            }
            Ok(())
        }
        Some(6) => {
            if packet.len() < 40 {
                return Err(Error::ShortPacket);
            }
            let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if payload_len + 40 != packet.len() {
                return Err(Error::InvalidIpPacket);
            }
            Ok(())
        }
        _ => Err(Error::InvalidIpPacket),
    }
}

/// Stable protocol version negotiated independently from capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolVersion {
    /// Stable protocol major version.
    pub major: u32,
    /// Backward-compatible protocol minor version.
    pub minor: u32,
}

/// Negotiates stable-v1 version and known capability intersection.
pub fn negotiate_protocol(
    local_version: ProtocolVersion,
    remote_version: ProtocolVersion,
    local_capabilities: u64,
    remote_capabilities: u64,
    known: u64,
    required: u64,
) -> Result<(ProtocolVersion, u64), Error> {
    if local_version.major != 1 || remote_version.major != 1 {
        return Err(Error::IncompatibleVersion);
    }
    let capabilities =
        negotiate_capabilities(local_capabilities, remote_capabilities, known, required)?;
    Ok((
        ProtocolVersion {
            major: 1,
            minor: local_version.minor.min(remote_version.minor),
        },
        capabilities,
    ))
}

/// Decoded fixed-size direct-path reachability probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectProbe {
    /// True for a response, false for a request.
    pub response: bool,
    /// Nonzero rendezvous token.
    pub token: [u8; 16],
    /// Authenticated sender node encoded in the probe.
    pub sender: Id,
    /// Intended recipient node encoded in the probe.
    pub recipient: Id,
}

/// Decodes the exact 54-byte stable-v1 direct probe format.
pub fn decode_direct_probe(packet: &[u8]) -> Result<DirectProbe, Error> {
    if packet.len() != 54 {
        return Err(Error::InvalidPacket);
    }
    if &packet[..5] != b"\x0cWHP\x01" || !matches!(packet[5], 1 | 2) {
        return Err(Error::InvalidPacket);
    }
    let token: [u8; 16] = packet[6..22].try_into().map_err(|_| Error::InvalidPacket)?;
    if token == [0; 16] {
        return Err(Error::InvalidPacket);
    }
    let sender = Id::from_slice(&packet[22..38]).map_err(|_| Error::InvalidPacket)?;
    let recipient = Id::from_slice(&packet[38..54]).map_err(|_| Error::InvalidPacket)?;
    if sender == recipient {
        return Err(Error::InvalidPacket);
    }
    Ok(DirectProbe {
        response: packet[5] == 2,
        token,
        sender,
        recipient,
    })
}

/// Stable-v1 TCP fallback record discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpRecordKind {
    /// Protobuf control envelope.
    Control = 1,
    /// Laneway packet frame.
    Packet = 2,
    /// Empty keepalive request.
    Ping = 3,
    /// Empty keepalive response.
    Pong = 4,
}

impl TcpRecordKind {
    /// Returns the stable-v1 one-byte wire value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Validated metadata from one stable-v1 TCP fallback record prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpRecordHeader {
    /// Record discriminator.
    pub kind: TcpRecordKind,
    /// Payload bytes following the one-byte discriminator.
    pub payload_length: usize,
}

/// Decodes and bounds-checks the exact five-byte TCP fallback record prefix.
pub fn decode_tcp_record_prefix(
    prefix: &[u8],
    max_control_payload: usize,
    max_packet_frame: usize,
) -> Result<TcpRecordHeader, Error> {
    if prefix.len() != TCP_RECORD_PREFIX_LEN {
        return Err(Error::InvalidTcpRecord);
    }
    let length = u32::from_be_bytes(prefix[..4].try_into().expect("fixed prefix"));
    if length == 0 {
        return Err(Error::InvalidTcpRecord);
    }
    let payload_length = usize::try_from(length - 1).map_err(|_| Error::FrameTooLarge)?;
    let kind = match prefix[4] {
        1 => TcpRecordKind::Control,
        2 => TcpRecordKind::Packet,
        3 => TcpRecordKind::Ping,
        4 => TcpRecordKind::Pong,
        _ => return Err(Error::InvalidTcpRecord),
    };
    let maximum = match kind {
        TcpRecordKind::Control => max_control_payload,
        TcpRecordKind::Packet => max_packet_frame,
        TcpRecordKind::Ping | TcpRecordKind::Pong => 0,
    };
    if payload_length > maximum {
        return Err(Error::FrameTooLarge);
    }
    Ok(TcpRecordHeader {
        kind,
        payload_length,
    })
}

/// Encodes one validated stable-v1 TCP fallback record prefix.
pub fn encode_tcp_record_prefix(
    kind: TcpRecordKind,
    payload_length: usize,
    max_control_payload: usize,
    max_packet_frame: usize,
) -> Result<[u8; TCP_RECORD_PREFIX_LEN], Error> {
    let length = u32::try_from(payload_length.checked_add(1).ok_or(Error::FrameTooLarge)?)
        .map_err(|_| Error::FrameTooLarge)?;
    let mut prefix = [0_u8; TCP_RECORD_PREFIX_LEN];
    prefix[..4].copy_from_slice(&length.to_be_bytes());
    prefix[4] = kind.as_u8();
    decode_tcp_record_prefix(&prefix, max_control_payload, max_packet_frame)?;
    Ok(prefix)
}

/// Decodes one complete stable-v1 TCP fallback record without allocating.
pub fn decode_tcp_record(
    record: &[u8],
    max_control_payload: usize,
    max_packet_frame: usize,
) -> Result<(TcpRecordKind, &[u8]), Error> {
    if record.len() < TCP_RECORD_PREFIX_LEN {
        return Err(Error::InvalidTcpRecord);
    }
    let header = decode_tcp_record_prefix(
        &record[..TCP_RECORD_PREFIX_LEN],
        max_control_payload,
        max_packet_frame,
    )?;
    if record.len() != TCP_RECORD_PREFIX_LEN + header.payload_length {
        return Err(Error::InvalidTcpRecord);
    }
    Ok((header.kind, &record[TCP_RECORD_PREFIX_LEN..]))
}

/// Negotiates the known capability intersection while rejecting missing
/// required bits. Unknown peer bits are ignored for forward compatibility.
pub fn negotiate_capabilities(
    local: u64,
    remote: u64,
    known: u64,
    required: u64,
) -> Result<u64, Error> {
    if required & !known != 0 {
        return Err(Error::IncompatibleCapabilities);
    }
    let negotiated = local & remote & known;
    if negotiated & required != required {
        return Err(Error::IncompatibleCapabilities);
    }
    Ok(negotiated)
}

/// Reads one bounded four-byte big-endian length-prefixed control payload.
pub fn read_control_frame<R: io::Read>(reader: &mut R, maximum: usize) -> Result<Vec<u8>, Error> {
    let maximum = if maximum == 0 {
        DEFAULT_MAX_CONTROL_PAYLOAD
    } else {
        maximum
    };
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|error| Error::Io(error.to_string()))?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| Error::FrameTooLarge)?;
    if length == 0 || length > maximum {
        return Err(Error::FrameTooLarge);
    }
    let mut payload = vec![0; length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| Error::Io(error.to_string()))?;
    Ok(payload)
}

/// Appends one bounded four-byte big-endian length-prefixed control payload.
pub fn write_control_frame(
    payload: &[u8],
    maximum: usize,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    let maximum = if maximum == 0 {
        DEFAULT_MAX_CONTROL_PAYLOAD
    } else {
        maximum
    };
    if payload.is_empty() || payload.len() > maximum || payload.len() > u32::MAX as usize {
        return Err(Error::FrameTooLarge);
    }
    output.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    output.extend_from_slice(payload);
    Ok(())
}
