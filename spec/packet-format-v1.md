# Laneway Packet Format v1

One frame carries one complete IPv4/IPv6 packet or one opaque WireGuard UDP
datagram.

## Frame

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 byte | Version in bits 7..4; flags in bits 3..0 |
| 1 | 4 bytes | Unsigned route handle in network byte order |
| 5 | Remaining bytes | Unmodified carrier payload |

Version MUST equal `1`. Flag value `0` selects raw IP; flag value `1` selects
an opaque WireGuard payload under `LANEWAY_E2E_PACKET_V1`. Reserved flag bits
1..3 MUST be zero. Thus a v1 raw-IP frame starts with `0x10` and an opaque frame
with `0x11`.

The header is exactly five bytes with no padding, payload length, identifier,
checksum, or alignment field. A receiver MUST reject unsupported versions,
reserved flags, and flag `1` unless the authenticated carrier negotiated and
policy allowed `LANEWAY_E2E_PACKET_V1`.

Route handle zero is invalid. Nonzero handles are session-local values defined
by [control-protocol-v1.md](control-protocol-v1.md); they have no global or
persistent meaning and are not identities or authorization tokens.

Raw IPv4 frames are at least 25 bytes; raw IPv6 frames are at least 45 bytes.
A frame that is not exactly one valid payload for its flag MUST be dropped.

## Raw IP validation

For flag `0`, the receiver checks the payload's high nibble:

- `4` selects IPv4;
- `6` selects IPv6 and requires negotiated `LANEWAY_IPV6_V1`; and
- every other value is invalid.

For IPv4, IHL MUST be at least 5 and total length MUST equal payload length.
Receivers MUST reject truncated headers, impossible lengths, and checksums they
verify as invalid. A relay MUST at least validate version and total length.

For IPv6, the fixed-header payload length plus 40 MUST equal payload length. A
zero payload length is valid only for an exactly 40-byte packet; v1 jumbograms
are unsupported. Extension headers do not change framing.

Laneway does not fragment or reassemble IP packets. Existing IPv4 and IPv6
fragments MAY be carried when the path MTU permits. Endpoints SHOULD set the
interface MTU and support ICMP packet-too-big behavior to avoid transport
fragmentation.

## Opaque WireGuard validation

For flag `1`, the first little-endian `u32` is the public WireGuard message
type; its upper three bytes MUST be zero. Valid messages are:

| Type | Message | Length |
| ---: | --- | ---: |
| 1 | Handshake initiation | 148 bytes |
| 2 | Handshake response | 92 bytes |
| 3 | Cookie reply | 64 bytes |
| 4 | Transport data | At least 32 bytes and a multiple of 16 |

All other types and lengths are invalid. A relay MUST preserve the validated
ciphertext as opaque bytes. The receiving endpoint decrypts it only through
the bound WireGuard peer, then applies controller-derived source, destination,
route, and ACL policy before accepting or forwarding the IP packet.

## Size and authorization

A sender MUST honor the smallest active peer, path, and carrier payload limit.
The `lane0` MTU MUST account for the five-byte header and transport overhead.
Oversized packets MUST be dropped or handled by IP MTU discovery; a packet
MUST NOT be split across Laneway frames.

On a relay path, the sending handle names the destination peer within the
authenticated sender session and NetworkID. For raw IP, the relay MUST validate
the source against that sender's authorized prefixes and the destination
against the bound peer. For opaque WireGuard, it MUST require a live,
controller-authorized exact identity binding for both peers and negotiated
`LANEWAY_E2E_PACKET_V1`.

The relay rewrites only the handle, preserving flags and payload byte-for-byte.
The outgoing handle belongs to the destination session and names the
authenticated source. The receiver MUST resolve it locally, then validate raw
IP before injection or send opaque data only to the bound WireGuard peer.

Any failed check drops the frame. A receiver MUST NOT guess another route,
return it through another handle, or create state from invalid input.

## Carriage

With `LANEWAY_QUIC_DATAGRAM_V1`, each QUIC DATAGRAM contains exactly one frame.
Frames MUST NOT be concatenated or span datagrams; empty datagrams are invalid.
Delivery is unreliable and unordered, with no Laneway acknowledgement,
retransmission, sequence number, or ordering guarantee.

TCP fallback adds only its record boundary; packet semantics remain unchanged.
Reserved flags and new packet versions require specification and golden vectors
under [compatibility.md](compatibility.md).
