# Laneway Packet Format v1

Status: Stable-v1 normative packet framing.

Normative terms have the meaning defined in BCP 14.

## 1. Frame layout

One Laneway packet frame carries either one complete IPv4/IPv6 packet or one
opaque WireGuard UDP datagram:

```text
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | Version |Flags|                 Route Handle                  |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Carrier Payload ...                  |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The header is exactly five bytes:

- Byte 0 bits 7..4: version, value `1`.
- Byte 0 bits 3..0: flags. Value `0` identifies a raw IP payload. Value `1`
  (`LANEWAY_E2E_PACKET_V1`) identifies an opaque WireGuard payload. Bits 1..3
  are reserved and MUST be zero.
- Bytes 1..4: unsigned 32-bit route handle in network byte order.
- Bytes 5..end: one unmodified payload selected by the flags.

The Laneway-specific overhead is five bytes. No padding, payload length, node identifier, checksum, or alignment bytes are present. The containing QUIC DATAGRAM supplies the frame boundary.

## 2. Field rules

Version 1 with a raw IP payload begins with byte `0x10`; version 1 with an
opaque WireGuard payload begins with `0x11`. A receiver MUST reject an
unsupported version or any reserved flag bit. A receiver MUST reject flag value
`1` unless `LANEWAY_E2E_PACKET_V1` was negotiated on the authenticated carrier
by both endpoints and allowed by local policy.

Route handle zero is invalid. Nonzero handles are allocated and scoped as defined by [control-protocol-v1.md](control-protocol-v1.md). The numerical value has no global meaning and MUST NOT be interpreted as a NodeID, array index without bounds checks, authorization token, or persistent route identifier.

Raw IPv4 frames are at least 25 bytes and raw IPv6 frames are at least 45 bytes.
Opaque WireGuard frames have the message-specific sizes defined below. A frame
that does not contain exactly one valid payload for its flag value MUST be
dropped.

## 3. IP payload validation

This section applies only when flags are zero.

The receiver MUST inspect the high nibble of payload byte 0:

- value `4` identifies IPv4;
- value `6` identifies IPv6 and additionally requires negotiated `LANEWAY_IPV6_V1`;
- every other value is invalid.

For IPv4, the Internet Header Length MUST be at least 5, and the encoded total length MUST equal the Laneway payload length. The receiver MUST reject truncated headers, impossible lengths, and a header checksum that it verifies as invalid. Implementations MAY rely on a platform packet parser for checksum policy, but a relay MUST at least validate version and total length before forwarding.

For IPv6, the fixed header's payload-length field plus 40 MUST equal the Laneway payload length. A zero IPv6 payload length, which may indicate a jumbogram, is unsupported in v1 unless the frame is exactly 40 bytes; jumbograms MUST be rejected. Extension headers do not change Laneway framing.

Laneway v1 does not fragment or reassemble IP packets. Existing IPv4 fragments are carried as ordinary complete IP packets. IPv6 fragments are likewise carried if the negotiated path MTU permits them. Endpoints SHOULD use interface MTU and ICMP packet-too-big behavior to avoid transport fragmentation.

## 4. Opaque WireGuard payload validation

Flag value `1` carries exactly one public WireGuard UDP message. The message
type is the first little-endian `u32`; its upper three bytes MUST be zero. A
receiver MUST enforce the public WireGuard framing lengths before forwarding:

- handshake initiation (type 1): exactly 148 bytes;
- handshake response (type 2): exactly 92 bytes;
- cookie reply (type 3): exactly 64 bytes; and
- transport data (type 4): at least 32 bytes and a multiple of 16 bytes.

Every other type or length is invalid. The relay MUST treat the validated bytes
as opaque ciphertext and MUST NOT parse them as IP. The receiving endpoint
decrypts them through its WireGuard device and MUST apply controller-derived
source, destination, route, and ACL policy before decrypted IP is accepted or
forwarded.

## 5. Size limits

A sender MUST determine the active path's maximum Laneway payload. It MUST NOT send a frame larger than the peer/path limit or the QUIC DATAGRAM limit. An implementation MUST expose a conservative `lane0` MTU that accounts for the five-byte header and transport overhead.

There is no packet-layer segmentation. Oversized packets MUST be dropped or handled by normal IP MTU discovery; they MUST NOT be split into multiple Laneway frames. Benchmarks MUST report the configured maximum payload.

## 6. Handle and authorization validation

On node transmission, the handle identifies the intended destination peer in
that node's authenticated relay session. On relay receipt, the relay MUST
resolve the handle only in the authenticated sender's session and NetworkID.
For plaintext, it MUST validate the source address against prefixes authorized
for that sender and the destination address against the peer named by the
binding. For opaque WireGuard, it MUST instead require a live,
controller-authorized exact identity binding for both peers and negotiated
`LANEWAY_E2E_PACKET_V1`; it cannot evaluate ciphertext as an IP packet.

The relay MUST rewrite only the header handle before forwarding. It MUST
preserve the flag and payload byte-for-byte. The outgoing handle is from the
destination node's session and names the authenticated source node. On receipt,
the destination node MUST resolve that incoming handle locally. For plaintext
it performs IP validation before injection. For opaque WireGuard it submits the
ciphertext to only the bound peer's WireGuard session, then applies endpoint
policy to the decrypted packet.

Failure of any check causes the frame to be dropped. An implementation SHOULD increment a reason-specific bounded metric. It MUST NOT return the invalid packet to another route, guess a route from the payload, or create state from it.

## 7. QUIC DATAGRAM carriage

With negotiated `LANEWAY_QUIC_DATAGRAM_V1`, each QUIC DATAGRAM payload is exactly one Laneway packet frame. Multiple frames MUST NOT be concatenated, and one frame MUST NOT span datagrams. Empty datagrams are invalid.

QUIC DATAGRAM delivery is unreliable and unordered. Laneway packet framing adds no acknowledgement, retransmission, sequence number, or ordering guarantee. Upper-layer IP protocols provide any required reliability.

## 8. Examples

A route handle of decimal 42 followed by an IPv4 packet begins:

```text
10 00 00 00 2a 45 ...
```

A route handle of hexadecimal `01020304` followed by an IPv6 packet begins:

```text
10 01 02 03 04 60 ...
```

The same handle followed by a WireGuard handshake initiation begins:

```text
11 01 02 03 04 01 00 00 00 ...
```

Canonical golden vectors MUST include valid IPv4 and IPv6 examples and negative cases for zero handles, reserved flags, unsupported versions, truncated headers, encoded-length mismatch, capability mismatch, and packets exceeding the configured path limit.

## 9. Other transports

The five-byte frame is transport independent. The implemented TCP fallback
adds an outer record boundary and length but carries identical version, flags,
route handle, and payload semantics. Any future use of reserved flag bits or a
new packet version requires specification and golden vectors under
[compatibility.md](compatibility.md).
