# Laneway Packet Format v1

Status: Stable-v1 normative packet framing.

Normative terms have the meaning defined in BCP 14.

## 1. Frame layout

One Laneway packet frame carries exactly one complete IPv4 or IPv6 packet:

```text
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | Version |Flags|                 Route Handle                  |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         Raw IP Packet ...                     |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The header is exactly five bytes:

- Byte 0 bits 7..4: version, value `1`.
- Byte 0 bits 3..0: flags, value `0` in this revision.
- Bytes 1..4: unsigned 32-bit route handle in network byte order.
- Bytes 5..end: one unmodified raw IP packet, beginning with its IP version nibble.

The Laneway-specific overhead is five bytes. No padding, payload length, node identifier, checksum, or alignment bytes are present. The containing QUIC DATAGRAM supplies the frame boundary.

## 2. Field rules

Version 1 is encoded as byte value `0x10` because every v1 flag is zero. A receiver MUST reject an unsupported version. A v1 receiver MUST reject any nonzero flag bit; reserved bits are not silently ignored because doing so could alter forwarding semantics.

Route handle zero is invalid. Nonzero handles are allocated and scoped as defined by [control-protocol-v1.md](control-protocol-v1.md). The numerical value has no global meaning and MUST NOT be interpreted as a NodeID, array index without bounds checks, authorization token, or persistent route identifier.

The minimum frame length is 25 bytes: five header bytes plus the minimum valid 20-byte IPv4 header. IPv6 frames are at least 45 bytes. A frame that does not contain exactly one syntactically valid complete IP packet MUST be dropped.

## 3. IP payload validation

The receiver MUST inspect the high nibble of payload byte 0:

- value `4` identifies IPv4;
- value `6` identifies IPv6 and additionally requires negotiated `LANEWAY_IPV6_V1`;
- every other value is invalid.

For IPv4, the Internet Header Length MUST be at least 5, and the encoded total length MUST equal the Laneway payload length. The receiver MUST reject truncated headers, impossible lengths, and a header checksum that it verifies as invalid. Implementations MAY rely on a platform packet parser for checksum policy, but a relay MUST at least validate version and total length before forwarding.

For IPv6, the fixed header's payload-length field plus 40 MUST equal the Laneway payload length. A zero IPv6 payload length, which may indicate a jumbogram, is unsupported in v1 unless the frame is exactly 40 bytes; jumbograms MUST be rejected. Extension headers do not change Laneway framing.

Laneway v1 does not fragment or reassemble IP packets. Existing IPv4 fragments are carried as ordinary complete IP packets. IPv6 fragments are likewise carried if the negotiated path MTU permits them. Endpoints SHOULD use interface MTU and ICMP packet-too-big behavior to avoid transport fragmentation.

## 4. Size limits

A sender MUST determine the active path's maximum Laneway payload. It MUST NOT send a frame larger than the peer/path limit or the QUIC DATAGRAM limit. An implementation MUST expose a conservative `lane0` MTU that accounts for the five-byte header and transport overhead.

There is no packet-layer segmentation. Oversized packets MUST be dropped or handled by normal IP MTU discovery; they MUST NOT be split into multiple Laneway frames. Benchmarks MUST report the configured maximum payload.

## 5. Handle and address validation

On node transmission, the handle identifies the intended destination peer in that node's authenticated relay session. On relay receipt, the relay MUST resolve the handle only in the authenticated sender's session and NetworkID. Before forwarding, it MUST validate the source address against prefixes authorized for that sender and the destination address against the peer named by the binding.

The relay MUST rewrite the header handle before forwarding. The outgoing handle is from the destination node's session and names the authenticated source node. On receipt, the destination node MUST resolve that incoming handle locally, validate the packet source against that peer's authorized prefixes, and validate that the destination is locally assigned or routed before injecting the raw packet into `lane0` or delivering it to a benchmark receiver.

Failure of any check causes the frame to be dropped. An implementation SHOULD increment a reason-specific bounded metric. It MUST NOT return the invalid packet to another route, guess a route from the payload, or create state from it.

## 6. QUIC DATAGRAM carriage

With negotiated `LANEWAY_QUIC_DATAGRAM_V1`, each QUIC DATAGRAM payload is exactly one Laneway packet frame. Multiple frames MUST NOT be concatenated, and one frame MUST NOT span datagrams. Empty datagrams are invalid.

QUIC DATAGRAM delivery is unreliable and unordered. Laneway packet framing adds no acknowledgement, retransmission, sequence number, or ordering guarantee. Upper-layer IP protocols provide any required reliability.

## 7. Examples

A route handle of decimal 42 followed by an IPv4 packet begins:

```text
10 00 00 00 2a 45 ...
```

A route handle of hexadecimal `01020304` followed by an IPv6 packet begins:

```text
10 01 02 03 04 60 ...
```

Canonical golden vectors MUST include valid IPv4 and IPv6 examples and negative cases for zero handles, reserved flags, unsupported versions, truncated headers, encoded-length mismatch, capability mismatch, and packets exceeding the configured path limit.

## 8. Future transports

The five-byte frame is transport independent. The implemented TCP fallback adds an outer record boundary and length but carries the same version/flags, route handle, and IP packet semantics. Any future use of flag bits or a new packet version requires specification and golden vectors under [compatibility.md](compatibility.md).
