# Laneway TLS/TCP Fallback v1

Status: Stable-v1 normative fallback transport specification.

Normative terms have the meaning defined in BCP 14.

## 1. Purpose and negotiation

TCP fallback is used only when a preferred QUIC relay carrier is unavailable.
It uses TLS 1.3 with mutual certificate authentication and the node/relay URI
identity profiles defined by `identity-v1.md`. The ALPN is
`laneway-fallback/1`. A node advertises `LANEWAY_RELAY_V1` and
`LANEWAY_TCP_FALLBACK_V1`; it MUST NOT advertise the QUIC-datagram capability
merely to establish this carrier.

The authenticated Hello, Welcome, RelayRegister, route-binding, policy, source
validation, and destination validation semantics are identical to the QUIC
relay path. A relay MUST keep at most one current session for a node identity
across both carriers according to its configured duplicate-session policy.

## 2. Records

TLS application bytes are a sequence of records:

```text
0                   1                   2                   3
+-------------------+-------------------+-------------------+-------------------+
|                 record_length (uint32, network byte order)                  |
+-------------------+-----------------------------------------------------------+
| record_type       | record_payload ...
+-------------------+-----------------------------------------------------------+
```

`record_length` includes the one-byte `record_type`. It MUST be nonzero. Types
are:

| Value | Name | Payload |
| --- | --- | --- |
| 1 | control | one serialized control or relay Protobuf envelope |
| 2 | packet | the complete packet-format-v1 header and IP payload |
| 3 | ping | empty |
| 4 | pong | empty |

Unknown types, nonempty ping/pong payloads, truncated records, invalid packet
frames, and records over the negotiated/configured bound terminate the
connection. A parser MUST check the declared length before allocation and MUST
NOT scan for a new boundary after a malformed record.

## 3. Bounds and liveness

Control and packet receive queues are independently bounded. Queue exhaustion
terminates the slow session; it MUST NOT grow memory without bound or block the
relay registry's packet forwarding path. Writes are serialized and have a
finite deadline. Implementations send an empty ping after the configured quiet
period, answer it with pong, and terminate a peer that produces no records for
the idle timeout.

The packet carrier preserves TCP ordering and therefore has head-of-line
blocking. Implementations MUST prefer a healthy direct or QUIC relay path and
MUST fully stop the previous packet pump before switching carriers.

## 4. Security boundary

TLS authenticates the node to the relay and the relay to the node; the relay
can still observe packet contents unless a separately negotiated end-to-end
packet capability is used. A TCP session receives no authority from its socket
address. All forwarding authority comes from its certificate identity,
authorization snapshot, negotiated route handles, and packet policy.
