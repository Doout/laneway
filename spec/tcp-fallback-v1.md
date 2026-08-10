# Laneway TLS/TCP Fallback v1

## Negotiation

TCP fallback is used when a preferred QUIC relay carrier is unavailable. It
uses TLS 1.3 mutual authentication, the identities in
[identity-v1.md](identity-v1.md), and ALPN `laneway-fallback/1`. A node
advertises `LANEWAY_RELAY_V1` and `LANEWAY_TCP_FALLBACK_V1`; it MUST NOT
advertise `LANEWAY_QUIC_DATAGRAM_V1` solely to establish this carrier.

Hello, Welcome, RelayRegister, route binding, policy, and packet validation are
the same as on the QUIC relay path. A relay MUST keep at most one current
session per node identity across both carriers, following its configured
duplicate-session policy.

## Records

TLS application data is a sequence of:

```text
uint32  record_length (network byte order; includes record_type)
uint8   record_type
byte[]  record_payload
```

`record_length` MUST be nonzero.

| Type | Name | Payload |
| ---: | --- | --- |
| 1 | Control | One serialized control or relay Protobuf envelope |
| 2 | Packet | One complete Laneway packet frame |
| 3 | Ping | Empty |
| 4 | Pong | Empty |

Unknown types, nonempty ping/pong payloads, truncation, invalid packet frames,
and records above the negotiated or configured limit terminate the connection.
A parser MUST validate length before allocation and MUST NOT resynchronize
after a malformed record.

## Bounds and liveness

Control and packet receive queues MUST be independently bounded. Exhaustion
terminates the slow session and MUST NOT block the relay forwarding path.
Writes MUST be serialized with finite deadlines. Implementations send ping
after the configured quiet period, answer with pong, and terminate a peer that
sends no records before the idle timeout.

The carrier preserves order and has head-of-line blocking. Implementations MUST
prefer a healthy direct or QUIC relay path and fully stop the previous packet
pump before switching carriers.

TLS authenticates each endpoint, but forwarding authority comes only from the
certificate identity, authorization snapshot, negotiated handles, and packet
policy—not the socket address. Payloads remain visible to the relay unless the
separate end-to-end packet capability is negotiated.
