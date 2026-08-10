# Laneway Direct Path v1

## Negotiation and fallback

Both node and relay MUST negotiate `LANEWAY_DIRECT_PEER_V1` before exchanging
endpoint candidates. Direct-path failure MUST leave a healthy relay path
available. Carrier preference is direct QUIC, relay QUIC, then relay TLS/TCP.
Path selection MUST use health hysteresis; a hard transport or send failure MAY
trigger immediate fallback.

## Candidates

A node publishes `EndpointCandidate` on its authenticated relay control stream:

- `node_id` MUST equal its certificate NodeID;
- `transport` MUST equal `ENDPOINT_TRANSPORT_QUIC_UDP`;
- `rendezvous_token` and `probe_start_unix_nano` MUST be empty; and
- candidate count, address classes, TTL, and control-frame size MUST be bounded.

The relay MUST NOT trust the advertised address or port and MUST replace them
with the UDP endpoint observed on the same QUIC connection. TCP fallback cannot
publish candidates.

The relay distributes a candidate only to active same-network peers already
authorized and route-bound to the publisher. It MUST replace `node_id` with the
authenticated NodeID, create a fresh unpredictable 16-byte rendezvous token,
and set a coordinated future probe time. Fan-out MUST be bounded, and a
candidate MUST be removed when its session ends.

## UDP probes

A probe is exactly 54 bytes:

```text
4 bytes   magic: 0x0c, 'W', 'H', 'P'
1 byte    version: 1
1 byte    type: 1 request, 2 response
16 bytes  rendezvous token
16 bytes  sender NodeID
16 bytes  recipient NodeID
```

A receiver MUST validate the exact size, magic, version, type, nonzero token,
expected sender, and local recipient. The short-lived bearer token MUST NOT be
logged or reused for another peer pair.

Both peers send bounded, priority-ordered probe rounds at the relay-supplied
start time. Relay QUIC, probes, direct listening, and direct dialing MUST use
the same UDP socket to preserve the NAT mapping.

## Authentication and packets

After reachability is confirmed, the lexicographically lower NodeID initiates
QUIC. Both peers MUST use TLS 1.3 mutual authentication and ALPN
`laneway-peer/1`, MUST disable 0-RTT, and MUST support QUIC DATAGRAM.

The certificate URI SAN MUST identify a node in the expected NetworkID; the
dialer MUST also verify the expected NodeID. Before enabling packets, both
peers exchange the fixed identity binding on the first stream. The certificate,
not the probe token or endpoint, establishes identity.

Direct QUIC DATAGRAMs carry raw IP without relay route handles. Before writing
to `lane0`, the receiver MUST apply the same source-prefix,
destination-prefix, and ACL checks as for relayed traffic.
