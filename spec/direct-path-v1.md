# Laneway Direct Path v1

Status: Stable-v1 normative direct-path profile.

## 1. Negotiation and fallback

Both node and relay MUST negotiate `LANEWAY_DIRECT_PEER_V1` before exchanging
endpoint candidates. Direct connectivity is an optimization: failure to
publish, probe, or authenticate a direct path MUST leave an already healthy
relay path available.

The preferred carrier order is direct QUIC, relay QUIC, then relay TLS/TCP.
Implementations MUST use health hysteresis rather than switching because of one
latency sample. A hard send or transport failure may trigger immediate fallback.

## 2. Candidate publication

A node publishes `EndpointCandidate` on its authenticated relay control stream.
For a publication:

- `node_id` MUST equal the publisher's certificate NodeID;
- `transport` MUST be `ENDPOINT_TRANSPORT_QUIC_UDP`;
- `rendezvous_token` and `probe_start_unix_nano` MUST be empty; and
- the candidate count, address classes, TTL, and control-frame size are bounded.

The relay MUST NOT trust the advertised public address or port. For a QUIC
publisher, it replaces them with the UDP endpoint observed on that same QUIC
connection. Candidates are not available through TCP fallback because a TCP
connection provides no usable UDP mapping.

The relay distributes an observed candidate only to active, same-network peers
already authorized and route-bound to communicate with the publisher. It
replaces `node_id` with the authenticated publisher NodeID, generates a fresh
unpredictable 16-byte rendezvous token, and supplies a coordinated future probe
start time. Relays MUST bound fan-out and remove a candidate when its session
ends.

## 3. UDP probes

The probe is a fixed 54-byte non-QUIC datagram:

```text
4 bytes  magic (0x0c, 'W', 'H', 'P')
1 byte   version (1)
1 byte   type (1 request, 2 response)
16 bytes rendezvous token
16 bytes sender NodeID
16 bytes recipient NodeID
```

The high bits in the magic keep the datagram outside the QUIC long- and
short-header spaces used by the shared socket. A receiver MUST require the
exact size, magic, version, type, nonzero token, expected sender, and local
recipient. The random token is a short-lived bearer rendezvous secret; it MUST
not be logged or reused across unrelated peer pairs.

Both peers send bounded, priority-ordered probe rounds at the relay-supplied
start time. They MUST use the same UDP socket for relay QUIC, probes, direct
listening, and direct dialing so the NAT mapping is preserved.

## 4. Direct QUIC authentication

After reachability is observed, the lexicographically lower NodeID initiates the
QUIC connection. The other node accepts. Both directions use TLS 1.3 mutual
authentication and ALPN `laneway-peer/1`; 0-RTT is disabled and QUIC DATAGRAM
support is mandatory.

The certificate URI SAN MUST identify a node in the expected NetworkID. The
dialer additionally requires the exact expected NodeID. Both sides exchange a
fixed identity binding on the first stream before exposing the packet path.
Certificate authentication, not the probe token or endpoint address, is the
peer identity.

## 5. Packets and authorization

Direct paths carry raw IP payloads in QUIC DATAGRAM frames. The session-local
relay route handle is not used on a peer path. The receiving node nevertheless
performs the same source-prefix, destination-prefix, and ACL checks used for a
relayed packet before writing it to `lane0`.

One daemon component owns the TUN reader. Direct, QUIC-relay, and TCP-relay
paths attach to one path manager; transport implementations MUST NOT race by
reading the TUN device independently.
