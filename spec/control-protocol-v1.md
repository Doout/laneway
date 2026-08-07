# Laneway Control Protocol v1

Status: Stable-v1 normative control-plane specification.

Normative terms have the meaning defined in BCP 14.

## 1. Transport and encoding

Control messages use Protobuf schemas in `api/proto/laneway/v1/` over a reliable ordered QUIC stream. Every control payload is one serialized `ControlEnvelope`; relay-specific payloads use `RelayEnvelope` under the same framing rule. Every message is framed as:

```text
uint32 payload_length   big-endian
byte[payload_length]    serialized protobuf message
```

The length counts only the Protobuf payload. A receiver MUST read exactly four bytes, decode the unsigned length, validate it, and only then read or allocate for the payload. The v1 maximum control payload is 1,048,576 bytes. Length zero and lengths above that maximum are protocol errors. Deployments MAY configure a smaller limit but MUST fail explicitly rather than truncate.

An envelope MUST set `schema_version` to `1` and exactly one `oneof body` member. A receiver MUST reject a different schema version, a missing body, or a body invalid in the current session state. `sequence` starts at 1 independently in each direction and increases by exactly one for each envelope on that stream. Duplicate, zero, or skipped sequence values are protocol errors. Sequence numbers detect state-machine mistakes; they are not cryptographic replay protection and MUST NOT persist across sessions.

Protobuf parsers MUST reject malformed encodings. Unknown fields MUST be preserved when a message is decoded and re-encoded by a component acting as a transparent intermediary; ordinary endpoints MUST ignore unknown fields as Protobuf requires. Unknown enum numeric values MUST NOT be treated as a known authorization or capability value.

The first client-initiated bidirectional QUIC stream is the connection's sole control stream. It begins with the four ASCII octets `LWC1`, consumed by the transport, then carries framed control messages. An endpoint MUST send and process messages serially in stream order.

After `Welcome`, the same stream changes to `RelayEnvelope` frames with an independent sequence starting at 1. Its first relay body MUST be `RelayRegister`, whose `session_id` MUST equal the current `Welcome.session_id`; the relay rejects a duplicate registration or a request above its configured route limit. The relay uses `RouteHandleBinding` and `RouteHandleRelease` bodies to manage handles. `EndpointCandidate` MUST NOT be sent unless `LANEWAY_DIRECT_PEER_V1` has been negotiated. Further QUIC streams are reserved unless a future capability defines them.

Controller connections are a separate use of the same bounded framing. They
MUST negotiate TLS 1.3 mutual authentication with ALPN `laneway-control/1` and
MUST NOT use 0-RTT. A client maintains one persistent connection and opens one
bidirectional stream for each `ControllerEnvelope` request/response pair.
Clients MUST serialize requests; servers MUST admit at most one concurrent
bidirectional request stream per connection and process streams in order.
There is no `LWC1` preface on controller request streams.

A controller envelope MUST have `schema_version = 1`, exactly one body, and a
nonzero `request_id`. The response MUST echo the exact request ID. A mismatch,
duplicate in-flight ID, unexpected body direction, malformed frame, or frame
above 1,048,576 bytes is a connection-fatal protocol error. Node credentials
permit `ConfigurationRequest` and `RenewalRequest`; relay credentials permit
only `RelayConfigurationRequest`. The corresponding successful response is
`NodeConfiguration`, `RenewalResponse`, or `RelayConfiguration`, respectively;
an unchanged configuration uses `ConfigurationLease`, and failures use
`ProtocolError`.

The controller server certificate MUST contain exactly one controller-role
Laneway URI SAN. A client MUST verify its CA chain and the exact configured
NetworkID and controller ServiceID, in addition to the configured DNS name
when present. A server MUST verify a client chain, exact node or relay role,
and equality with the controller certificate NetworkID. It MUST re-check the
client certificate validity interval and current authorization on every
request, because a persistent connection can outlive certificate expiry or a
relay disable operation. Implementations MUST use finite complete-request
deadlines, connection limits, handshake limits, idle timeouts, and bounded
reconnect backoff.

Initial enrollment and administrative operations are the only normative HTTPS
exception. A joining node cannot perform mTLS before the controller issues its
first certificate, so it sends the one-time token and signed PKCS#10 CSR over
TLS 1.3 HTTPS. The private key MUST remain local. All authenticated ongoing
control MUST use QUIC; production controller-backed node and relay
configuration MUST require `controller.quic_endpoint`. HTTPS polling MAY be
retained only as an explicitly selected legacy compatibility mechanism.

## 2. Session establishment

The connection MUST first complete TLS 1.3 mutual authentication with `laneway-relay/1`. QUIC 0-RTT application data MUST NOT be used.

The body of the node's first `ControlEnvelope` MUST be `Hello`; no other body may precede it. `Hello` contains:

- `network_id`: exactly 16 bytes and equal to the authenticated certificate NetworkID;
- `node_id`: exactly 16 bytes and equal to the authenticated certificate NodeID;
- `boot_id`: exactly 16 nonzero bytes, freshly generated on daemon start;
- `protocol_major`: `1`;
- `protocol_minor`: the highest v1 minor revision supported by the sender; and
- `capabilities`: the sender's supported capability bitset.

The relay MUST reject invalid identifier lengths, identity mismatches, an unsupported major version, or a second `Hello`. Authentication succeeds before `Hello`; session establishment succeeds only after `Hello` validation.

The relay responds with exactly one `Welcome` or a fatal error. `Welcome` contains:

- a fresh 16-byte nonzero `session_id`;
- the controller configuration epoch applied by the relay;
- zero or more canonical packed overlay addresses (4 bytes for IPv4, 16 for IPv6); and
- the negotiated capability intersection;
- `max_control_payload`, the maximum framed Protobuf payload the relay will accept; and
- `max_packet_payload`, the maximum complete raw IP payload the relay will accept in a packet frame.

Both advertised maximums MUST be nonzero. `max_control_payload` MUST NOT exceed 1,048,576 in v1. Each sender uses the smaller of its local limit and the peer-advertised limit. The node MUST verify that every bit in `Welcome.capabilities` was present in its `Hello` and is supported locally. An unexpected bit is a protocol error. A session becomes active only after a valid `Welcome` is received.

## 3. Version negotiation

Version numbers describe the control protocol, not the implementation release.

- `protocol_major` changes for an incompatible wire or semantic change. v1 endpoints MUST reject any value other than `1`.
- `protocol_minor` increases for backward-compatible additions. The negotiated minor version is `min(client_minor, server_minor)`.
- A feature gated by a capability MUST NOT be used merely because a minor version is high enough.
- Mandatory v1 security checks are not capabilities and cannot be disabled by negotiation.

An endpoint SHOULD return a stable `UNSUPPORTED_VERSION` error including its supported major and highest minor before closing, when it is safe to do so.

## 4. Capability registry

The `uint64` capability field uses bit positions below. Bit `n` has value `1 << n`.

| Bit | Name | Stable-v1 meaning |
| ---: | --- | --- |
| 0 | `LANEWAY_RELAY_V1` | Relay control and forwarding semantics v1 |
| 1 | `LANEWAY_QUIC_DATAGRAM_V1` | Five-byte packet frames in QUIC DATAGRAM |
| 2 | `LANEWAY_DIRECT_PEER_V1` | Observed-endpoint rendezvous and direct authenticated QUIC peer paths |
| 3 | `LANEWAY_SUBNET_ROUTER_V1` | Controller-authorized non-overlay prefixes |
| 4 | `LANEWAY_EXIT_NODE_V1` | Controller-authorized, explicitly selected default routes |
| 5 | `LANEWAY_TCP_FALLBACK_V1` | Fallback records over TLS/TCP |
| 6 | `LANEWAY_IPV6_V1` | IPv6 packet and route support |
| 7 | `LANEWAY_E2E_PACKET_V1` | Opaque WireGuard packet framing protected from relay plaintext inspection |

Bits 8 through 63 are unassigned in this revision and MUST be sent as zero. Receivers MUST ignore unknown capability bits when computing an intersection and MUST NOT echo them unless they independently implement the assigned capability.

QUIC relay packet exchange requires bits 0 and 1. TCP relay exchange requires
bits 0 and 5. IPv4-only implementations MUST clear bit 6. Implementations that
set bit 2 MUST follow [direct-path-v1.md](direct-path-v1.md). Implementations
that set bit 7 MUST implement the opaque framing, identity binding, and endpoint
policy requirements in [packet-format-v1.md](packet-format-v1.md); support for
legacy raw-IP relay packets alone is insufficient.

## 5. Configuration epochs

`configuration_epoch` is an unsigned 64-bit monotonically increasing value scoped to one NetworkID and one controller authority. Zero means no controller-issued configuration has been applied and is permitted only in manual static deployments.

Configuration objects belonging to an epoch form a coherent snapshot. A node MUST apply a snapshot atomically and MUST NOT combine route or policy objects from different epochs unless a later incremental-update specification explicitly permits it. A node MUST reject an epoch lower than its currently committed epoch, except after explicit administrative reset or full resynchronization with a newly trusted authority.

`NodeConfiguration.valid_until_unix_seconds` and
`RelayConfiguration.valid_until_unix_seconds` are authorization lease
deadlines. A full snapshot with a missing or elapsed deadline MUST be rejected.
When an epoch is unchanged, QUIC returns `ConfigurationLease` with the exact
requested `configuration_epoch` and a fresh `valid_until_unix_seconds`. The
legacy HTTPS compatibility path uses `304 Not Modified` and
`X-Laneway-Configuration-Valid-Until`. Either response renews only
that deadline; it does not alter
routes, policy, identities, or capabilities. Nodes and relays MUST fail closed
at the last accepted deadline even while the controller is unreachable. A
renewed lease for the same epoch may reactivate the retained complete snapshot.

Fresh node and relay configurations carry the complete
`revoked_certificate_serials` set for revoked, unexpired credentials in the
network. Each entry is a canonical positive unsigned big-endian X.509 serial.
Recipients MUST reject malformed or duplicate entries, atomically replace the
previous set, deny matching new TLS sessions, and promptly close matching
active relay or direct-path sessions. A not-modified response renews the lease
on the already installed set.

Each `NodeConfiguration.relays[].endpoint` is a canonical numeric-IP or DNS
`host:port` authority. Before publishing a new snapshot, a node MUST resolve
the complete bounded relay set to bounded, deduplicated numeric targets and
install native transport bypasses for every retained address. Failure to
resolve one relay does not invalidate other resolvable authorized relays, but
a snapshot with no usable resolved target MUST fail closed and leave no new
authority published. DNS answers are transport locations only: every dial
MUST still authenticate the exact relay ServiceID from the same entry. DNS
resolution, target and answer counts, and the resolution deadline MUST be
finite. Same-epoch lease renewal retains the previously resolved target set;
new DNS answers are adopted only through a complete newer snapshot.

## 6. Route-handle lifecycle

The authenticated relay allocates nonzero 32-bit route handles and communicates each binding with `RouteHandleBinding`. `peer_node_id` is exactly 16 bytes and identifies the peer represented by the handle; `max_packet_payload` is nonzero and limits complete IP payloads sent with that binding. A handle is scoped to:

- the NetworkID;
- the allocating relay;
- one authenticated QUIC connection/session; and
- one direction of packet transmission.

A node uses an installed handle on transmission to designate `peer_node_id` as the destination peer. When forwarding to that peer, the relay MUST replace it with the handle in the receiving session that represents the authenticated source node. Consequently, on node receipt the handle identifies the source peer. A sender MUST NOT use a handle before receiving its installation. A relay MUST NOT resolve a handle outside its owning session. Withdrawal takes effect in relay-management-stream order; packets observed after withdrawal MUST be dropped. All handles become invalid when the connection closes. Reconnection MUST install new handles.

Handle value zero is permanently invalid. Handle reuse within one live session SHOULD be avoided; if unavoidable after exhaustion, the relay MUST ensure the previous binding is withdrawn and all ordered control effects are observed before reuse. A random or stale handle is never evidence of identity or authority.

## 7. Liveness and reconnection

Authenticated carrier liveness is authoritative. Application health messages MAY expose metrics but MUST NOT override a failed transport. Nodes SHOULD reconnect with exponential backoff and jitter. A new connection performs full authentication, sends a new `Hello`, receives a new session ID, and rebuilds handles and configuration.

Implementations MUST bound queued control messages during disconnection. They MUST discard obsolete snapshots rather than replay an unbounded history; the latest complete authoritative snapshot wins.

## 8. Error handling

Protocol errors use the stable numeric `ErrorCode` values in the Protobuf schema. The v1 categories are:

| Name | Meaning |
| --- | --- |
| `ERROR_CODE_MALFORMED` | Invalid frame, Protobuf, identifier, field invariant, ordering, or session state |
| `ERROR_CODE_UNSUPPORTED_VERSION` | No common major protocol or envelope schema |
| `ERROR_CODE_UNAUTHENTICATED` | Authentication is absent or message identity differs from the certificate |
| `ERROR_CODE_PERMISSION_DENIED` | Valid identity lacks permission |
| `ERROR_CODE_STALE_EPOCH` | Configuration is older than committed state |
| `ERROR_CODE_RESOURCE_EXHAUSTED` | A documented finite limit was reached |
| `ERROR_CODE_INTERNAL` | Peer cannot safely expose a more specific cause |

`ERROR_CODE_UNSPECIFIED` MUST NOT be sent as an error. Human-readable `detail` is diagnostic only and MUST NOT drive interoperability. `retryable` is advisory and MUST NOT override local backoff, authentication, or authorization policy. Fatal authentication, framing, ordering, or identity errors close the control session. A recoverable object rejection MUST be explicit and MUST leave the previous valid snapshot active.

## 9. Resource limits

In addition to the one MiB frame maximum, implementations MUST configure finite limits for concurrent sessions, streams, queued frames, routes, overlay addresses, and handles. Limits SHOULD be reported through metrics. Exceeding a limit MUST yield bounded rejection, backpressure, or packet loss; it MUST NOT cause unbounded memory growth.
