# Laneway controller control transport v1

Status: Stable-v1 normative control-plane specification.

Authenticated controller traffic uses reliable QUIC streams with ALPN
`laneway-control/1`. HTTPS remains available for management and compatibility.
Initial enrollment is HTTPS-only by design: before enrollment a node has no
controller-issued certificate and therefore cannot authenticate a mandatory
mTLS QUIC connection. The one-time token and signed PKCS#10 CSR are protected
by TLS 1.3; the private key never leaves the joining node. Every operation
after issuance—configuration snapshots, conditional lease renewal, and node
certificate renewal—uses mTLS QUIC when `controller.quic_endpoint` is set.

Enrollment tokens are authority for exactly one controller-selected class:
`DURABLE_NODE`, `EPHEMERAL_USER`, or `REMEMBERED_USER`. The request cannot
upgrade that class. An ephemeral token also fixes a 5-minute through 24-hour
identity lifetime. Its certificate, configuration lease, overlay addresses,
peer/route authorization, and renewal are all bounded by the same UTC deadline.
Every node and relay snapshot is capped by the earliest active ephemeral lease
in its network, so an established direct or relayed path fails closed at the
deadline even if no cleanup request arrives at that instant. Expiry revokes the
certificate, releases addresses, withdraws routes, advances the network epoch,
and writes an audit event in one transaction. Expired records are retained for
seven days for recovery, then pruned in bounded batches while audit events
remain. A remembered user is a distinct durable identity class; reconnecting
never converts an ephemeral identity into that class.

The UDP QUIC listener may share a numeric port with the HTTPS TCP listener.
Servers require TLS 1.3, a chain rooted in the configured network CA, exactly
one Laneway URI SAN, a node or relay workload role, and the same NetworkID as
the controller certificate. Clients validate the server chain, configured DNS
name where present, and the exact controller NetworkID, role, and ServiceID.
TLS early data and QUIC 0-RTT are disabled.

Each request opens one bidirectional stream on a persistent QUIC connection.
Clients serialize requests, and servers accept one concurrent bidirectional
stream per connection, giving deterministic request/response ordering. Both
directions carry exactly one `ControllerEnvelope` encoded as:

```text
4-byte unsigned big-endian payload length
protobuf ControllerEnvelope payload
```

The length must be in `1..=1,048,576`, `schema_version` must equal 1, and
`request_id` must be nonzero and echoed exactly. Streams have a complete
request deadline (15 seconds by default and configurable on clients),
connections have bounded handshakes and idle time, and servers cap concurrent
connections at 256. Malformed framing, identity/role mismatch, unexpected
message direction, or response ID mismatch closes the connection. A failed
connection is discarded; the existing bounded exponential polling backoff
reconnects without replaying an in-flight renewal.

After its single envelope, each sender MUST finish its write half and each
receiver MUST consume that FIN, rejecting any trailing byte. This completes
both directions deterministically and releases bidirectional stream credit on
long-lived, serialized controller connections.

`NodeConfiguration` is the atomic authoritative snapshot for discovery,
routes, ACL policy, relay-assisted candidate-exchange policy, approved exit
gateways, revocation state, and the presented certificate's renewal/expiry
health. Ephemeral peer endpoint candidates remain on the authenticated relay
rendezvous channel and are intentionally not persisted by the controller.
`RelayConfiguration` contains packet authorization, ACL policy, revocation,
lease, and relay certificate health. `ConfigurationLease` extends an unchanged
snapshot's fail-closed deadline without retransmitting it.

Node certificate serial revocation is checked durably on every request.
Relay service credentials are authorized by the exact registered
NetworkID/ServiceID binding; disabling that relay registration revokes ongoing
controller access on the next request, including over an already established
QUIC connection. Expiry is independently re-checked per request for both roles.
