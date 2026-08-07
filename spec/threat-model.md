# Laneway Threat Model

Status: Stable-v1 threat model.

Normative terms have the meaning defined in BCP 14.

## 1. Security objectives

Laneway aims to provide:

- mutual authentication of every transport endpoint;
- cryptographic binding of a connection to one network and one node or service identity;
- confidentiality and integrity in transit;
- authorization of overlay addresses and advertised routes;
- source-address validation before packet forwarding or local injection;
- isolation between Laneway networks sharing a relay;
- resistance to replay of stale sessions, handles, and control state; and
- bounded resource use under malformed or excessive traffic.

Laneway does not attempt to make a compromised endpoint trustworthy, conceal traffic metadata from the relay, or protect cleartext traffic after an authorized subnet router or exit node forwards it outside Laneway.

## 2. Trust boundaries and assumptions

The offline root and online issuing CA are trusted to issue correct identities.
The offline root private key MUST NOT be stored on a controller, relay, Exit
Node, or control VPS. The controller is trusted to authorize nodes, addresses,
routes, and policy, but it is not trusted with endpoint private keys and MUST
NOT receive them. Administrators are trusted to protect CA material and approve
routes correctly.

Nodes trust their local OS, daemon, configuration, certificate, and private key. A relay is trusted to enforce session isolation and forwarding policy. Transport cryptography protects packets from on-path observers; the relay terminates node transport connections and therefore can observe relayed packet plaintext and metadata. End-to-end packet encryption, represented by `LANEWAY_E2E_PACKET_V1`, is not provided by stable v1 and MUST NOT be advertised.

The public network, NAT devices, DNS, unauthenticated peers, node names, hostnames, claimed overlay addresses, and identity fields inside protocol messages are untrusted.

Docker Engine and the host kernel are trusted to enforce namespace and device
boundaries. Controller and relay containers are unprivileged. The default Exit
Node has `NET_ADMIN` and `/dev/net/tun` only in its own network namespace; this
does not protect it from a compromised container runtime or kernel. The exact
deployment boundary is defined in
[deployment-contract.md](deployment-contract.md).

## 3. Adversaries

The design considers:

- a passive network observer;
- an active on-path attacker that can drop, reorder, duplicate, or inject traffic;
- an unauthenticated Internet client contacting a relay or controller;
- an authenticated node attempting to impersonate another node, spoof source addresses, access another network, advertise unauthorized routes, or exhaust shared resources;
- a stale or revoked node attempting to reconnect;
- a compromised relay attempting to inspect or disrupt relayed traffic; and
- malformed input intended to trigger parser bugs or resource exhaustion.
- a local unprivileged user attempting to abuse the temporary networking helper;
- a compromised Exit Node attempting to alter host or sibling-container network
  state; and
- a compromised control-plane container attempting to read unrelated secrets or
  gain host capabilities.

Compromise of an issuing CA, controller authorization database, endpoint OS, or endpoint private key is outside the containment promise for identities governed by that component. Recovery from such compromise requires revocation and re-issuance.

## 4. Threats and required mitigations

### 4.1 Identity spoofing

All authenticated node, relay, and controller connections MUST use TLS 1.3 with certificate path and time validation. The authorization identity MUST be derived from the validated URI SAN as specified in [identity-v1.md](identity-v1.md). A receiver MUST compare any message-carried `network_id` or `node_id` with the authenticated identity and terminate the protocol session on mismatch. One-time enrollment is the sole client-certificate exception: a not-yet-enrolled node authenticates with a bounded, expiring, single-use enrollment token and sends only a signed PKCS#10 CSR over server-authenticated TLS 1.3 HTTPS. After issuance, ongoing node and relay controller traffic MUST use `laneway-control/1` mTLS QUIC and MUST NOT silently downgrade to HTTPS.

Names, hostnames, IP addresses, session IDs, boot IDs, and route handles MUST NOT serve as authentication credentials.

### 4.2 Cross-network forwarding

A relay or controller serving multiple networks MUST partition all session, handle, address, route, and policy lookups by the authenticated `NetworkID`. It MUST NOT allocate a handle that resolves to a session in another network. The receiver MUST reject control objects for a different network.

### 4.3 Address and route spoofing

The relay MUST associate every handle with authenticated session state and an authorized destination. A node or relay MUST validate the IP version, packet length, source prefix, and destination implied by the receiving handle before forwarding. Nodes MUST accept source prefixes only from controller-authorized ownership or advertisement state. Advertisements are requests, not authority; no route becomes active until approved.

Default routes require both controller authorization and explicit local selection. More-specific route selection MUST NOT bypass ACL or route authorization.

### 4.4 Replay and stale state

TLS and QUIC provide transport-level anti-replay for established connections. Laneway route handles are scoped to one authenticated session and one direction. They MUST be discarded on disconnect and MUST NOT be restored solely from disk. A fresh random `boot_id` identifies a daemon incarnation but is not a credential. Implementations MUST reject control epochs older than the last committed epoch for the same authority, except during an explicitly defined full resynchronization.

QUIC 0-RTT application data MUST be disabled in v1. A future protocol may permit replay-safe messages in 0-RTT only after defining them explicitly; packet frames, route mutations, and authorization changes MUST NOT be accepted as early data by default.

### 4.5 Downgrade

TLS, ALPN, protocol major/minor values, and capability intersection form the negotiation boundary. An endpoint MUST reject a different major version. It MUST NOT use a feature unless both endpoints advertised its capability and local policy permits it. A missing capability means unsupported, not implicitly enabled. Security requirements such as certificate validation and source validation cannot be negotiated away.

### 4.6 Denial of service

All control frames, queues, session counts, route counts, and per-session handle counts MUST have configured finite limits. Length prefixes MUST be checked before allocating or reading a payload. Invalid datagrams SHOULD be dropped cheaply. Expensive authentication attempts SHOULD be rate-limited. Persistent malformed traffic SHOULD terminate or quarantine the session.

Packet processing MUST NOT allocate an unbounded buffer, spawn work per packet, perform a database access per packet, or emit unbounded logs. Backpressure and drop counters SHOULD be observable without exposing packet contents.

### 4.7 Key theft and certificate misuse

Private keys MUST be generated and retained on the node that uses them. They MUST NOT be transmitted to the controller. Key files SHOULD use OS-provided protection and least-privilege permissions. Certificates MUST contain exactly one usable Laneway identity URI; ambiguous identities MUST be rejected.

Implementations MUST check certificate validity and revocation information made available by the controller. Manual static-certificate deployments MUST document that removal from static configuration is their revocation mechanism and that already active sessions need explicit termination.

### 4.8 Relay compromise

TLS protects each node-to-relay hop, not packet content from the relay. A compromised relay can observe, drop, delay, replay at the application level within live connections, or misroute traffic subject to endpoint validation. Endpoints MUST therefore retain source and destination validation even when the relay is authenticated. Applications needing confidentiality from the relay MUST use their own end-to-end security until `LANEWAY_E2E_PACKET_V1` is specified and negotiated.

### 4.9 Route recursion and traffic leaks

When exit routing is enabled, paths to the controller, relay, selected exit, and required local gateways MUST bypass `lane0`. Full tunnel MUST be opt-in. Implementations MUST define fail-open versus fail-closed behavior explicitly; they MUST NOT silently change modes after path failure.

### 4.10 Local privilege boundaries

The foreground User dataplane, enrollment, private-key handling, and controller
communication MUST run without elevated privilege. Its privileged helper MUST
accept only a structured allowlist of TUN, address, route, rule, endpoint-bypass,
and optional DNS operations. Requests MUST be bound to one local session and
requesting process. The helper MUST reject unsafe identifiers and foreign state,
MUST NOT execute caller-supplied commands, and MUST NOT receive enrollment tokens
or endpoint private keys. Parent death MUST trigger bounded cleanup or leave an
exactly recoverable root-owned journal.

The Linux helper boundary uses a private `SOCK_SEQPACKET` socket inherited from
the requester rather than a listening endpoint. Kernel `SO_PEERCRED` binds that
channel to the process that created it, and the helper accepts versioned JSON
operations with unknown fields rejected. Setup transfers only a duplicate TUN
file descriptor with `SCM_RIGHTS`; controller credentials, enrollment tokens,
and private keys never cross the boundary. A non-root launcher will elevate only
a resolved binary whose file and every parent directory are root-owned and not
group- or world-writable, preventing executable replacement before `sudo`.
After setup, the helper drops its
capability bounding, permitted, effective, inheritable, and ambient sets to
`CAP_NET_ADMIN` and enables `no_new_privs`. Socket EOF is the requester-death
journal: the helper transactionally restores only routes it owns and closes the
last privileged TUN reference. Privileged namespace tests cover clean shutdown,
requester `SIGKILL`, exact capability state, and rejection of non-allowlisted
operations.

Controller and relay containers MUST run as non-root, drop all capabilities, use
a read-only root filesystem, and set `no-new-privileges`. The default Exit Node
MUST NOT use host networking, `privileged: true`, the Docker socket, or host
network-state mounts. It MAY receive only `NET_ADMIN` and `/dev/net/tun` inside
its container namespace. All actors MUST validate ownership before cleanup and
fail closed rather than remove foreign state.

Temporary identity class and lifetime are properties of the one-time token,
not caller-selected enrollment fields. Ephemeral certificates and every node
or relay snapshot that could authorize them are capped by the same controller
lease. The earliest active ephemeral lease bounds the complete network
snapshot, preventing established relay or direct paths from extending a user
session. Expiry transactionally revokes credentials, releases addresses,
withdraws owned routes, advances the epoch, and audits the event. Address reuse
is allowed only after the former credential is expired or durably revoked.

### 4.11 Bootstrap and supply chain

Unauthenticated discovery data is not authority. Bootstrap metadata MUST be
authenticated by public Web PKI or an equivalently pre-pinned mechanism before
it can introduce the network CA, controller and relay identity pins, or artifact
metadata. Enrollment codes MUST be short-lived, single-use, rate-limited, and
bound to the intended network and enrollment class. They MUST NOT be placed in
argv, URLs, logs, or shell history.

The public listener exposes no secret or mutation endpoint. Clients reject
redirects, IP authorities, unbounded, stale, or unknown metadata, endpoint
overrides, invalid identity pins, and artifact size or digest mismatches.
Enrollment codes are read from a non-echoed controlling terminal (or a
protected file); requests carry the WebPKI-authenticated expected NetworkID
and are throttled by bounded transport-source state before parsing or token
lookup. A network mismatch is checked before the code can be consumed.

Downloaded artifacts MUST be verified before execution and before any privilege
boundary is crossed. Deployment inputs MUST use a semantic version or immutable
digest, never a mutable `latest` tag.

## 5. Privacy

Relays necessarily learn authenticated node identity, connection timing, observed public endpoints, packet sizes, and destinations needed for forwarding. Controllers learn membership, addresses, approved routes, and policy. Logs SHOULD minimize retention of public endpoints and MUST NOT log raw packet bodies or private keys. Stable NodeIDs are linkable within their network by design.

## 6. Stable-v1 security validation gate

Release validation MUST cover:

- invalid chain, expired certificate, wrong CA, malformed URI SAN, and identity mismatch;
- cross-network handle use and stale handle use;
- malformed and oversized control frames;
- every reserved packet-header flag and unsupported packet version;
- invalid IPv4 lengths/checksums where validated, spoofed sources, and wrong destinations;
- incompatible major versions and capability downgrade behavior;
- queue exhaustion without unbounded memory growth; and
- direct-path identity, observed-candidate rewriting, and relay fallback;
- subnet/exit authorization and host-state rollback;
- UDP-blocked TCP fallback; and
- shared golden vectors in the Go and Rust protocol implementations.
- temporary-helper allowlist, requester binding, foreign-state rejection, clean
  teardown, and crash reconciliation;
- container capability, read-only-root, secret-mount, and namespace-isolation
  assertions; and
- tampered bootstrap metadata, artifact, enrollment replay, and wrong-network
  rejection.

## 7. TLS/TCP fallback

TCP fallback uses a distinct ALPN, TLS 1.3 mutual authentication, the same
certificate-bound authorization and ephemeral route handles as QUIC, bounded
record lengths, bounded receive queues, finite write deadlines, and idle-peer
termination. It is selected only after QUIC failure because a single ordered
TCP stream introduces head-of-line blocking. Switching waits for the old
packet pump to stop, preventing duplicate TUN readers. The relay remains able
to observe plaintext IP packets; TCP fallback does not imply end-to-end packet
encryption.

## 8. Hybrid WireGuard carrier boundary

WireGuard private keys are generated and retained only on the enrolled host.
The controller binds the corresponding public key to NetworkID, NodeID,
overlay ownership, policy epoch, and expiry; relays receive only public
authorization data and already-encrypted WireGuard datagrams. Compromise of a
hybrid relay can drop, delay, replay, or observe encrypted packet sizes and
timing, but must not expose overlay plaintext or permit a key from another
network. The legacy native-QUIC/TCP dataplane retains the plaintext-relay
limitation described above until operators complete hybrid migration.

Hybrid enrollment rejects low-order or duplicate public keys before invite
consumption. A missing key retains stable-v1 legacy enrollment but produces no
hybrid authorization. Authenticated renewal rotates the key and certificate in a
single transaction, and snapshot leases bound how long an old authorization can
survive loss of controller reachability. Pre-schema-v6 nodes have no key and
are deliberately unusable on the hybrid dataplane until they renew.

## 9. Residual and future risks

Rendezvous tokens reveal a short-lived reachability secret to the relay, while direct QUIC still authenticates both certificate identities before carrying packets. Enrollment and renewal remain dependent on controller and CA integrity. End-to-end packet encryption from the relay applies only to the hybrid WireGuard carriers; selecting the legacy native-QUIC dataplane retains relay plaintext exposure. Traffic analysis, compromised endpoints, and compromised issuing authorities remain outside the containment promise described above.
