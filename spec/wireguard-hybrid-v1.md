# WireGuard hybrid dataplane v1

## Identity binding

Every client that enables the hybrid dataplane MUST enroll a locally generated,
raw 32-byte X25519 WireGuard public key. The controller rejects malformed,
low-order, and already-bound keys before consuming the single-use enrollment token. The client
MUST authenticate the bootstrap NetworkID and enrollment class, MUST retain the
private key locally, and MUST compare the public key echoed by the enrollment
response before installing credentials.

The controller stores one globally unique public key on the node row. Global
uniqueness intentionally rejects private-key reuse across networks as well as
within one network. A node snapshot publishes that key alongside the exact
NodeID and controller-assigned overlay addresses. A peer MUST treat a missing
key as an unbound pre-v6-schema identity and MUST NOT authorize it on any
WireGuard carrier.

Authenticated certificate renewal carries the current or replacement public
key. Certificate insertion, key replacement, audit event, and configuration
epoch increment are one database transaction. A uniqueness, signing,
persistence, cancellation, or commit failure retains the old key and epoch and
does not publish the replacement certificate. Successful rotation invalidates
the old key at the next bounded configuration snapshot; revocation removes the
node and its key from active snapshots under the existing fail-closed lease.

Private keys are 32 raw bytes in protected local credential files. They are
never present in controller requests, snapshots, relay messages, diagnostics,
or audit records. Foreground sessions keep an unlinked descriptor; managed
nodes install a root-owned, service-group-readable mode-0640 file. Enrollment
and renewal clients verify that controller responses echo the derived public
key before promoting any local credential set.

## Logical device and carriers

One stable `lane0` WireGuard device owns the controller overlay addresses and
routes. Carrier selection MUST NOT recreate that device or change its public
key, addresses, ACL, route ownership, or exit policy. Each peer has exactly one
of these observable carrier states:

1. `direct-wireguard`
2. `wireguard-relay-quic`
3. `wireguard-relay-tcp`
4. `negotiating`, `degraded`, or `disconnected`

The direct carrier sends ordinary WireGuard UDP after authenticated endpoint
discovery. Relay carriers transport the same already-encrypted WireGuard UDP
datagrams through an authenticated Laneway relay session. The relay validates
sender and receiver authorization and bounded record sizes but never possesses
a WireGuard private key or decrypts an overlay packet.

The carrier manager prefers direct UDP, demotes only after a bounded failure
threshold, and promotes only after a bounded healthy interval. QUIC relay is
the first fallback and bounded TCP relay is last. Endpoint changes trigger
authenticated roaming and direct retry without withdrawing overlay routes.

## Fail-closed invariants

- A key is usable only with the NetworkID, NodeID, overlays, routes, lease, and
  policy in the same or newer controller epoch.
- Unknown, unbound, duplicate, expired, and revoked keys carry no traffic.
- Carrier changes never broaden ACLs, source prefixes, exit authorization, or
  subnet ownership.
- Relay envelopes include authenticated network and peer identities and reject
  cross-network destinations, replay, oversize records, and unauthorised source
  addresses before queueing.
- Controller, relay, and direct endpoint bypass routes remain outside a selected
  full tunnel, preventing recursive encapsulation.
- The effective MTU is the minimum safe value across configured carriers; v1
  starts at 1280 so both IPv4 and IPv6 remain deterministic under relay nesting.

## Schema migration

Controller schema v6 adds a nullable `nodes.wireguard_public_key` only so an
existing database can start safely. Existing rows remain unbound and therefore
fail closed for the hybrid dataplane until an authenticated renewal binds a
key. Field absence remains the stable-v1 compatibility value: legacy clients
enroll or renew an unbound native-QUIC identity, while already-bound identities
retain their key during a legacy renewal. An absent key can never authorize a
hybrid carrier. Rolling back to a
pre-v6 controller is unsupported after any node has bound a key because it
cannot publish or revoke the hybrid identity correctly.
