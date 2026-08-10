# WireGuard Hybrid Dataplane v1

Status: Stable-v1 carrier profile.

Normative terms have the meaning defined in BCP 14.

## 1. Identity binding

A client enabling the hybrid dataplane MUST enroll a locally generated raw
32-byte X25519 WireGuard public key. Before consuming the single-use enrollment
token, the controller MUST reject malformed, low-order, or already-bound keys.
The client MUST authenticate the bootstrap NetworkID and enrollment class, keep
the private key local, and verify the public key echoed by an enrollment or
renewal response before installing credentials.

The controller MUST bind one globally unique public key to the exact NetworkID,
NodeID, overlay addresses, policy epoch, and lease. Global uniqueness rejects
key reuse across as well as within networks. Snapshots publish that binding;
peers MUST NOT authorize a missing or mismatched key on a WireGuard carrier.

Authenticated renewal MAY replace the key. Certificate issuance, key binding,
epoch advancement, and publication MUST be atomic: failure retains the prior
binding, while successful rotation invalidates it at the next bounded snapshot.
Revocation removes the binding from active snapshots under the existing
fail-closed lease.

An absent key means an unbound native-QUIC identity and cannot authorize the
hybrid carrier. A legacy renewal MUST NOT erase an existing binding merely by
omitting the field.

Private keys are raw 32-byte values and MUST remain in protected local
credentials. They MUST NOT appear in controller requests or snapshots, relay
messages, diagnostics, or audit records.

## 2. Logical device and carriers

One stable `lane0` WireGuard device owns overlay addresses and routes. Carrier
selection MUST NOT recreate it or change its key, addresses, ACLs, route
ownership, or exit policy. Each peer has exactly one observable state:

| State | Carrier |
| --- | --- |
| `direct-wireguard` | ordinary WireGuard UDP after authenticated endpoint discovery |
| `wireguard-relay-quic` | encrypted WireGuard datagrams over relay QUIC |
| `wireguard-relay-tcp` | encrypted WireGuard datagrams over bounded relay TCP |
| `negotiating`, `degraded`, `disconnected` | no healthy selected carrier |

Relay carriers use the same already-encrypted datagrams and require negotiated
`LANEWAY_E2E_PACKET_V1` framing. A relay validates identities, authorization,
and record bounds but never receives a WireGuard private key or overlay
plaintext.

The carrier manager prefers direct UDP, demotes only after a bounded failure
threshold, and promotes only after a bounded healthy interval. QUIC relay is
the first fallback and TCP relay is last. Endpoint changes trigger authenticated
roaming and direct retry without withdrawing overlay routes.

## 3. Fail-closed invariants

- A key is valid only with the NetworkID, NodeID, overlays, routes, lease, and
  policy from the same or a newer controller epoch.
- Unknown, unbound, duplicate, expired, and revoked keys carry no traffic.
- Carrier changes never broaden ACLs, source prefixes, exit authorization, or
  subnet ownership.
- Relay envelopes reject cross-network destinations, replay, oversized records,
  and unauthorized sources before queueing.
- Controller, relay, and direct-endpoint bypasses remain outside a selected full
  tunnel.
- The effective MTU is the minimum safe value across carriers; v1 starts at
  1280 for deterministic IPv4 and IPv6 behavior under relay nesting.
