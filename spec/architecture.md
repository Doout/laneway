# Laneway Architecture

Status: Stable-v1 normative architecture.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** in the Laneway specifications are to be interpreted as described by BCP 14 when, and only when, they appear in all capitals.

## 1. Purpose and scope

Laneway is a private IP overlay. It gives authenticated nodes stable addresses
and carries ordinary IP packets without application-specific proxies. A node
can also act as a controller-authorized subnet router or explicitly selected
exit node. Protocol behavior is independent of implementation language and
runtime.

## 2. Components and product actors

Laneway has four logical components:

| Component | Responsibility |
| --- | --- |
| Controller | networks, identities, certificates, addresses, policy, and approved routes; it MUST NOT carry user packets |
| Relay | rendezvous, session-local route handles, and fallback packet forwarding |
| Endpoint | authentication, path management, routes, and packet exchange through `lane0` |
| CLI | local management; it is not a wire-protocol peer |

Every participating endpoint uses the same reusable node dataplane. Roles are
controller-authorized policy attributes rather than trust granted by different
agent binaries. A protocol node MAY hold any compatible combination of ordinary
peer, subnet-router, exit-node, and relay-client roles.

The product distinguishes a foreground temporary **User**, a persistent host
**Node**, and an isolated container **Exit Node**. Their supported paths,
privilege boundaries, namespace ownership, and cleanup requirements are
normatively defined in [deployment-contract.md](deployment-contract.md).

## 3. Plane separation

Laneway separates three concerns:

1. The control plane distributes authenticated configuration, discovery, routes, policy, capabilities, and health information over reliable QUIC streams.
2. The packet dataplane carries framed raw IP packets, initially in QUIC DATAGRAM frames.
3. The local routing plane maps OS routes through `lane0` to immutable route snapshots.

The controller MUST NOT be in the datapath. A relay MUST make forwarding decisions from authenticated session state and bounded in-memory tables; it MUST NOT query the controller or a database per packet.

Control and packet processing SHOULD have independently bounded queues so control progress is not starved by packet load.

## 4. Connections and paths

Each node initiates outbound connections; a private node MUST NOT require an inbound firewall rule for relay operation. QUIC connections MUST use TLS 1.3 mutual authentication and the identity rules in [identity-v1.md](identity-v1.md).

Defined ALPN identifiers are:

| ALPN | Purpose |
| --- | --- |
| `laneway-relay/1` | Node-to-relay QUIC connection |
| `laneway-peer/1` | Direct peer QUIC connection |
| `laneway-fallback/1` | TLS/TCP fallback connection |

An endpoint MUST reject a connection when the negotiated ALPN does not match the endpoint role. QUIC relay sessions use `laneway-relay/1`; bounded TCP fallback uses `laneway-fallback/1` and [tcp-fallback-v1.md](tcp-fallback-v1.md). Direct peer paths remain capability-gated.

A path is an authenticated carrier associated with a peer. The preference order is direct authenticated path, hole-punched direct authenticated path, relay QUIC/UDP, then relay TLS/TCP. Path selection MUST use only mutually negotiated capabilities and healthy paths. Direct rendezvous is defined by [direct-path-v1.md](direct-path-v1.md); fallback records are defined by [tcp-fallback-v1.md](tcp-fallback-v1.md).

## 5. Packet flow

The virtual interface name is `lane0`. An outbound packet follows:

```text
application -> kernel route -> lane0 -> route snapshot -> path -> frame -> transport
```

An inbound packet follows:

```text
transport -> authenticated path -> handle and source validation -> deframe -> lane0 -> kernel
```

Inbound source validation MUST happen before injection into `lane0`. Route and path lookup MUST NOT perform a persistent-store read. Installing or removing OS routes MUST be transactional where supported and MUST restore previous system state after a clean shutdown or failed startup.

Implementations MUST authenticate certificate identities, negotiate compatible
versions and capabilities, install relay handles from authenticated control
state, and pass the shared golden vectors.

## 6. State ownership

- The controller owns durable identity, authorization, address, and route policy state.
- A relay owns ephemeral sessions and handles that it allocated for those sessions.
- A node owns its private key, boot identifier, active connections, route snapshot, path health, and local OS state.
- Only the authenticated control plane may replace authoritative configuration. Packet contents MUST NOT create routes or identities.

Disconnecting invalidates all handles allocated for that connection. Reconnection creates a new session and requires fresh handle installation; old handles MUST NOT be reused by assumption. For relayed traffic, the relay rewrites the sender-session destination handle to the receiver-session handle representing the authenticated source peer.

## 7. Fast-path invariants

Implementations MUST use bounded queues and define their behavior on exhaustion.
Packet processing MUST NOT create unbounded work, log packet bodies, query
persistent storage, or route packets through the controller. Forwarding state
changes MUST be atomic; validation, retagging, and enqueueing MUST use one
coherent snapshot.

An implementation MUST reject a packet that exceeds the negotiated path payload limit before transmission. Receivers MUST reject malformed or unsupported frames without forwarding them. Repeated malformed traffic SHOULD cause the offending session to be rate-limited or terminated.

## 8. Failure behavior

Control loss MUST NOT silently broaden authorization. A node MAY continue using a controller-issued configuration for its stated validity period, but MUST fail closed after that period. Transport reconnection MUST reauthenticate and renegotiate; cached session identifiers and route handles are not credentials.

Split-tunnel routing is the default. Default routes (`0.0.0.0/0` or `::/0`) MUST NOT be installed unless the local user explicitly selects an authorized exit node. A transport path to the selected relay, controller, or exit node MUST remain outside the tunnel to prevent recursive routing.

## 9. Versioned boundaries

The language-neutral compatibility boundary consists of:

- X.509 certificates and the URI identity profile;
- Protobuf control messages inside length-delimited frames;
- fixed-width integers in network byte order;
- the five-byte packet header and raw IP payload;
- defined capability bits and error codes; and
- canonical golden vectors.

Changes to those boundaries follow [compatibility.md](compatibility.md). Internal APIs, storage schemas, process layout, and implementation language are not protocol commitments.
