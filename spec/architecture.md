# Laneway Architecture

Status: Stable-v1 normative architecture.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** in the Laneway specifications are to be interpreted as described by BCP 14 when, and only when, they appear in all capitals.

## 1. Purpose and scope

Laneway is a private IP overlay. It gives authenticated nodes stable overlay addresses and carries ordinary IP packets between them without application-specific proxies. A node can also act as a controller-authorized subnet router or explicitly selected exit node. Stable v1 specifies identity, control negotiation, packet framing, routing, path selection, and interoperability independently of implementation language.

The first implementation is Go, but no Laneway protocol element may depend on Go types, encodings, errors, memory layout, or runtime behavior.

## 2. Components

Laneway has four logical components:

- `laneway-controller` is the authority for networks, identities, certificates, overlay addresses, policy, and approved routes. It MUST NOT carry user packets.
- `laneway-relay` accepts outbound authenticated connections, provides rendezvous, allocates session-local route handles, and forwards packets when no direct path is used.
- `lanewayd` is the node agent. It authenticates, maintains paths, applies routes, and exchanges packets with the operating system through `lane0`.
- `laneway` is the user-facing CLI. It manages the local daemon; it is not a wire-protocol peer.

Every participating endpoint runs the same `lanewayd`. Roles are policy attributes rather than different agent binaries. A node MAY hold any compatible combination of ordinary peer, subnet-router, exit-node, and relay-client roles.

## 3. Plane separation

Laneway separates three concerns:

1. The control plane distributes authenticated configuration, discovery, routes, policy, capabilities, and health information over reliable QUIC streams.
2. The packet dataplane carries framed raw IP packets, initially in QUIC DATAGRAM frames.
3. The local routing plane maps OS routes through `lane0` to immutable in-process routing snapshots.

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

An endpoint MUST reject a connection when the negotiated ALPN does not match the endpoint role. QUIC relay sessions use `laneway-relay/1`; the implemented bounded TCP fallback uses `laneway-fallback/1` and [tcp-fallback-v1.md](tcp-fallback-v1.md). Direct peer paths remain capability-gated.

A path is an authenticated carrier associated with a peer. The preference order is direct authenticated path, hole-punched direct authenticated path, relay QUIC/UDP, then relay TLS/TCP. Path selection MUST use only mutually negotiated capabilities and healthy paths. Direct rendezvous is defined by [direct-path-v1.md](direct-path-v1.md); fallback records are defined by [tcp-fallback-v1.md](tcp-fallback-v1.md).

## 5. Benchmark-foundation data flow

The TUN-less benchmark used to validate the protocol foundation is:

```text
sender -> route lookup -> 5-byte Laneway header -> QUIC DATAGRAM
       -> authenticated relay -> QUIC DATAGRAM -> receiver
```

Before TUN development, two independent programs MUST be able to:

- authenticate with certificates;
- derive network and node identity from those certificates;
- negotiate a compatible protocol version and capability set;
- establish relay route handles through authenticated control state;
- exchange packets conforming to [packet-format-v1.md](packet-format-v1.md); and
- pass the shared golden vectors.

## 6. Production TUN model

The virtual interface name is `lane0`. An outbound packet follows:

```text
application -> kernel route -> lane0 -> route snapshot -> path -> frame -> transport
```

An inbound packet follows:

```text
transport -> authenticated path -> handle and source validation -> deframe -> lane0 -> kernel
```

Inbound source validation MUST happen before injection into `lane0`. Route and path lookup MUST NOT perform a persistent-store read. Installing or removing OS routes MUST be transactional where supported and MUST restore previous system state after a clean shutdown or failed startup.

## 7. State ownership

- The controller owns durable identity, authorization, address, and route policy state.
- A relay owns ephemeral sessions and handles that it allocated for those sessions.
- A node owns its private key, boot identifier, active connections, route snapshot, path health, and local OS state.
- Only the authenticated control plane may replace authoritative configuration. Packet contents MUST NOT create routes or identities.

Disconnecting invalidates all handles allocated for that connection. Reconnection creates a new session and requires fresh handle installation; old handles MUST NOT be reused by assumption. For relayed traffic, the relay rewrites the sender-session destination handle to the receiver-session handle representing the authenticated source peer.

## 8. Fast-path invariants

Implementations MUST use bounded queues and MUST define their behavior on queue exhaustion. They MUST NOT create a goroutine/thread/task per packet, serialize raw packets with Protobuf, log every packet by default, or route packets through the controller. They SHOULD use pooled buffers, immutable route snapshots, batching, and minimal copies.

Relay handle lookup MUST likewise avoid a process-global control-plane lock on
the packet path. Both v1 relays publish immutable per-session forwarding
snapshots atomically after register/bind/release/disconnect transactions;
packet readers retain a snapshot for one validation/retag/enqueue operation.

An implementation MUST reject a packet that exceeds the negotiated path payload limit before transmission. Receivers MUST reject malformed or unsupported frames without forwarding them. Repeated malformed traffic SHOULD cause the offending session to be rate-limited or terminated.

## 9. Failure behavior

Control loss MUST NOT silently broaden authorization. A node MAY continue using a controller-issued configuration for its stated validity period, but MUST fail closed after that period. Transport reconnection MUST reauthenticate and renegotiate; cached session identifiers and route handles are not credentials.

Split-tunnel routing is the default. Default routes (`0.0.0.0/0` or `::/0`) MUST NOT be installed unless the local user explicitly selects an authorized exit node. A transport path to the selected relay, controller, or exit node MUST remain outside the tunnel to prevent recursive routing.

## 10. Versioned boundaries

The language-neutral compatibility boundary consists of:

- X.509 certificates and the URI identity profile;
- Protobuf control messages inside length-delimited frames;
- fixed-width integers in network byte order;
- the five-byte packet header and raw IP payload;
- defined capability bits and error codes; and
- canonical golden vectors.

Changes to those boundaries follow [compatibility.md](compatibility.md). Internal APIs, storage schemas, process layout, and implementation language are not protocol commitments.
