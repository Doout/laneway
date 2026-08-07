# Laneway v1 Observability Profile

Status: Stable-v1 operational profile.

## 1. Scope

This document defines the minimum operational signals for a Laneway node,
relay, and controller. Metrics are implementation-local and are not part of the
wire protocol. They MUST NOT add controller or database work to the packet fast
path.

## 2. Counters

Implementations MUST expose point-in-time counters sufficient to distinguish:

- successful transport connections and reconnects;
- packets or frames sent, received, forwarded, and dropped;
- malformed input and authorization failures;
- active relay sessions, route bindings, and bounded-queue depth;
- QUIC failures and successful or failed TCP fallback attempts; and
- direct-path failures and automatic path switches when direct paths are used.

Counters SHOULD be monotonically increasing for one process lifetime. A process
restart may reset them. A metrics consumer MUST NOT treat a reset as negative
traffic.

## 3. Cardinality and privacy

Metrics MUST have bounded cardinality. Persistent NodeIDs, addresses, route
prefixes, certificate serials, enrollment tokens, packet contents, and peer
names MUST NOT be metric labels. Per-peer detail belongs in the authenticated
local status interface and remains bounded by the configured peer limit.

Packet contents and credentials MUST NOT be logged. Repeated malformed traffic
SHOULD be represented by counters and rate-limited summaries rather than one log
entry per packet.

## 4. Go diagnostics endpoint

The Go daemons accept an opt-in `-diagnostics` TCP address. The address MUST be
an explicit loopback address or `localhost`; wildcard and non-loopback binds are
rejected. The endpoint provides:

```text
GET /metrics
GET /debug/pprof/
GET /debug/pprof/heap
GET /debug/pprof/profile
GET /debug/pprof/trace
```

Operators requiring remote access SHOULD use an authenticated administrative
tunnel. Laneway does not make an unauthenticated profiling server remotely
reachable.

The Go relay exposes active session/binding/queue gauges plus transport
connections and failures, forwarded traffic, malformed input, authorization
failures, policy drops, queue-full drops, and aggregate drops. The Go
controller exposes request/success counters and separate malformed-input,
authorization-failure, and internal-failure counters. These classifications
are deliberately label-free; peer identities, routes, and credentials never
become metric dimensions.

## 5. Rust node diagnostics endpoint

The native Rust node accepts an optional `diagnostics.listen` socket in its
strict TOML configuration. The address MUST be an explicit, nonzero loopback
socket. The endpoint serves only:

```text
GET /metrics
```

The Rust endpoint MUST bound concurrent connections, request bytes, and I/O
deadlines. It has no application authentication because it is local-only;
operators MUST NOT publish it through an unauthenticated proxy. It does not
provide remote profiling or pprof routes.

The Rust node exports process-lifetime counters for connections/reconnections,
packets/bytes sent and received, classified malformed/authorization/policy and
queue/no-path drops, QUIC/TCP/direct attempts and failures, direct switches,
and pool or concurrency saturation. Gauges distinguish active QUIC and TCP
carriers, active direct paths, selected-exit health, current outbound and
injection queue depths, and the maximum observed queue depth. These metrics
are node-global and label-free; they do not identify a peer, route, address,
or credential.

## 6. Rust relay diagnostics endpoint

The native Rust relay accepts an optional `relay.metrics_listen` socket in its
strict TOML configuration. The address MUST be an explicit loopback IP socket;
wildcard, hostname, and non-loopback addresses are rejected. The endpoint
serves only:

```text
GET /metrics
```

The relay MUST bound concurrent connections, request bytes, and read/write
deadlines. It has no application authentication or profiling routes and MUST
NOT be published through an unauthenticated proxy. Metrics are process-global
and label-free. They include the existing session, registration, binding,
candidate, forwarding, and classified-drop counters; QUIC and TLS/TCP
connection attempts and failures; aggregate current and peak outbound queue
depth; TCP receive-pool misses; and successful process allocation calls plus
requested allocation bytes from the production system-allocator wrapper.
Periodic structured metric logs remain
available independently of the HTTP listener.

## 7. Backpressure

All dataplane queues MUST be bounded and MUST expose drops caused by a full
queue. Profiling and metrics serving run outside packet loops. A slow metrics
consumer MUST NOT delay packet forwarding or controller configuration polling.
