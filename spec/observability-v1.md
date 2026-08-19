# Laneway v1 Observability Profile

Status: Stable-v1 operational profile.

Normative terms have the meaning defined in BCP 14.

## 1. Scope

This document defines minimum local signals for nodes, relays, and controllers.
Metrics are not part of the wire protocol and MUST NOT add controller or
database work to the packet path.

## 2. Required signals

Implementations MUST expose point-in-time counters or gauges for:

| Area | Signals |
| --- | --- |
| Transport | successful connections, reconnects, failures, and current carriers |
| Traffic | packets or frames sent, received, forwarded, and dropped |
| Rejection | malformed input, authorization failures, policy drops, and no-path drops |
| Capacity | active sessions and bindings, queue depth, queue-full drops, and configured-limit saturation |
| Path selection | QUIC failures, TCP fallback attempts and results, direct-path failures, and automatic switches |
| Exit service | forwarding and NAT readiness, forwarded traffic, and namespace-cleanup failures |

Counters SHOULD increase monotonically for one process lifetime. Consumers MUST
treat a restart as a reset, not negative traffic.

## 3. Cardinality, privacy, and logging

Metrics MUST have bounded cardinality and MUST NOT label persistent NodeIDs,
addresses, route prefixes, certificate serials, tokens, packet contents, or
peer names. Bounded per-peer detail belongs only in the authenticated local
status API.

Packet contents and credentials MUST NOT be logged. Repeated malformed traffic
SHOULD produce counters and rate-limited summaries rather than per-packet logs.

## 4. Local status

The authenticated mode-0600 Unix status API and `laneway status` MUST return a
bounded readiness summary:

| Scope | Required status |
| --- | --- |
| Every actor | actor type, NetworkID, NodeID, overlay addresses, installed routes, active carrier, controller certificate health, configuration-lease deadline, and explicit lease-expired state |
| Ephemeral identity | identity-lease deadline |
| Peer | one of `direct`, `relay-quic`, `tcp-fallback`, or `disconnected` |
| Exit client | selected Exit Node and authorization state |
| Exit server | forwarding and NAT readiness, forwarded packets, and namespace-cleanup failures |
| Foreground User | `actor=user`, owned routes, local-LAN bypasses, DNS ownership (`native` or `temporary-session`), identity deadline, and `cleanup_journal=helper-active` while connected |

Go and Rust local APIs share JSON field names. Unknown deadlines are zero and
empty bounded lists are encoded as empty arrays. Status MUST NOT include tokens,
keys, rendezvous material, or packet data. A foreground User reports successful
network-state restoration when it exits cleanly.

## 5. Controller latest endpoint status

Endpoint status reporting is optional and runs outside the packet path. A node
submits a strict JSON object to `PUT /v1/status` over its existing authenticated
management connection. The controller applies the same mTLS identity,
certificate, durable node-revocation, and identity-lease checks used by
configuration requests before parsing or accepting the report.

The request contains exactly these fields:

```json
{
  "valid_for_seconds": 60,
  "product_version": "1.2.3",
  "platform": "linux",
  "certificate_state": "healthy",
  "configuration_state": "current",
  "carrier_state": "relay_quic",
  "route_state": "ready",
  "selected_exit_state": "not_selected",
  "cleanup_failure_count": 0,
  "configuration_epoch": 42
}
```

`valid_for_seconds` MUST be 10 through 300. Product version is 1 through 64
printable ASCII bytes. Platform is `linux`, `darwin`, `windows`, `other`, or
`unknown`. Certificate state is `healthy`, `renewal_due`, `expired`, `revoked`,
or `unknown`. Configuration state is `current`, `stale`, `expired`, or
`unknown`. Carrier state is `direct`, `relay_quic`, `relay_tcp`, `negotiating`,
`degraded`, `disconnected`, or `unknown`. Route state is `ready`, `degraded`,
`unavailable`, or `unknown`. Selected Exit state adds `not_selected` to the
route-state vocabulary. Cleanup failures are a bounded aggregate counter.

The controller owns `observed_at` and `expires_at`; endpoint clocks do not.
`expires_at` is exactly `observed_at + valid_for_seconds`.
Only one row per NodeID is retained, and a report older than the retained
observation is rejected. A report whose configuration epoch is ahead of the
controller is rejected. A lower epoch is exposed as `stale`, even if the
endpoint claimed `current`; staleness is re-evaluated when administrators read
the report so a later controller change cannot leave old status marked current.

The protected administrator read is
`GET /v1/admin/networks/{network_id}/endpoint-statuses`. It returns one bounded
inventory row per node with freshness `current`, `expired`, `never_reported`,
or `node_inactive`. Runtime report fields are returned only for `current`.
Expired and inactive rows may retain last-report and expiry timestamps as
evidence but MUST NOT return stale health fields. Revocation, identity-lease
expiry, or absence of a controller-valid certificate produces `node_inactive`;
administrative enablement or the absence of revocation never produces current
health.

Reports MUST NOT contain tokens, keys, packet contents, private endpoints,
free-form local data, per-peer state, or unbounded collections. Reporting does
not create per-heartbeat audit history. Loss or rejection of telemetry MUST NOT
change authorization or interrupt otherwise healthy forwarding.

## 6. Diagnostics listeners

| Implementation | Opt-in setting | Routes | Binding requirements |
| --- | --- | --- | --- |
| Go daemons | `-diagnostics` | `/metrics`, `/debug/pprof/`, `/debug/pprof/heap`, `/debug/pprof/profile`, `/debug/pprof/trace` | explicit loopback address or `localhost`; reject wildcard and non-loopback addresses |
| Rust node | `diagnostics.listen` | `/metrics` | explicit nonzero loopback socket; bounded connections, request bytes, and I/O deadlines |
| Rust relay | `relay.metrics_listen` | `/metrics` | explicit loopback IP socket; reject hostnames and wildcard/non-loopback addresses; bound connections, request bytes, and I/O deadlines |

These listeners have no application authentication. Operators MUST use an
authenticated administrative tunnel for remote access and MUST NOT expose them
through an unauthenticated proxy. Rust listeners do not provide profiling
routes.

## 7. Component metrics

| Component | Required coverage |
| --- | --- |
| Controller | requests, successes, malformed input, authorization failures, and internal failures |
| Relay | sessions, registrations, bindings, candidates, forwarding, classified drops, QUIC and TLS/TCP results, and current/peak queue depth |
| Node | connections, packets and bytes, classified drops, QUIC/TCP/direct results, path switches, carrier and direct-path gauges, and current/peak queue depth |
| Exit Node | forwarded traffic, forwarding readiness, NAT readiness, and namespace-cleanup failures |

Metrics are process-global and label-free. The Go Exit Node names are
`laneway_exit_forwarded_packets_total`, `laneway_exit_forwarding_ready`,
`laneway_exit_nat_ready`, and
`laneway_exit_namespace_cleanup_failures_total`. Rust exposes
`laneway_rust_node_exit_forwarded_packets_total`,
`laneway_rust_node_exit_forwarded_bytes_total`, readiness gauges, and
`laneway_rust_node_exit_namespace_cleanup_failures_total`. A forwarded packet
means accepted between the encrypted carrier and Exit TUN; it does not prove
that an Internet destination replied.

## 8. Alerts and backpressure

Operators SHOULD alert on approaching certificate, identity, or configuration
lease deadlines; sustained limiter or queue saturation; path-failure rates
outside the normal baseline; any cleanup failure; and an enabled Exit Node with
forwarding or NAT readiness at zero. Relay fallback is healthy behavior, but a
sustained loss of direct paths is an operational signal.

All dataplane queues MUST be bounded and expose queue-full drops. Metrics and
profiling run outside packet loops; a slow consumer MUST NOT delay forwarding or
configuration polling.
