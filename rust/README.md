# Rust implementation

`laneway-protocol` generates the same `laneway.v1` Protobuf schema used by Go
and implements strict packet framing, IDs, URI/certificate identity extraction,
capability negotiation, and bounded control framing. Its tests consume the
top-level `testvectors/` directly.

`laneway-relay` is a deployable QUIC/UDP and TLS/TCP relay using the shared
wire format. It requires TLS 1.3 mutual authentication, rejects 0-RTT, bounds
sessions/control frames/route handles/packet queues, and enforces source and
destination ownership plus controller ACLs before forwarding. It supports
either `[[peers]]` static authorization or leased controller snapshots with
exact controller SPIFFE service pinning, epoch polling, revocation updates,
and fail-close expiry. Directional route handles are rewritten identically on
the QUIC and `laneway-fallback/1` carriers. QUIC sessions also publish their
relay-observed UDP endpoint for bounded, tokenized direct-path rendezvous.
Registration, replacement, release, and cleanup remain serialized control-plane
mutations. Each completed mutation publishes one coherent bilateral forwarding
graph through `ArcSwap`; packet lookup never acquires the registry mutex.
Controller authority is likewise loaded once per packet, so both prefix checks
and policy evaluation use one epoch without cloning authorization vectors.

```sh
cargo test --manifest-path rust/Cargo.toml
cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings
```

Build and run the relay from the repository root:

```sh
cargo build --locked --release --manifest-path rust/Cargo.toml -p laneway-relay
rust/target/release/laneway-relay --config deploy/examples/relay-rust.toml
```

The relay keeps its periodic structured metric snapshots and can additionally
serve label-free Prometheus text from `GET /metrics` when
`relay.metrics_listen` is set to an explicit loopback socket. The HTTP surface
is disabled when that field is empty, rejects wildcard/non-loopback binds, and
bounds concurrent clients, request bytes, and read/write time. It provides no
profiling or authentication routes; keep it local or collect it through an
authenticated administrative tunnel. Metrics include sessions, bindings,
forwarded traffic, classified drops, QUIC/TCP connection attempts and failures,
current/peak outbound queued-or-channel-reserved packet count, and TLS/TCP
packet-pool misses. The reservation wording is intentional: producers first
reserve real bounded channel capacity, then increment the gauge immediately
before publication so a concurrent receiver cannot decrement first. Full or
closed attempts never affect the gauge or peak.

The relay accepts the same relay TOML fields used by the Go binary. Controller
mode additionally requires `controller.service_id`, which must match the
controller-role SPIFFE certificate exactly. TLS paths reference the relay-role
certificate, its private key, and the network CA. No private key is included in
this repository.

The real cross-language release gate builds this binary and runs two unchanged
Go node sessions through it:

```sh
cd go
go test -tags=rustinterop ./integration/rustrelay -v
```

Networking components build on `laneway-protocol`; there is no Rust-specific
wire format.

## Native Linux node agent

`lanewayd-rs` is the second deployable Rust component. It owns `/dev/net/tun`,
longest-prefix routing, bounded packet queues, relay QUIC with stable-v1
TLS/TCP fallback, authenticated direct peer QUIC, keepalive, and reconnect
inside one process; there is no per-packet Go IPC. Relay datagrams use the
shared five-byte header and direct datagrams use the same raw-IP and `LWPD`
identity-binding format as the Go agent.

When QUIC is unavailable, TCP remains the only packet consumer while bounded
background QUIC recovery attempts run. A fully authenticated and registered
QUIC carrier replaces TCP; stale route handles are cleared before the promoted
carrier begins pumping packets.

```sh
cargo build --locked --release --manifest-path rust/Cargo.toml -p lanewayd-rs
sudo rust/target/release/lanewayd-rs --config deploy/examples/node-rust.toml
```

The agent accepts a dedicated, strict TOML schema. `tun.configure = true`
installs only explicitly configured interface addresses and routes and removes
them on graceful shutdown. Exit routes are installed as two `/1` routes after
pinning the relay's native host route, preventing tunnel recursion. Direct peer
entries are an authorization allowlist: an optional `address` enables a static
path, while relay-issued candidates trigger coordinated probes on the shared
UDP socket. Direct failure always retains the relay path; the lower node ID
dials and the higher node ID accepts, avoiding duplicate connection churn.
Long-lived QUIC sessions refresh their relay-observed candidate so failed
direct paths can rendezvous again. Keep
`direct.candidate_refresh_interval` above the Rust relay's
`relay.candidate_republish_floor`; accepted refreshes generate at most one
fresh pairing per peer and floor interval.
Host nodes use an ephemeral shared UDP port by default. The local `/v1/peers`
response reports the selected `direct`, `relay-quic`, `tcp-fallback`, or
`disconnected` path independently for every peer.

`forwarding.owned_prefixes` declares LAN prefixes that may cross the TUN.
Enabling `subnet_router` requires an exact `subnet_routes` entry for every
forwarded prefix, including its native interface and `nat` or `routed` mode.
Enabling `exit_gateway` likewise requires exact overlay source prefixes and a
native output interface. The agent transactionally owns its dedicated
nftables tables and required IPv4/IPv6 forwarding sysctls, restores prior
values on shutdown, and reclaims only an exact crashed predecessor.

Exit-client defaults use a dedicated policy table instead of the main route
table. They require explicit local authorization, failure mode, and selected
node; native relay, TCP fallback, direct, controller, and configured LAN
bypasses are installed before the family-specific split defaults. Rust exit
clients can transactionally own systemd-resolved's per-link DNS servers,
`~.` routing domain, and default-route flag with `dns_servers`. The exact prior
state is journaled before mutation, restored on graceful shutdown, and
recovered after a crash only while every live field still matches either the
prior or Laneway-owned value. Corrupt journals or external replacements stop
startup without overwriting resolver state. In `failure_mode = "open"`, loss
of every relay, TCP fallback, and direct path to the selected exit removes both
policy routing and owned DNS after bounded hysteresis; recovery restores them.
Closed mode retains the tunnel policy so traffic cannot leak.

An optional `[diagnostics]` `listen` address exposes label-free Prometheus
metrics at `GET /metrics`. It must be an explicit nonzero loopback socket; the
server bounds request size, deadlines, and concurrent connections. It has no
remote authentication and deliberately exposes no profiling routes. See the
operations runbook for local collection and Rust profiling commands.

The native node accepts private-key modes `0600` and `0640`; group write or
execute and every world permission are rejected. This matches the supplied
`root:laneway 0640` deployment contract.

The bounded native packet benchmark covers both node-style routing and
relay-style authenticated forwarding for 1, 10, or 100 flows. Run small and
MTU-sized cases with stable JSON output:

```sh
cargo run -p laneway-bench --release -- \
  --mode node --flows 10 --packet-size 1400 --duration-secs 10 --json
```

Use `--mode relay-forward` with packet sizes up to the negotiated 1280-byte
relay maximum to benchmark the production immutable forwarding snapshot,
single-epoch authorization/policy check, in-place handle retag, bounded queue,
and prewarmed packet pool. `allocations_per_packet` makes the fast-path
allocation evidence explicit; authorization prefix vectors are borrowed from
the loaded controller snapshot or session fallback and are never cloned per
packet. The current custom-owner `Bytes` representation still performs about
one small owner-metadata allocation per forwarded packet; the payload `Vec`
storage itself is recycled by the packet pool.

Each record reports packets/bytes, pps/Gbps, p50/p95/p99 latency, drops/loss,
CPU, RSS, measured allocations, and maximum queue depth. The packet queue and
latency sample storage are preallocated before measurement. The node relay
path uses a bounded lock-free pool sized to its configured packet queue; Quinn
returns each allocation to the pool after transmission. Pool exhaustion is
visible as `packet_pool_misses` in the node metric snapshot. The Rust relay
retags uniquely owned QUIC/TCP frames in place and transfers the same buffer to
the destination writer. Its TLS/TCP receive path shares a bounded pool
prewarmed to `tcp_fallback.queue_depth`; `Bytes::from_owner` returns each packet
buffer after the destination writer releases it. Exhaustion falls back to one
bounded packet allocation and increments
`laneway_relay_tcp_packet_pool_misses_total`.
The production relay binary also wraps the system allocator with relaxed
atomic counters exported as `laneway_relay_allocator_allocations_total` and
`laneway_relay_allocator_allocated_bytes_total`. Synchronous allocations used
only to dispatch, parse, and render the diagnostics scrape are excluded so the
observer does not charge its own request buffers to the next workload sample;
the exclusion guard is thread-local and never crosses an asynchronous
suspension. The external Go/Rust relay comparison samples the counters' delta
over the same packet measurement interval.

Node certificates used for direct paths need both client-auth and server-auth
EKUs plus a Laneway node-role SPIFFE URI; no DNS SAN is required. Direct peer
authentication checks the trusted chain and exact network/node identity, while
`direct_peers.server_name` is retained only for configuration compatibility.
Relay-only clients need client-auth; relay server names continue to use normal
WebPKI verification. Every node configuration
also requires `relay.service_id`; the relay certificate must match that exact
relay-role network/service SPIFFE identity.
