# Rust implementation

The public CLI, daemon, relay and container healthcheck build from this workspace.
The node’s userspace and Linux TUN modes share the same v1 protocol
library and [golden vectors](../testvectors/README.md) as the Go components.

| Executable | Role |
| --- | --- |
| `laneway` | Public client and deployment CLI. Start with `laneway configure`, `laneway start`, and `laneway update`. |
| `lanewayd` | Defaults to a per-user connector and authenticated loopback SOCKS5 proxy. Linux also supports explicit system networking. See [installation and enrollment](../docs/rootless.md). |
| `laneway-relay` | QUIC and TLS/TCP relay for existing Go and Rust clients. Also serves public bootstrap HTTPS when configured. |
| `laneway-healthcheck` | Local TCP, TLS, and Unix socket probes used by the container images. |

The production `laneway-controller` still runs in Go. The Rust controller
candidate is tested separately against the existing SQLite format. See the
[controller compatibility contract](../docs/controller-migration.md).
The public Rust CLI handles discovery, login, profile renewal, ephemeral
enrollment, and connection policy. Existing Go login profiles work in place.
Linux management commands, managed node installation, Connector activation,
and updates also run through the Rust CLI.

On Linux, a split-tunnel `laneway connect` session runs its packet loop in
Rust. An ordinary user needs the installed network helper to configure the
TUN interface and host routes. The default `laneway configure` and
`laneway start` userspace proxy needs only ordinary sockets.

Linux and macOS packages install a private Go executable, `laneway-compat`,
beside the public CLI. Historical standalone Go update assets continue to
bootstrap upgrades from older installations.

| Command or mode | Runtime |
| --- | --- |
| `laneway configure`, `start` (default) | Rust daemon with an authenticated loopback proxy. |
| `laneway login`, `logout` | Rust CLI with interoperable on-disk profiles. |
| `laneway connect` on Linux | Rust handles split-tunnel packets and privileged TUN, route, exit policy and DNS setup. The existing sudo entry point starts the protected Rust helper. Closed-mode exits and ordinary-user exit sessions still use the Go packet runtime. |
| `laneway connect` on macOS | Rust handles the profile, enrollment and privileged utun and route setup. The foreground packet session still runs in Go. |
| `laneway node run` on Linux | Rust handles compatible TUN configurations and controller route updates. WireGuard, legacy userspace Connectors, Exit gateway service, pprof diagnostics, and configurations outside the native runtime's limits use Go. |
| `laneway controller …` on Linux | Rust management client. Production deployments run a Go controller. |
| `laneway pki …` on Linux | Rust issues and verifies the standard Laneway Ed25519 hierarchy. External issuer profiles can require the Go PKI backend. |

## Build

To build the Rust CLI and daemon on Linux, macOS, or Windows, run

```sh
cargo build --locked --release --manifest-path rust/Cargo.toml -p laneway-cli -p lanewayd
```

To build and test the entire workspace on Linux, run

```sh
make rust-test
cargo build --locked --release --manifest-path rust/Cargo.toml
```

## Run

```sh
rust/target/release/laneway-relay \
  --config deploy/examples/relay.toml

sudo rust/target/release/lanewayd run --system \
  --config deploy/examples/node-rust.toml
```

Validate an installed configuration without opening listeners or changing host
networking:

```sh
laneway-relay --config /etc/laneway/relay.toml --check-config
lanewayd run --system --config /etc/laneway/node-rust.toml --check-config
```

The relay accepts either static peers or controller snapshots, not both. The
system mode requires Linux, `/dev/net/tun`, and `NET_ADMIN` when it manages routes.
Private keys must be mode `0600` or `0640`, and certificates must contain the
configured Laneway SPIFFE identity.

Node metrics use `diagnostics.listen` and relay metrics use
`relay.metrics_listen`. Both listeners require loopback addresses. Existing
relay Prometheus metric names remain available. Go runtime profiling endpoints
were retired with the Go executable.

For relays with public bootstrap HTTPS enabled, keep the existing ACME cache
volume. The Rust relay reads the Go account key and cached certificate. It
can serve a valid cached RSA certificate until expiry. New orders and renewals
use ECDSA P-256, which public bootstrap clients must support.

See [integration tests](../integration/README.md) for cross-language and kernel
gates, and [benchmarks](../docs/benchmarks.md) for performance commands.
