# Rust implementation

The workspace contains the shared `laneway-protocol` library, the
`laneway-relay` QUIC/TCP relay, and the Linux `lanewayd-rs` Node. They use the
same v1 protocol and [golden vectors](../testvectors/README.md) as Go.

## Build

From the repository root:

```sh
make rust-test
cargo build --locked --release --manifest-path rust/Cargo.toml
```

## Run

```sh
rust/target/release/laneway-relay \
  --config deploy/examples/relay-rust.toml

sudo rust/target/release/lanewayd-rs \
  --config deploy/examples/node-rust.toml
```

Validate an installed configuration without opening listeners or changing host
networking:

```sh
laneway-relay --config /etc/laneway/relay-rust.toml --check-config
lanewayd-rs --config /etc/laneway/node-rust.toml --check-config
```

The relay accepts either static peers or controller snapshots, not both. The
Node requires Linux, `/dev/net/tun`, and `NET_ADMIN` when it manages routes.
Private keys must be mode `0600` or `0640`, and certificates must contain the
configured Laneway SPIFFE identity.

Node metrics use `diagnostics.listen`; relay metrics use
`relay.metrics_listen`. Both must stay on loopback because they have no
application authentication.

See [integration tests](../integration/README.md) for cross-language and kernel
gates, and [benchmarks](../docs/benchmarks.md) for performance commands.
