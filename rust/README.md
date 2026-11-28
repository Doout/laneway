# Rust workspace

The workspace contains the Laneway controller, relay, endpoint and CLI,
privileged network helper, Docker network plugin, and shared protocol crates.
The [v1 specifications](../spec/) and [golden vectors](../testvectors/README.md)
define their wire formats.

## Build and test

Run from the repository root with Rust 1.91 or newer:

```sh
make build
make test
make vet
make fmt-check
```

For an optimized build, run
`cargo build --locked --release --manifest-path rust/Cargo.toml`.

Validate installed configurations without opening listeners or changing host
networking:

```sh
laneway-relay --config /etc/laneway/relay-rust.toml --check-config
lanewayd-rs --config /etc/laneway/node-rust.toml --check-config
```

See [runtime and releases](../docs/rust-runtime-migration.md) for packaging and
deployment, [integration tests](../integration/README.md) for network and
release gates, and [benchmarks](../docs/benchmarks.md) for performance tests.
