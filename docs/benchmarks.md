# Dataplane benchmarks

Run the in-process node and relay dataplane benchmark on Linux from the repository root:

```sh
cargo run --locked --release --manifest-path rust/Cargo.toml -p laneway-bench -- \
  --mode node --flows 10 --packet-size 1200 --duration-secs 10 --json
```

The modes are `node` for route lookup and packet framing, `relay` for
packet validation and retagging, and `relay-forward` for relay forwarding.
Each run produces one JSON object with throughput, queue drops, latency
percentiles, CPU, memory, allocations, and peak queue depth. The benchmark
models an in-process dataplane. To test live transports and kernel networking,
use the [integration suites](../integration/README.md).

GitHub Actions runs a smoke check and collects a scheduled dataplane matrix on
native Linux amd64 and arm64 runners. Compare measurements on equivalent
hardware with the same mode, flow count, packet size, and duration.
