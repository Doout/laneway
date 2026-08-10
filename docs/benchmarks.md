# Benchmarks

Use results to track regressions on comparable hardware, not as portable
performance claims.

Run the quick matrix and Go/Rust relay comparison from the repository root:

```sh
make benchmark-matrix
make benchmark-relay-comparison
```

For a custom matrix:

```sh
cd go
go run ./cmd/laneway-bench matrix \
  -duration 2s -flows 1,10,100 -sizes small,mtu \
  -profiles lan,wan -pps 10000 -queue 4096 \
  -loss 0.5 -burst-loss 2 -seed 1
```

`small` is 64 bytes, `mtu` is 1200 bytes, and `wan` adds 25 ms one-way
latency. Loss is deterministic for a fixed seed. Rows include throughput, loss,
latency, CPU, memory, allocations, and queue depth.

Run the standalone Rust Node benchmark from the repository root:

```sh
cargo run --manifest-path rust/Cargo.toml -p laneway-bench --release -- \
  --mode node --flows 10 --packet-size 1400 --duration-secs 10 --json
```

Use `--mode relay-forward` for Rust relay forwarding.

Release jobs run `make benchmark-full-matrix` and
`make benchmark-arch-smoke`. QEMU architecture smoke results prove
compatibility only and are not comparable with native results. Kernel
dataplane benchmarks are documented in the
[integration test guide](../integration/README.md).
