# Benchmarks

Laneway keeps benchmarks bounded and explicit about which part of the system
they measure. Shared CI runner results are useful for regressions, not as
hardware-independent performance claims.

## Quick matrix

```bash
make benchmark-matrix
make benchmark-relay-comparison
```

The quick matrix covers native UDP and QUIC baselines plus authenticated direct
QUIC, relay QUIC, relay TCP fallback, subnet forwarding, and exit forwarding.
The relay comparison runs equivalent Go and Rust QUIC/TCP relay workloads.

Each row reports packet and byte throughput, drops, latency percentiles, CPU,
RSS, allocations, garbage collection, and queue depth. Scenario `scope` fields
distinguish loopback baselines, authenticated paths, and TUN-less forwarding
tests. Kernel TUN, routing, NAT, and nftables evidence is collected separately
by the privileged integration workflow.

## Custom matrix

```bash
cd go
go run ./cmd/laneway-bench matrix \
  -duration 2s -flows 1,10,100 -sizes small,mtu \
  -profiles lan,wan -pps 10000 -queue 4096 \
  -loss 0.5 -burst-loss 2 -seed 1
```

`small` is 64 bytes and `mtu` is 1200 bytes. LAN adds no artificial delay;
WAN adds 25 ms one-way delay. Loss and burst injection use a deterministic
seed. Flow counts are logical packet flows multiplexed over an authenticated
carrier, not separate connections.

## Release evidence

```bash
make benchmark-full-matrix
make benchmark-arch-smoke
```

The full matrix exercises Go and Rust relays across flow counts, sizes, network
profiles, and deterministic loss. GitHub workflows retain raw output, validated
JSONL, checksums, tool versions, and architecture classification. ARM64 QEMU
smoke results prove architecture compatibility only and must not be compared
with native AMD64 performance.

Privileged kernel benchmarks and complete reproduction notes live in
[`integration/README.md`](../integration/README.md).
