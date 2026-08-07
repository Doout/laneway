# Rust relay interoperability

This opt-in test builds the real Rust `laneway-relay` binary, launches it with
temporary Go-generated mTLS credentials, connects two unchanged Go
`nodeservice` sessions, and verifies an IPv4 packet crosses
Go node → Rust relay → Go node.

Run it from `go/`:

```sh
go test -tags=rustinterop ./integration/rustrelay -v
```

The build tag keeps the ordinary Go unit suite independent of a local Rust
toolchain while preserving a runnable cross-language release gate.

The tagged suite also launches a controller-backed Rust relay against the real
Go HTTPS/mTLS controller service. It records initial 200 and conditional 304
polls with monotonic epochs, carries an application packet, and verifies that
certificate revocation and snapshot expiry terminate established sessions.

The real Rust node binary requires a kernel TUN. The companion privileged gate
uses disposable network namespaces to verify Rust node → Go relay → Go node,
Rust node → Rust relay → Rust node, Rust node → Rust relay → Go node, and Go
node → Rust relay → Go node application packet exchange. It covers
bidirectional IPv4/IPv6 UDP, ICMP, and TCP over ordinary TUN routes. Additional
cells block relay UDP to prove a Rust node selects TLS/TCP fallback, prove
cross-language direct QUIC forwards no application packet at the relay, assert
NAT and routed sources behind a Rust subnet router, and assert IPv4/NAT66
sources behind a Rust exit gateway:

```sh
sudo env PATH="$PATH" HOME="$HOME" \
  CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
  RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
  LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-node-interop.sh
```
