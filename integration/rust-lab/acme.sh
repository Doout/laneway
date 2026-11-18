#!/usr/bin/env bash
# Exercise real TLS-ALPN issuance and hot renewal with an isolated test CA.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
pebble_volume="$(docker volume create --label laneway.test=rust-acme)"
cleanup() { docker volume rm "$pebble_volume" >/dev/null; }
trap cleanup EXIT
docker run --rm -v "$pebble_volume:/tools" -v laneway-rust-lab-gomod:/go/pkg/mod \
  -v laneway-rust-lab-gobuild:/gobuild -e GOBIN=/tools laneway-rust-lab:local \
  go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.3
docker run --rm -v "$root:/src:ro" -v laneway-rust-lab-target:/src/rust/target \
  -v laneway-rust-lab-cache:/usr/local/cargo/registry \
  -v laneway-rust-lab-gomod:/go/pkg/mod -e CARGO_PROFILE_DEV_DEBUG=0 -e CARGO_INCREMENTAL=0 \
  -w /src laneway-rust-lab:local sh -ec '
    cargo build --locked --manifest-path rust/Cargo.toml -p laneway-controller -p laneway-relay
    cd go && go mod download'
docker run --rm --network none --cap-drop ALL -v "$root:/src:ro" \
  -v "$pebble_volume:/tools:ro" -v laneway-rust-lab-target:/src/rust/target:ro \
  -v laneway-rust-lab-gomod:/go/pkg/mod -v laneway-rust-lab-gobuild:/gobuild \
  -e LANEWAY_RUST_PEBBLE=/tools/pebble \
  -e LANEWAY_RUST_CONTROLLER=/src/rust/target/debug/laneway-controller \
  -e LANEWAY_RUST_RELAY=/src/rust/target/debug/laneway-relay \
  -w /src/go laneway-rust-lab:local \
  go test -count=1 -tags=rustinterop ./internal/controllerservice -run '^TestRustControllerDiscovery$' -v
