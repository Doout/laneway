#!/usr/bin/env bash
# Build and test the real Dispatch client against two local Rust services.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
dispatch="${1:?usage: dispatch.sh DISPATCH_CHECKOUT [REVISION]}"
revision="$(git -C "$dispatch" rev-parse --verify --end-of-options "${2:-HEAD}^{commit}")"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/laneway-dispatch-XXXXXXXX")"
dispatch_volume=""
cleanup() {
  find "$scratch" -depth -delete
  if [[ -n "$dispatch_volume" ]]; then docker volume rm "$dispatch_volume" >/dev/null; fi
}
trap cleanup EXIT
git -C "$dispatch" archive "$revision" go.mod go.sum internal/laneway |
  tar -xf - -C "$scratch"
mkdir -p "$scratch/cmd/laneway-lab"
cp "$root/integration/rust-lab/dispatch-client/main.go" "$scratch/cmd/laneway-lab/main.go"
echo "Using Dispatch client $revision"
dispatch_volume="$(docker volume create --label laneway.test=dispatch-client)"
COPYFILE_DISABLE=1 tar --no-xattrs -cf - -C "$scratch" . |
  docker run --rm -i --network none -v "$dispatch_volume:/dispatch" -w /dispatch \
    laneway-rust-lab:local sh -ec 'tar --no-same-owner -xf - && chmod 0755 /dispatch'
docker run --rm -v "$root:/src:ro" -v laneway-rust-lab-target:/src/rust/target \
  -v laneway-rust-lab-cache:/usr/local/cargo/registry \
  -v laneway-rust-lab-gomod:/go/pkg/mod -e CARGO_PROFILE_DEV_DEBUG=0 -e CARGO_INCREMENTAL=0 \
  -w /src laneway-rust-lab:local sh -ec '
    cargo build --locked --manifest-path rust/Cargo.toml -p laneway-controller -p laneway-relay
    cd go && go mod download'
docker run --rm --network none --cap-drop ALL -v "$root:/src:ro" \
  -v "$dispatch_volume:/dispatch:ro" -v laneway-rust-lab-target:/src/rust/target:ro \
  -v laneway-rust-lab-gomod:/go/pkg/mod -v laneway-rust-lab-gobuild:/gobuild \
  -e LANEWAY_DISPATCH_PROBE=/tmp/dispatch-client \
  -e LANEWAY_RUST_CONTROLLER=/src/rust/target/debug/laneway-controller \
  -e LANEWAY_RUST_RELAY=/src/rust/target/debug/laneway-relay \
  -w /dispatch laneway-rust-lab:local sh -ec '
    go build -mod=readonly -o /tmp/dispatch-client ./cmd/laneway-lab
    cd /src/go
    go test -count=1 -tags=rustinterop ./internal/controllerservice -run "^TestRustControllerDiscovery$" -v'
