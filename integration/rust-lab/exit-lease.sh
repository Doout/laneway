#!/usr/bin/env bash
# Exercise the native node's control loop with both real controller services.
# No TUN, forwarding, live credentials, or privileged networking is needed.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
controller="$(cargo build --locked --manifest-path rust/Cargo.toml -p laneway-controller \
  --message-format=json | jq -ser '[.[] | select(.target.name=="laneway-controller" and .executable!=null) | .executable] | if length==1 then .[0] else error("expected one controller executable") end')"
node_test="$(cargo test --locked --manifest-path rust/Cargo.toml -p lanewayd-rs --lib --no-run \
  --message-format=json | jq -ser '[.[] | select(.profile.test and .executable!=null) | .executable] | if length==1 then .[0] else error("expected one node test executable") end')"
cd go
LANEWAY_RUST_CONTROLLER="$controller" LANEWAY_RUST_EXIT_LEASE_TEST="$node_test" \
  go test -count=1 -tags=rustinterop ./internal/controllerservice -run '^TestRustControllerQUIC$/^rust_ephemeral_exit_lease$' -v
