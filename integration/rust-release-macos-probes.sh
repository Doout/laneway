#!/bin/sh
# Build the two native test harnesses. The probes take the package at runtime.
set -eu
[ "$#" -eq 1 ] || { echo 'usage: sh rust-release-macos-probes.sh OUTPUT_DIRECTORY' >&2; exit 2; }
[ "$(uname -s)" = Darwin ]
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
log=$(mktemp)
trap 'rm -f -- "$log"' EXIT
trap 'exit 1' HUP INT TERM
cargo test --locked --manifest-path "$root/rust/Cargo.toml" -p lanewayd-rs \
  --no-run --lib --test desktop_local_api_lab --message-format=json-render-diagnostics >"$log"
mkdir -p "$1"
for name in lanewayd_rs desktop_local_api_lab; do
  executable=$(jq -ers --arg name "$name" '
    [.[] | select(.reason == "compiler-artifact" and .target.name == $name and .profile.test)
      | .executable | select(type == "string")]
    | if length == 1 then .[0] else error("expected one test executable for " + $name) end
  ' "$log")
  install -m 0755 "$executable" "$1/$name"
done
