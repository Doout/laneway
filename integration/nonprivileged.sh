#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo test --locked --manifest-path "${repo_root}/rust/Cargo.toml" -p lanewayd-rs -p laneway-relay
"${repo_root}/integration/release-contract.sh"
