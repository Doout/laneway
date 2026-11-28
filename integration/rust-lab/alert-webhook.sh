#!/usr/bin/env bash
# Isolated TLS sink for the Rust alert worker. The container has no egress.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
lab_image=${LANEWAY_RUST_LAB_IMAGE:-laneway-rust-lab:local}
if ! docker image inspect "$lab_image" >/dev/null 2>&1; then
  docker build --tag "$lab_image" "$root/integration/rust-lab"
fi
docker run --rm --cap-drop ALL -v "$root:/src:ro" \
  -v laneway-rust-lab-cache:/usr/local/cargo/registry "$lab_image" \
  cargo fetch --locked --manifest-path rust/Cargo.toml

docker run --rm --network none --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE \
  --tmpfs /tmp:exec,size=1g -v "$root:/src:ro" \
  -v laneway-rust-lab-target:/src/rust/target -v laneway-rust-lab-cache:/usr/local/cargo/registry \
  -e LANEWAY_LAB_ALERT_WEBHOOK=1 -e CARGO_INCREMENTAL=0 -e CARGO_PROFILE_DEV_DEBUG=0 \
  -w /src "$lab_image" sh -ec '
    ip link set lo up
    ip address add 8.8.4.4/32 dev lo
    cargo test --offline --locked --manifest-path rust/Cargo.toml \
      -p laneway-controller --bin laneway-controller \
      sends_exact_signed_bytes_to_pinned_tls_and_does_not_redirect -- --ignored --nocapture'
