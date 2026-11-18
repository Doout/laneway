#!/usr/bin/env bash
# Run from a dedicated rootless Docker context; never uses host networking.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
case "$(docker info --format '{{json .SecurityOptions}}')" in
  *'"name=rootless"'*) ;;
  *) echo "Use a rootless lab Docker context, or run the gates on a disposable Linux VM." >&2; exit 1 ;;
esac
docker build -t laneway-rust-lab:local "$root/integration/rust-lab"
mounts=(-v "$root:/src:ro"
  -v laneway-rust-lab-target:/src/rust/target
  -v laneway-rust-lab-cache:/usr/local/cargo/registry
  -v laneway-rust-lab-gomod:/go/pkg/mod -v laneway-rust-lab-gobuild:/gobuild)
# Only dependency fetch has external networking; it has no extra capabilities.
docker run --rm "${mounts[@]}" laneway-rust-lab:local sh -ec \
  'cargo fetch --locked --manifest-path rust/Cargo.toml; cd go && go mod download'
docker run --rm --network none --cap-drop ALL \
  -e CARGO_INCREMENTAL=0 -e CARGO_PROFILE_TEST_DEBUG=0 \
  "${mounts[@]}" laneway-rust-lab:local \
  cargo test --locked --manifest-path rust/Cargo.toml -p lanewayd-rs connector
docker run --rm --network none --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --security-opt systempaths=unconfined --device /dev/net/tun \
  -e CARGO_INCREMENTAL=0 -e CARGO_PROFILE_DEV_DEBUG=0 -e CARGO_PROFILE_TEST_DEBUG=0 \
  -e LANEWAY_RUN_PRIVILEGED=1 "${mounts[@]}" laneway-rust-lab:local sh -ec '
    export PATH=/opt/rootless-lab:$PATH
    ./integration/rust-kernel-netns.sh
    ./integration/rust-node-interop.sh
    ./integration/rust-controller-node-netns.sh
    LANEWAY_NODE_TEST_CONTROLLER=rust ./integration/rust-controller-node-netns.sh'
