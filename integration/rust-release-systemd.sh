#!/usr/bin/env bash
# Test the exact Rust Linux archive with the packaged controller, relay, and node.
set -euo pipefail

if [[ $# != 3 ]]; then
  echo 'usage: bash integration/rust-release-systemd.sh ARCHIVE amd64|arm64 RELEASE_VERSION' >&2
  exit 2
fi
if [[ $(id -u) != 0 || $(cat /proc/1/comm) != systemd ||
  ! -f /run/.laneway-isolated-systemd-lab || -L /run/.laneway-isolated-systemd-lab ||
  $(stat -c '%u:%a' /run/.laneway-isolated-systemd-lab) != 0:600 ]]; then
  echo 'The release packet gate requires root on a marked disposable Linux systemd VM.' >&2
  exit 2
fi
archive=$1
architecture=$2
version=$3
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
sh "$root/integration/rust-release-package.sh" "$archive" "$architecture" "$version"

probe_dir=$(mktemp -d -t laneway-release-systemd.XXXXXX)
cleanup() {
  find "$probe_dir" -depth -delete
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$probe_dir/rust"
listing=$(tar -tzf "$archive")
bootstrap=laneway/deploy/ephemeral-exit/bootstrap.sh
if [[ $(grep -Fxc "$bootstrap" <<<"$listing") != 1 ]] ||
  ! tar -xzOf "$archive" "$bootstrap" | cmp - "$root/deploy/ephemeral-exit/bootstrap.sh"; then
  echo 'The archived bootstrap must match the installer exercised by the packet gate.' >&2
  exit 1
fi
member=laneway/bin/laneway
if [[ $(grep -Fxc "$member" <<<"$listing") != 1 ]]; then
  printf 'Expected one %s in the Linux archive.\n' "$member" >&2
  exit 1
fi
tar -xzOf "$archive" "$member" > "$probe_dir/rust/laneway"
for name in laneway-controller-rs laneway-healthcheck-rs laneway-relay-rs lanewayd-rs; do
  tar -xzOf "$archive" "laneway/sbin/$name" > "$probe_dir/rust/$name"
done
chmod 0755 "$probe_dir/rust/"*

run_packet_gate() {
  env LANEWAY_RUN_PRIVILEGED=1 LANEWAY_NODE_TEST_WIREGUARD=1 LANEWAY_NODE_WIREGUARD_NATIVE=1 \
    LANEWAY_NODE_WIREGUARD_CREDENTIALS=0 LANEWAY_NODE_WIREGUARD_DRAIN="$1" \
    LANEWAY_NODE_WIREGUARD_SYSTEMD=1 LANEWAY_NODE_WIREGUARD_INVITATION="$2" \
    LANEWAY_NODE_TEST_RUST_RUNTIME_DIR="$probe_dir/rust" \
    bash "$root/integration/rust-controller-node-netns.sh"
}

run_packet_gate 1 0
run_packet_gate 0 1

# Run the packaged ordinary-node and relay units, not the transient WireGuard
# exit unit. Only the lab network and log location will be overridden.
tar -xzf "$archive" -C "$probe_dir"
DESTDIR="$probe_dir/installed" PREFIX=/usr/local sh "$probe_dir/laneway/install.sh"
run_installed_gate() {
  env LANEWAY_RUN_PRIVILEGED=1 LANEWAY_NODE_TEST_WIREGUARD=0 \
    LANEWAY_NODE_WIREGUARD_DRAIN=0 LANEWAY_NODE_WIREGUARD_CREDENTIALS=0 \
    LANEWAY_NODE_WIREGUARD_SYSTEMD=0 LANEWAY_NODE_WIREGUARD_INVITATION=0 \
    LANEWAY_NODE_TEST_PACKAGED_INSTALL="$probe_dir/installed" LANEWAY_NODE_TEST_PACKAGED_RELAY=1 \
    LANEWAY_NODE_TEST_MANAGED_INVITATION="$1" \
    LANEWAY_NODE_TEST_RUST_RUNTIME_DIR="$probe_dir/rust" \
    bash "$root/integration/rust-controller-node-netns.sh"
}
run_installed_gate 0
run_installed_gate 1
