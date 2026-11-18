#!/usr/bin/env bash
# Test the exact Linux archive to be released, including the legacy peer.
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
trap 'find "$probe_dir" -depth -delete' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$probe_dir/go" "$probe_dir/rust"
# Take both peers and both release servers from the archive. Extract to plain
# files rather than installing over any of the host's binaries.
listing=$(tar -tzf "$archive")
bootstrap=laneway/deploy/ephemeral-exit/bootstrap.sh
if [[ $(grep -Fxc "$bootstrap" <<<"$listing") != 1 ]] ||
  ! tar -xzOf "$archive" "$bootstrap" | cmp - "$root/deploy/ephemeral-exit/bootstrap.sh"; then
  echo 'The archived bootstrap must match the installer exercised by the packet gate.' >&2
  exit 1
fi
for member in laneway/bin/laneway laneway/sbin/laneway-relay; do
  if [[ $(grep -Fxc "$member" <<<"$listing") != 1 ]]; then
    printf 'Expected one %s in the Linux archive.\n' "$member" >&2
    exit 1
  fi
  tar -xzOf "$archive" "$member" > "$probe_dir/go/${member##*/}"
done
cp "$probe_dir/go/laneway" "$probe_dir/go/lanewayd"
for name in laneway-controller-rs laneway-relay-rs lanewayd-rs; do
  tar -xzOf "$archive" "laneway/sbin/$name" > "$probe_dir/rust/$name"
done
for fixture in netprobe rustnodecontroller; do
  if [[ -n ${LANEWAY_NODE_TEST_GO_FIXTURE_DIR:-} ]]; then
    install -m 0755 "$LANEWAY_NODE_TEST_GO_FIXTURE_DIR/$fixture" "$probe_dir/go/$fixture"
  else
    (cd "$root/go" && CGO_ENABLED=0 go build -o "$probe_dir/go/$fixture" "./integration/$fixture")
  fi
done
chmod 0755 "$probe_dir/go/"* "$probe_dir/rust/"*

run_packet_gate() {
  local controller="$1" drain="$2" invitation="$3"
  env LANEWAY_RUN_PRIVILEGED=1 LANEWAY_NODE_TEST_CONTROLLER="$controller" \
    LANEWAY_NODE_TEST_WIREGUARD=1 LANEWAY_NODE_WIREGUARD_NATIVE=1 \
    LANEWAY_NODE_WIREGUARD_CREDENTIALS=0 LANEWAY_NODE_WIREGUARD_DRAIN="$drain" \
    LANEWAY_NODE_WIREGUARD_SYSTEMD=1 LANEWAY_NODE_WIREGUARD_INVITATION="$invitation" \
    LANEWAY_NODE_TEST_GO_FIXTURE_DIR="$probe_dir/go" LANEWAY_NODE_TEST_RUST_RUNTIME_DIR="$probe_dir/rust" \
    bash "$root/integration/rust-controller-node-netns.sh"
}

run_packet_gate go 1 0
run_packet_gate rust 1 0
run_packet_gate rust 0 1
