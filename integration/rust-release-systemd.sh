#!/usr/bin/env bash
# Test the exact Rust Linux archive against Rust and source-built Go peers.
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
packet_jobs=()
cleanup() {
  local pid
  for pid in "${packet_jobs[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
  for pid in "${packet_jobs[@]}"; do wait "$pid" 2>/dev/null || true; done
  find "$probe_dir" -depth -delete
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$probe_dir/go" "$probe_dir/rust"
# Use the archive for the native CLI and daemon. Source-build the legacy
# clients for the independent mixed-runtime interoperability cases.
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
for name in laneway-controller-rs laneway-relay-rs lanewayd-rs; do
  tar -xzOf "$archive" "laneway/sbin/$name" > "$probe_dir/rust/$name"
done
for fixture in laneway laneway-relay netprobe rustnodecontroller; do
  if [[ -n ${LANEWAY_NODE_TEST_GO_FIXTURE_DIR:-} ]]; then
    install -m 0755 "$LANEWAY_NODE_TEST_GO_FIXTURE_DIR/$fixture" "$probe_dir/go/$fixture"
  else
    case "$fixture" in laneway|laneway-relay) pkg="./cmd/$fixture" ;; *) pkg="./integration/$fixture" ;; esac
    (cd "$root/go" && CGO_ENABLED=0 go build -o "$probe_dir/go/$fixture" "$pkg")
  fi
done
cp "$probe_dir/go/laneway" "$probe_dir/go/lanewayd"
chmod 0755 "$probe_dir/go/"* "$probe_dir/rust/"*

run_packet_gate() {
  local controller="$1" drain="$2" invitation="$3"
  exec env LANEWAY_RUN_PRIVILEGED=1 LANEWAY_NODE_TEST_CONTROLLER="$controller" \
    LANEWAY_NODE_TEST_WIREGUARD=1 LANEWAY_NODE_WIREGUARD_NATIVE=1 \
    LANEWAY_NODE_WIREGUARD_CREDENTIALS=0 LANEWAY_NODE_WIREGUARD_DRAIN="$drain" \
    LANEWAY_NODE_WIREGUARD_SYSTEMD=1 LANEWAY_NODE_WIREGUARD_INVITATION="$invitation" \
    LANEWAY_NODE_TEST_GO_FIXTURE_DIR="$probe_dir/go" LANEWAY_NODE_TEST_RUST_RUNTIME_DIR="$probe_dir/rust" \
    bash "$root/integration/rust-controller-node-netns.sh"
}

# Each drain test owns its own network namespaces and transient service. Keep
# the installer and packaged services sequential because they check host state.
for controller in go rust; do
  run_packet_gate "$controller" 1 0 >"$probe_dir/drain-$controller.log" 2>&1 &
  packet_jobs+=("$!")
done
result=0
for index in "${!packet_jobs[@]}"; do
  wait "${packet_jobs[$index]}" || result=$?
  unset 'packet_jobs[index]'
done
for controller in go rust; do
  printf '==> %s controller drain gate\n' "$controller"
  cat "$probe_dir/drain-$controller.log"
done
((result == 0)) || exit "$result"
(run_packet_gate rust 0 1)

# Run the packaged ordinary-node and relay units, not the transient WireGuard
# exit unit. Only the lab network and log location will be overridden.
tar -xzf "$archive" -C "$probe_dir"
DESTDIR="$probe_dir/installed" PREFIX=/usr/local sh "$probe_dir/laneway/install.sh"
run_installed_gate() {
  env LANEWAY_RUN_PRIVILEGED=1 LANEWAY_NODE_TEST_CONTROLLER="$1" LANEWAY_NODE_TEST_WIREGUARD=0 \
    LANEWAY_NODE_WIREGUARD_DRAIN=0 LANEWAY_NODE_WIREGUARD_CREDENTIALS=0 \
    LANEWAY_NODE_WIREGUARD_SYSTEMD=0 LANEWAY_NODE_WIREGUARD_INVITATION=0 \
    LANEWAY_NODE_TEST_PACKAGED_INSTALL="$probe_dir/installed" LANEWAY_NODE_TEST_PACKAGED_RELAY="$2" \
    LANEWAY_NODE_TEST_MANAGED_INVITATION="${3:-0}" \
    LANEWAY_NODE_TEST_GO_FIXTURE_DIR="$probe_dir/go" LANEWAY_NODE_TEST_RUST_RUNTIME_DIR="$probe_dir/rust" \
    bash "$root/integration/rust-controller-node-netns.sh"
}
run_installed_gate go 0
run_installed_gate rust 1
run_installed_gate rust 1 1
