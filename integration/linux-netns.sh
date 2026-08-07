#!/usr/bin/env bash
set -euo pipefail

if [[ "${LANEWAY_RUN_PRIVILEGED:-0}" != "1" ]]; then
  echo "SKIP: set LANEWAY_RUN_PRIVILEGED=1 to run disposable Linux network-namespace tests"
  exit 0
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "ERROR: run as root (or with sudo preserving LANEWAY_RUN_PRIVILEGED)" >&2
  exit 1
fi

for command in go ip nft sysctl; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "ERROR: required command is missing: ${command}" >&2
    exit 1
  fi
done
if [[ ! -c /dev/net/tun ]]; then
  echo "ERROR: /dev/net/tun is unavailable; load the tun module or expose the device" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d -t laneway-netns.XXXXXX)"
namespace="laneway-it-$$"

cleanup() {
  ip netns delete "${namespace}" >/dev/null 2>&1 || true
  rm -rf -- "${work_dir}"
}
trap cleanup EXIT INT TERM

(
  cd "${repo_root}/go"
  go test -c -o "${work_dir}/linux.test" ./integration/linux
  go test -c -o "${work_dir}/relay.test" ./integration/relay
  go build -o "${work_dir}/laneway" ./cmd/laneway
  go build -o "${work_dir}/lanewayd" ./cmd/lanewayd
  go build -o "${work_dir}/laneway-relay" ./cmd/laneway-relay
  go build -o "${work_dir}/laneway-controller" ./cmd/laneway-controller
  go build -o "${work_dir}/netprobe" ./integration/netprobe
)

ip netns add "${namespace}"
ip -n "${namespace}" link set lo up

echo "==> kernel TUN, overlay routes, subnet forwarding, exit rollback, and crash ownership"
ip netns exec "${namespace}" env \
  LANEWAY_PRIVILEGED_INTEGRATION=1 \
  "${work_dir}/linux.test" -test.v

echo "==> authenticated TCP fallback with all UDP output blocked"
ip netns exec "${namespace}" nft add table inet laneway_udp_block
ip netns exec "${namespace}" nft add chain inet laneway_udp_block output \
  '{ type filter hook output priority -10; policy accept; }'
ip netns exec "${namespace}" nft add rule inet laneway_udp_block output meta l4proto udp drop
ip netns exec "${namespace}" "${work_dir}/relay.test" \
  -test.v -test.run '^TestNodesFallBackToTCPWhenQUICUnavailable$'
ip netns exec "${namespace}" nft delete table inet laneway_udp_block

echo "==> full-stack kernel application flows"
LANEWAY_INTEGRATION_WORK_DIR="${work_dir}" "${repo_root}/integration/fullstack-netns.sh"

echo "PASS: privileged namespace integration"
