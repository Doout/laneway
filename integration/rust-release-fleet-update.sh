#!/usr/bin/env bash
# Prove the packaged updater and runtime on an isolated systemd runner.
set -euo pipefail

if [[ $# != 2 ]]; then
  echo 'usage: bash integration/rust-release-fleet-update.sh ARCHIVE ACTIVATION_FIXTURE_DIRECTORY' >&2
  exit 2
fi
marker=/run/.laneway-isolated-systemd-lab
if [[ $(id -u) != 0 || $(cat /proc/1/comm) != systemd ||
      ! -f $marker || -L $marker || $(stat -c '%u:%a' "$marker") != 0:600 ]]; then
  echo 'The fleet update gate requires root on a marked disposable systemd runner.' >&2
  exit 2
fi
archive=$1
fixture=$(realpath -e -- "$2")
for executable in prior-node activation-test; do
  [[ -f $fixture/$executable && ! -L $fixture/$executable && -x $fixture/$executable ]]
done
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d -t laneway-release-fleet.XXXXXX)
trap 'find "$work" -depth -delete' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Extract only the exact release binaries. The prior version and instrumented
# activation test are CI fixtures, never members of the release archive.
listing=$(tar -tzf "$archive")
for name in laneway-controller-rs laneway-update-rs lanewayd-rs; do
  member=laneway/sbin/$name
  [[ $(grep -Fxc "$member" <<<"$listing") == 1 ]]
  tar -xzOf "$archive" "$member" > "$work/$name"
  chmod 0755 "$work/$name"
done
[[ $("$work/lanewayd-rs" --version) != "$("$fixture/prior-node" --version)" ]]
CGO_ENABLED=0 go -C "$root/go" test -c -tags=rustinterop -o "$work/fleet-test" ./internal/controllerservice
LANEWAY_RUST_CONTROLLER="$work/laneway-controller-rs" LANEWAY_RUST_UPDATER="$work/laneway-update-rs" \
  LANEWAY_RUST_NODE="$fixture/prior-node" LANEWAY_LAB_NODE_CANDIDATE="$work/lanewayd-rs" \
  LANEWAY_RUST_SYSTEMD_ACTIVATION_TEST="$fixture/activation-test" \
  "$work/fleet-test" -test.run '^TestRustControllerFleetUpdates$/^managed-worker$' -test.v -test.timeout 6m |
  tee "$work/result"
grep -Fq 'systemd activated' "$work/result"
grep -Fq 'the same credential, and a fresh controller lease' "$work/result"
