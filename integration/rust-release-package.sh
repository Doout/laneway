#!/bin/sh
# Validate and execute the immutable archive members on the target Linux architecture.
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: sh integration/rust-release-package.sh ARCHIVE amd64|arm64 RELEASE_VERSION" >&2
  exit 2
fi
archive=$1
architecture=$2
expected_version=$3
case "$(uname -sm):$architecture" in
  "Linux x86_64:amd64"|"Linux aarch64:arm64") ;;
  *) echo "the runtime archive probe requires the matching native Linux architecture" >&2; exit 2 ;;
esac
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
probe_dir=$(mktemp -d)
trap 'find "$probe_dir" -depth -delete' EXIT HUP INT TERM
listing=$(tar -tzf "$archive")
for name in laneway-controller-rs laneway-healthcheck-rs laneway-relay-rs laneway-update-rs lanewayd-rs; do
  member="laneway/sbin/$name"
  count=$(printf '%s\n' "$listing" | grep -Fxc "$member" || true)
  test "$count" -eq 1 || { echo "expected a single $member in the Linux archive" >&2; exit 1; }
  tar -xOzf "$archive" "$member" > "$probe_dir/$name"
  chmod 0755 "$probe_dir/$name"
done
sh "$root/scripts/verify-rust-release-runtime.sh" "$probe_dir" "$architecture"
for name in laneway-controller-rs laneway-healthcheck-rs laneway-relay-rs laneway-update-rs lanewayd-rs; do
  for flag in --version -version; do
    observed=$("$probe_dir/$name" "$flag")
    if [ "$observed" != "$expected_version" ]; then
      echo "unexpected packaged build version for $name $flag: $observed" >&2
      exit 1
    fi
  done
done
if ! tar -tvzf "$archive" laneway/sbin/lanewayd |
  grep -F 'laneway/sbin/lanewayd -> ../bin/laneway' >/dev/null; then
  echo "the Rust preview must not change the default Go daemon link" >&2
  exit 1
fi
for member in examples/managed-updates-rust.toml systemd/laneway-rust-updater.service systemd/laneway-rust-updater.timer \
  deploy/compose/verify-rust-release.sh; do
  printf '%s\n' "$listing" | grep -Fx "laneway/$member" >/dev/null
done
printf 'Verified all five static Rust %s runtimes at version %s; default daemon link unchanged.\n' \
  "$architecture" "$expected_version"
