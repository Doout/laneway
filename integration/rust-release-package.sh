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
rust_commands='laneway-controller-rs laneway-healthcheck-rs laneway-relay-rs laneway-update-rs lanewayd-rs'
for name in $rust_commands; do
  member="laneway/sbin/$name"
  count=$(printf '%s\n' "$listing" | grep -Fxc "$member" || true)
  test "$count" -eq 1 || { echo "expected a single $member in the Linux archive" >&2; exit 1; }
  tar -xOzf "$archive" "$member" > "$probe_dir/$name"
  chmod 0755 "$probe_dir/$name"
done
sh "$root/scripts/verify-rust-release-runtime.sh" "$probe_dir" "$architecture"
for name in $rust_commands; do
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
  systemd/lanewayd-rs.service systemd/laneway-relay-rs.service \
  deploy/compose/verify-rust-release.sh; do
  printf '%s\n' "$listing" | grep -Fx "laneway/$member" >/dev/null
done
# Exercise the shipped installer in an isolated staging root; no host user,
# configuration, daemon, or updater is touched.
tar -xzf "$archive" -C "$probe_dir"
package=$probe_dir/laneway
control_root=$probe_dir/control-tool-install
DESTDIR="$control_root" PREFIX=/usr/local sh "$package/install.sh" --control-tools >/dev/null
cmp "$package/bin/laneway" "$control_root/usr/local/bin/laneway"
test -x "$control_root/usr/local/share/laneway/deploy/compose/install-control-plane.sh"
test -f "$control_root/usr/local/share/laneway/deploy/compose/compose.rust.yaml"
test ! -e "$control_root/usr/local/sbin"
test ! -e "$control_root/usr/local/lib/systemd"
test ! -e "$control_root/etc/laneway"

destination=$probe_dir/installed
DESTDIR="$destination" PREFIX=/usr/local sh "$package/install.sh" >/dev/null
installed=$destination/usr/local
test "$(readlink "$installed/sbin/lanewayd")" = ../bin/laneway
test ! -e "$installed/sbin/lanewayd-rs"
test ! -e "$installed/lib/systemd/system/lanewayd-rs.service"

DESTDIR="$destination" PREFIX=/usr/local sh "$package/install.sh" --rust-preview >/dev/null
test "$(readlink "$installed/sbin/lanewayd")" = ../bin/laneway
for name in $rust_commands; do
  cmp "$probe_dir/$name" "$installed/sbin/$name"
  test "$("$installed/sbin/$name" --version)" = "$expected_version"
done
units=$installed/lib/systemd/system
grep -Fx 'ExecStart=/usr/local/sbin/lanewayd-rs --config /etc/laneway/node-rust.toml' "$units/lanewayd-rs.service"
grep -Fx 'ExecStart=/usr/local/sbin/laneway-relay-rs --config /etc/laneway/relay-rust.toml' "$units/laneway-relay-rs.service"
test -f "$units/laneway-rust-updater.timer"
test -z "$(find "$units" -type l -print -quit)"
test ! -e "$destination/etc/laneway"

mv "$package/sbin/lanewayd-rs" "$probe_dir/missing-rust-node"
if DESTDIR="$probe_dir/rejected" PREFIX=/usr/local sh "$package/install.sh" --rust-preview >"$probe_dir/rejected.log" 2>&1; then
  echo 'partial Rust preview unexpectedly installed' >&2
  exit 1
fi
grep -F 'requires a packaged lanewayd-rs' "$probe_dir/rejected.log" >/dev/null
test ! -e "$probe_dir/rejected"
printf 'Verified five static Rust %s runtimes at %s, preview installation, and daemon-free control-plane tools.\n' \
  "$architecture" "$expected_version"
