#!/bin/sh
# Smoke-test the packaged CLI's userspace dispatch and embedded helper as an ordinary user.
set -eu

if [ "$#" -ne 2 ]; then
  echo 'usage: sh integration/rust-release-rootless.sh CLIENT DAEMON | --linux-archive ARCHIVE' >&2
  exit 2
fi
if [ "$(id -u)" -eq 0 ]; then
  echo 'the rootless release probe requires an ordinary user' >&2
  exit 2
fi

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
probe_dir=$(mktemp -d)
trap 'find "$probe_dir" -depth -delete' EXIT
trap 'exit 1' HUP INT TERM
linux_archive=false
if [ "$1" = --linux-archive ]; then
  linux_archive=true
  tar -xzf "$2" -C "$probe_dir"
  DESTDIR="$probe_dir/install" PREFIX=/usr/local sh "$probe_dir/laneway/install.sh"
  installed="$probe_dir/install/usr/local"
  client="$installed/bin/laneway"
  daemon="$installed/sbin/lanewayd-rs"
else
  client=$1
  daemon=$2
fi

for path in "$client" "$daemon"; do
  [ -f "$path" ] && [ ! -L "$path" ] && [ -x "$path" ] ||
    { echo "invalid packaged executable: $path" >&2; exit 1; }
done
client_version=$("$client" version)
daemon_version=$("$daemon" --version)
[ "$client_version" = "$daemon_version" ] ||
  { echo "packaged CLI and daemon versions differ: $client_version / $daemon_version" >&2; exit 1; }

# The packaged CLI must take the Rust discovery path before any network request.
if "$client" bootstrap inspect http://localhost >"$probe_dir/bootstrap-reject" 2>&1; then
  echo 'packaged bootstrap accepted an insecure origin' >&2
  exit 1
fi
grep -F -- 'expected authenticated HTTPS' "$probe_dir/bootstrap-reject"

# The current release embeds the helper in lanewayd-rs. This probe checks that
# the production runtime includes it and rejects an unprivileged invocation
# before touching the control socket or any host networking state.
"$daemon" _network-helper --help >"$probe_dir/helper-help" 2>&1
grep -F -- '-control-fd' "$probe_dir/helper-help"
if "$daemon" _network-helper --control-fd=2147483647 >"$probe_dir/helper-reject" 2>&1; then
  echo 'packaged helper accepted an unprivileged invocation' >&2
  exit 1
fi
grep -F -- 'network helper requires root' "$probe_dir/helper-reject"

state="$probe_dir/state"
"$client" configure --help >"$probe_dir/configure-help" 2>&1
grep -F -- '--state-dir' "$probe_dir/configure-help"
"$client" start --help >"$probe_dir/start-help" 2>&1
grep -F -- '--proxy-only' "$probe_dir/start-help"
printf '%s\n' 'temporary-release-probe-password' |
  "$client" credential add release-probe --password-stdin --state-dir "$state"
[ "$("$client" credential list --state-dir "$state")" = release-probe ]
"$client" credential remove release-probe --state-dir "$state"
[ -z "$("$client" credential list --state-dir "$state")" ]
printf 'Verified packaged rootless CLI and helper at version %s.\n' "$client_version"

if [ "$linux_archive" = true ]; then
  [ "$("$installed/bin/lane" -version)" = "$client_version" ]
  [ "$("$client" node run -version)" = "$client_version" ]
  python3 "$root/integration/rootless.py" --bin-dir "$installed"
fi
