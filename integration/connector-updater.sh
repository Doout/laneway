#!/bin/sh
# Check the packaged entry point without operating on host containers.
# Transaction coverage is in the Rust fleet_update::connector tests.
set -eu
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
updater=$repo_dir/deploy/containers/update-connector.sh
sh -n "$updater"
grep -Fx 'updater=/usr/local/sbin/laneway-update-rs' "$updater" >/dev/null
# shellcheck disable=SC2016 # Assert the literal installed command.
grep -Fx 'exec "$updater" --connector "$@"' "$updater" >/dev/null
if output=$(sh "$updater" 2>&1); then
  echo 'Connector updater accepted a missing name' >&2
  exit 1
fi
printf '%s\n' "$output" | grep -F 'usage: laneway-update-connector' >/dev/null
echo 'Connector update delegates to the packaged Rust updater'
