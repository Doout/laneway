#!/bin/sh
set -eu
case "$#:${2:-}" in
  1:|3:--version) ;;
  *) echo 'usage: laneway-update-connector laneway-connector-NAME [--version TAG]' >&2; exit 2 ;;
esac
updater=/usr/local/sbin/laneway-update-rs
[ -x "$updater" ] || { echo 'Install the signed Laneway Linux package first.' >&2; exit 1; }
exec "$updater" --connector "$@"
