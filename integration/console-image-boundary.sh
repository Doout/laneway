#!/bin/sh
set -eu

if [ "$#" -lt 2 ]; then
  echo "usage: $0 CONTROLLER_IMAGE NON_CONSOLE_IMAGE..." >&2
  exit 2
fi

controller_image=$1
shift
boundary_tmp=$(mktemp -d "${TMPDIR:-/tmp}/laneway-console-boundary.XXXXXX")
boundary_containers=

cleanup() {
  for boundary_container in $boundary_containers; do
    docker rm -f "$boundary_container" >/dev/null 2>&1 || true
  done
  rm -rf -- "$boundary_tmp"
}
trap cleanup EXIT HUP INT TERM

image_manifest() {
  boundary_image=$1
  boundary_manifest=$2
  boundary_container=$(docker create "$boundary_image")
  boundary_containers="$boundary_containers $boundary_container"
  docker export "$boundary_container" | tar -tf - >"$boundary_manifest"
}

controller_manifest=$boundary_tmp/controller.manifest
image_manifest "$controller_image" "$controller_manifest"
if ! grep -Fx 'usr/share/laneway-console/index.html' "$controller_manifest" >/dev/null; then
  echo "$controller_image does not contain the administrator console index" >&2
  exit 1
fi
if grep -E '^usr/share/laneway-console/.*\.map$' "$controller_manifest" >/dev/null; then
  echo "$controller_image unexpectedly contains console source maps" >&2
  exit 1
fi

boundary_index=0
for non_console_image in "$@"; do
  boundary_index=$((boundary_index + 1))
  non_console_manifest=$boundary_tmp/non-console-$boundary_index.manifest
  image_manifest "$non_console_image" "$non_console_manifest"
  if grep -E '^usr/share/laneway-console(/|$)' "$non_console_manifest" >/dev/null; then
    echo "$non_console_image unexpectedly contains administrator console assets" >&2
    exit 1
  fi
done

echo "Console assets are present only in $controller_image"
