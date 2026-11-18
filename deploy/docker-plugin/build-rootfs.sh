#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname "$0")/../.." && pwd)
version=${VERSION:-dev}
output=${1:-"$repo_root/dist/docker-plugin"}
runtime=${LANEWAY_DOCKER_PLUGIN_RUNTIME:-rust}
case "$runtime" in
  go) dockerfile=Dockerfile; context="$repo_root/go" ;;
  rust) dockerfile=Dockerfile.rust; context="$repo_root" ;;
  *) echo "LANEWAY_DOCKER_PLUGIN_RUNTIME must be go or rust" >&2; exit 2 ;;
esac
image="laneway-docker-plugin-rootfs:$version-$runtime"
temporary=$(mktemp -d)
trap 'find "$temporary" -depth -delete 2>/dev/null || true' EXIT HUP INT TERM

docker build --file "$repo_root/deploy/docker-plugin/$dockerfile" --build-arg "VERSION=$version" --tag "$image" "$context"
container=$(docker create "$image" /usr/bin/laneway-docker-plugin)
trap 'docker rm -f "$container" >/dev/null 2>&1 || true; find "$temporary" -depth -delete 2>/dev/null || true' EXIT HUP INT TERM
docker export "$container" | tar -x -C "$temporary"
docker rm "$container" >/dev/null
container=

test -x "$temporary/usr/bin/laneway-docker-plugin"
install -d -m 0755 "$output/rootfs"
cp -a "$temporary/." "$output/rootfs/"
install -m 0644 "$repo_root/deploy/docker-plugin/config.json" "$output/config.json"
