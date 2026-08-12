#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname "$0")/../.." && pwd)
version=${VERSION:-dev}
output=${1:-"$repo_root/dist/docker-plugin"}
image="laneway-docker-plugin-rootfs:$version"
temporary=$(mktemp -d)
trap 'find "$temporary" -depth -delete 2>/dev/null || true' EXIT HUP INT TERM

docker build --file "$repo_root/deploy/docker-plugin/Dockerfile" --build-arg "VERSION=$version" --tag "$image" "$repo_root/go"
container=$(docker create "$image" /usr/bin/laneway-docker-plugin)
trap 'docker rm -f "$container" >/dev/null 2>&1 || true; find "$temporary" -depth -delete 2>/dev/null || true' EXIT HUP INT TERM
docker export "$container" | tar -x -C "$temporary"
docker rm "$container" >/dev/null
container=

test -x "$temporary/usr/bin/laneway-docker-plugin"
install -d -m 0755 "$output/rootfs"
cp -a "$temporary/." "$output/rootfs/"
install -m 0644 "$repo_root/deploy/docker-plugin/config.json" "$output/config.json"
