#!/bin/sh
set -eu

# Run the installed CLI and release helpers with real archive checks and Compose
# rendering. Network, signature authority and container operations are fixtures.
case "$#" in
  1|2|3) ;;
  *) echo "usage: $0 LINUX_RELEASE_ARCHIVE [LINUX_SOURCE_CLI [LINUX_SOURCE_COMPANION]]" >&2; exit 2 ;;
esac
archive=$1
source_cli=${2:-}
source_companion=${3:-}
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'find "$work" -depth -delete' EXIT HUP INT TERM
mkdir -p "$work/fixture" "$work/assets"
cp "$archive" "$work/assets/archive.tar.gz"
if [ -n "$source_cli" ]; then
  cp "$source_cli" "$work/laneway-source"
else
  tar -xOzf "$archive" laneway/bin/laneway > "$work/laneway-source"
  if tar -tzf "$archive" laneway/bin/laneway-compat >/dev/null 2>&1; then
    tar -xOzf "$archive" laneway/bin/laneway-compat > "$work/laneway-compat-source"
  fi
fi
if [ -n "$source_companion" ]; then
  cp "$source_companion" "$work/laneway-compat-source"
fi
cp "$repo_dir/integration/fixtures/control-plane-release/v0.2.54/"* "$work/fixture/"
cp "$repo_dir/deploy/compose/generated/config/"*.toml.example "$work/fixture/"
cp "$repo_dir/deploy/compose/laneway-control" "$work/fixture/"
cp "$repo_dir/integration/fixtures/control-plane-release/server-update/"* "$work/"
cat > "$work/Dockerfile" <<'DOCKER'
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends jq docker-compose && rm -rf /var/lib/apt/lists/*
DOCKER
# Build only the test runner. Every fixture runs with no network and no host
# mounts, including the Docker socket.
mkdir "$work/build"
mv "$work/Dockerfile" "$work/build/"
runner_image=$(docker build -q "$work/build")
for scenario in good bad-signature bad-preflight bad-public-https; do
  printf '\nServer update fixture: %s\n' "$scenario"
  tar --format=ustar -C "$work" -cf - . | docker run --rm -i --network none --cgroupns private \
    -e "LANEWAY_FIXTURE_SCENARIO=$scenario" "$runner_image" \
    sh -c 'mkdir /lab && tar -xf - -C /lab && exec sh /lab/run.sh'
done
