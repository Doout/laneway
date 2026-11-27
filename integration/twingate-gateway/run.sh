#!/bin/sh
# The privileged, disposable inner engine owns all test networks, devices and filters.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
engine=$(docker run --privileged -d --network bridge docker:28-dind dockerd --host=unix:///var/run/docker.sock)
trap 'docker rm -fv "$engine" >/dev/null' EXIT
for _ in $(seq 1 40); do
  docker exec "$engine" docker info >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$engine" apk add --no-cache python3 iproute2 nftables util-linux curl >/dev/null
docker exec "$engine" mkdir /test
docker cp "$here/." "$engine:/test"
docker cp "$here/../../deploy/twingate-gateway/worker.py" "$engine:/test/worker.py"
docker exec "$engine" docker build --quiet -t lw-fixture:local /test
docker exec "$engine" sh /test/control.sh
docker exec "$engine" python3 -B /test/check.py
