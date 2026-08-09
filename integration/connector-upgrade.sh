#!/bin/sh
set -eu

image=${1:-laneway-connector:ci}
volume=laneway-connector-upgrade-test-$$
fixture_image=alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
cleanup() { docker volume rm "$volume" >/dev/null 2>&1 || true; }
trap cleanup EXIT HUP INT TERM

docker volume create "$volume" >/dev/null
docker run --rm --user 0:0 -v "$volume:/state" "$fixture_image" sh -eu -c '
  mkdir -p /state/connector
  printf "intentionally invalid test config\n" > /state/connector/connector.toml
  for file in ca.crt node.crt node.key wireguard.key; do
    : > "/state/connector/$file"
  done
  chown -R 65532:65532 /state/connector
'

set +e
output=$(docker run --rm --cap-add NET_ADMIN --security-opt no-new-privileges:true \
  -v "$volume:/var/lib/laneway" "$image" 2>&1)
status=$?
set -e
[ "$status" -ne 0 ] || { echo "fixture Connector unexpectedly started" >&2; exit 1; }
case "$output" in
  *'required environment variable'*)
    echo "Connector requested enrollment variables despite its persistent identity" >&2
    exit 1
    ;;
esac
docker run --rm -v "$volume:/state" "$fixture_image" \
  test ! -e /state/connector/enrollment.token

echo "Connector replacement reuses its persistent identity without enrollment"
