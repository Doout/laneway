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
  cat > /state/connector/connector.toml <<EOF
mode = "node"
state_dir = "/var/lib/laneway"
socket_path = "/run/laneway/lanewayd.sock"
[tls]
certificate = "/var/lib/laneway/connector/node.crt"
private_key = "/var/lib/laneway/connector/node.key"
ca = "/var/lib/laneway/connector/ca.crt"
server_name = "lane.example.test"
[node]
name = "upgrade-fixture"
relay_address = "lane.example.test:4433"
relay_network_id = "11111111111111111111111111111111"
relay_service_id = "33333333333333333333333333333333"
[controller]
endpoint = "https://lane.example.test:8443"
quic_endpoint = "lane.example.test:8443"
server_name = "lane.example.test"
network_id = "11111111111111111111111111111111"
service_id = "22222222222222222222222222222222"
[tcp_fallback]
address = "lane.example.test:443"
[direct]
enabled = true
listen = "0.0.0.0:4434"
[routing]
output_interface = "eth0"
nat = true
[exit]
enabled = false
serve = true
failure_mode = "closed"
EOF
  for file in ca.crt node.crt node.key wireguard.key; do
    : > "/state/connector/$file"
  done
  chown -R 65532:65532 /state/connector
'

set +e
output=$(docker run --rm --cap-drop ALL --security-opt no-new-privileges:true \
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
case "$output" in
  *'/dev/net/tun'*|*'setpriv:'*)
    echo "Connector retained its privileged dataplane after upgrade" >&2
    exit 1
    ;;
esac
docker run --rm -v "$volume:/state" "$fixture_image" \
  test ! -e /state/connector/enrollment.token
docker run --rm -v "$volume:/state" "$fixture_image" sh -eu -c '
  grep -F "userspace = true" /state/connector/connector.toml >/dev/null
  ! grep -E "output_interface|serve = true|enabled = true" /state/connector/connector.toml >/dev/null
'

echo "Connector replacement migrates its persistent identity without re-enrollment or TUN"
