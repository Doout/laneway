#!/bin/sh
set -eu

image=${1:-lane-edge:ci}
volume=laneway-connector-upgrade-test-$$
fixture_image=alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
cleanup() { docker volume rm "$volume" >/dev/null 2>&1 || true; }
trap cleanup EXIT HUP INT TERM

network=11111111111111111111111111111111
node=44444444444444444444444444444444

docker volume create "$volume" >/dev/null
docker run --rm --network none --user 0:0 -v "$volume:/state" "$fixture_image" sh -eu -c '
  mkdir -p /state/connector /state/pki
  chown 65532:65532 /state/connector /state/pki
'

cli() {
  docker run --rm --network none --read-only --user 65532:65532 \
    --cap-drop ALL --security-opt no-new-privileges:true \
    -v "$volume:/var/lib/laneway" "$image" "$@"
}
cli pki init --out-dir /var/lib/laneway/pki >/dev/null
cli pki node --network-id "$network" --node-id "$node" \
  --ca-cert /var/lib/laneway/pki/ca.crt --ca-key /var/lib/laneway/pki/ca.key \
  --out-cert /var/lib/laneway/connector/node.crt --out-key /var/lib/laneway/connector/node.key >/dev/null
docker run --rm --network none --user 0:0 -v "$volume:/state" "$fixture_image" sh -eu -c '
  cp /state/pki/ca.crt /state/connector/ca.crt
  dd if=/dev/zero of=/state/connector/wireguard.key bs=32 count=1 status=none
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
  chown -R 65532:65532 /state/connector
  chmod 400 /state/connector/wireguard.key
'

identity() {
  docker run --rm --network none --read-only -v "$volume:/state:ro" "$fixture_image" \
    sh -eu -c 'cd /state/connector; sha256sum ca.crt node.crt node.key wireguard.key connector.toml'
}
before=$(identity)
cli connector configure | grep -Fx 'configuration is valid' >/dev/null
cli connector validate | grep -Fx 'configuration is valid' >/dev/null
[ "$(identity)" = "$before" ]
docker run --rm --network none -v "$volume:/state:ro" "$fixture_image" \
  test ! -e /state/connector/enrollment.token

echo "Rust Connector accepts the legacy identity without enrollment or changes to its persistent files"
