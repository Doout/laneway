#!/usr/bin/env bash
# Smoke-test the actual packaging, file permissions, TUN and Docker healthcheck.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
config_volume="$(docker volume create --label laneway.test=rust-node-image)"
node=""
cleanup() {
  if [[ -n "$node" ]]; then docker rm -f "$node" >/dev/null; fi
  docker volume rm "$config_volume" >/dev/null
}
trap cleanup EXIT
docker run --rm --network none -v "$root:/src:ro" -v "$config_volume:/fixture" \
  -v laneway-rust-lab-gomod:/go/pkg/mod -v laneway-rust-lab-gobuild:/gobuild \
  -w /src/go laneway-rust-lab:local sh -ec '
    go build -o /tmp/laneway ./cmd/laneway
    /tmp/laneway pki init -out-dir /tmp/test-ca >/dev/null
    /tmp/laneway pki node -ca-cert /tmp/test-ca/ca.crt -ca-key /tmp/test-ca/ca.key \
      -network-id 000102030405060708090a0b0c0d0e0f -node-id 101112131415161718191a1b1c1d1e1f \
      -out-cert /fixture/node.crt -out-key /fixture/node.key
    cp /tmp/test-ca/ca.crt /fixture
    cp /src/deploy/examples/node-rust.toml /fixture/node.toml
    chown 65532:65532 /fixture/node.key
    chmod 0600 /fixture/node.key'
node="$(docker run -d --network none --cap-drop ALL --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$config_volume:/etc/laneway:ro" laneway-rust-node:migration-lab)"
for _ in {1..30}; do
  case "$(docker inspect -f '{{.State.Status}} {{.State.Health.Status}}' "$node")" in
    'running healthy') break ;;
    running*) sleep 1 ;;
    *) docker logs "$node"; exit 1 ;;
  esac
done
if [[ "$(docker inspect -f '{{.State.Health.Status}}' "$node")" != healthy ]]; then
  docker logs "$node"; exit 1
fi
docker exec "$node" sh -ec 'test "$(id -u)" = 65532; ip -4 addr show dev lane0 | grep -F "100.96.0.1/32"'
docker stop --time 10 "$node" >/dev/null
test "$(docker inspect -f '{{.State.ExitCode}}' "$node")" = 0
echo "PASS: non-root Rust node image created TUN, served the status check, and stopped cleanly"
