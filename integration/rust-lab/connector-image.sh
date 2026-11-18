#!/usr/bin/env bash
# Check the actual image with no network capability or TUN device.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
lab_image="${LANEWAY_RUST_LAB_IMAGE:-laneway-rust-lab:local}"
config_volume="$(docker volume create --label laneway.test=rust-connector-image)"
connector=""
cleanup() {
  if [[ -n "$connector" ]]; then docker rm -f "$connector" >/dev/null; fi
  docker volume rm "$config_volume" >/dev/null
}
trap cleanup EXIT
docker run --rm --network none -v "$root:/src:ro" -v "$config_volume:/fixture" \
  -v laneway-rust-lab-gomod:/go/pkg/mod -v laneway-rust-lab-gobuild:/gobuild \
  -w /src/go "$lab_image" sh -ec '
    go build -o /tmp/laneway ./cmd/laneway
    /tmp/laneway pki init -out-dir /tmp/ca >/dev/null
    /tmp/laneway pki node -ca-cert /tmp/ca/ca.crt -ca-key /tmp/ca/ca.key \
      -network-id 000102030405060708090a0b0c0d0e0f -node-id 101112131415161718191a1b1c1d1e1f \
      -out-cert /fixture/node.crt -out-key /fixture/node.key
    cp /tmp/ca/ca.crt /fixture
    cp /src/deploy/examples/connector-rust.toml /fixture/connector.toml
    chown 65532:65532 /fixture/node.key
    chmod 0600 /fixture/node.key'
connector="$(docker run -d --network none --cap-drop ALL \
  -v "$config_volume:/etc/laneway:ro" laneway-rust-connector:migration-lab)"
for _ in {1..30}; do
  case "$(docker inspect -f '{{.State.Status}} {{.State.Health.Status}}' "$connector")" in
    'running healthy') break ;;
    running*) sleep 1 ;;
    *) docker logs "$connector"; exit 1 ;;
  esac
done
if [[ "$(docker inspect -f '{{.State.Health.Status}}' "$connector")" != healthy ]]; then
  docker logs "$connector"; exit 1
fi
docker exec "$connector" sh -ec '
  test "$(id -u)" = 65532
  test ! -e /dev/net/tun
  test ! -e /sys/class/net/userspace
  grep -q "^CapEff:[[:space:]]*0000000000000000" /proc/self/status'
docker stop --time 10 "$connector" >/dev/null
test "$(docker inspect -f '{{.State.ExitCode}}' "$connector")" = 0
echo "PASS: non-root Rust connector image became healthy and stopped without TUN or capabilities"
