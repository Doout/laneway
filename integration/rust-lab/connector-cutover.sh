#!/usr/bin/env bash
# Enroll and restart a Rust Connector in a loopback-only namespace.
set -euo pipefail

fixture() {
  umask 077
  work="$(mktemp -d)"
  # shellcheck disable=SC2154 # The trap assigns log in its for loop.
  trap 'result=$?; if [ "$result" -ne 0 ]; then
    for log in "$work/controller.log" "$work/relay.log"; do
      if [ -f "$log" ]; then tail -n 20 "$log" >&2; fi
    done
  fi
  if [ -n "${controller_pid:-}" ]; then kill "$controller_pid" 2>/dev/null || true; fi
  if [ -n "${relay_pid:-}" ]; then kill "$relay_pid" 2>/dev/null || true; fi' EXIT
  trap 'echo "connector fixture failed at line $LINENO" >&2' ERR
  cd /src/go
  go build -o "$work/laneway" ./cmd/laneway
  go build -o "$work/controller" ./integration/rustnodecontroller
  go build -o "$work/relay" ./cmd/laneway-relay

  cli="$work/laneway"
  network=71000000000000000000000000000001
  controller=71000000000000000000000000000002
  relay=71000000000000000000000000000003
  relay_endpoint=localhost:4433
  if [ "${1:-relay-quic}" = tcp-fallback ]; then
    # Advertise an unused UDP port, keeping the real TCP listener reachable.
    # All listeners and advertised sockets are in this isolated namespace.
    relay_endpoint=localhost:4434
  fi
  endpoint=https://localhost:8443
  printf '%s\n' rust-connector-lab-admin-token > "$work/admin.token"
  "$cli" pki init -out-dir "$work/pki" >/dev/null
  for role in controller relay; do
    if [ "$role" = controller ]; then id="$controller"; else id="$relay"; fi
    "$cli" pki "$role" -ca-cert "$work/pki/ca.crt" -ca-key "$work/pki/ca.key" \
      -network-id "$network" -service-id "$id" -dns localhost -ip 127.0.0.1,::1 \
      -out-cert "$work/pki/$role.crt" -out-key "$work/pki/$role.key" >/dev/null
  done

  "$work/controller" -listen '[::]:8443' -quic-listen '[::]:8443' \
    -database "$work/controller.db" -ca-cert "$work/pki/ca.crt" -ca-key "$work/pki/ca.key" \
    -controller-cert "$work/pki/controller.crt" -controller-key "$work/pki/controller.key" \
    -admin-token-file "$work/admin.token" -snapshot-validity 30s >"$work/controller.log" 2>&1 &
  controller_pid=$!
  for _ in {1..100}; do
    grep -q 'controller listening' "$work/controller.log" && break
    kill -0 "$controller_pid" || { cat "$work/controller.log"; exit 1; }
    sleep 0.1
  done
  grep -q 'controller listening' "$work/controller.log"
  admin=(--controller "$endpoint" --ca "$work/pki/ca.crt"
    --controller-network-id "$network" --controller-service-id "$controller"
    --admin-token-file "$work/admin.token")
  "$cli" controller network create --network-id "$network" --name connector-lab \
    --ipv4-pool 100.115.2.0/24 "${admin[@]}" >/dev/null
  "$cli" controller relay register --network-id "$network" --service-id "$relay" \
    --name local-relay --endpoint "$relay_endpoint" "${admin[@]}" >/dev/null

  cat > "$work/relay.toml" <<EOF
mode = "relay"
state_dir = "$work/relay-state"
[tls]
certificate = "$work/pki/relay.crt"
private_key = "$work/pki/relay.key"
ca = "$work/pki/ca.crt"
[relay]
listen = "[::]:4433"
[tcp_fallback]
listen = "[::]:443"
[controller]
endpoint = "$endpoint"
quic_endpoint = "localhost:8443"
server_name = "localhost"
network_id = "$network"
service_id = "$controller"
poll_interval = "100ms"
EOF
  "$work/relay" -config "$work/relay.toml" >"$work/relay.log" 2>&1 &
  relay_pid=$!
  for _ in {1..100}; do
    grep -q 'QUIC=.*TCP-fallback=' "$work/relay.log" && break
    kill -0 "$relay_pid" || { cat "$work/relay.log"; exit 1; }
    sleep 0.1
  done
  grep -q 'QUIC=.*TCP-fallback=' "$work/relay.log"

  name=test-connector
  token="$("$cli" controller enrollment-token issue --network-id "$network" \
    --label "$name" --expires-in 10m "${admin[@]}" |
    sed -n 's/^[[:space:]]*"enrollment_token": "\([^"]*\)"[,]*$/\1/p')"
  [ -n "$token" ]
  ca="$(base64 < "$work/pki/ca.crt" | tr -d '\n')"
  {
    printf 'st1.'
    printf '%s\n' "$name" "$token" "$endpoint" localhost:8443 localhost \
      "$network" "$controller" "$relay_endpoint" "$relay" "$ca" | base64 | tr -d '\n'
    printf '\n'
  } > /state/setup.token
  chown 65532:65532 /state /state/setup.token
  echo 'connector fixture ready'
  wait "$controller_pid" "$relay_pid"
}

if [ "${1:-}" = --fixture ]; then
  set -E
  fixture "${2:-relay-quic}"
  exit
fi

root="$(cd "$(dirname "$0")/../.." && pwd)"
lab_image="${LANEWAY_RUST_LAB_IMAGE:-laneway-rust-lab:local}"
if [ "${1:-}" = --prime-cache ]; then
  # Dependency downloads run before the offline test.
  docker run --rm --mount "type=bind,src=$root,dst=/src,readonly" \
    --mount type=volume,src=laneway-rust-lab-gomod,dst=/go/pkg/mod \
    -w /src/go "$lab_image" go mod download
  exit
fi
if [[ ${1:-} != --fresh || $# -lt 2 || $# -gt 3 ]]; then
  printf 'usage: %s --fresh RUST_CONNECTOR_IMAGE [relay-quic|tcp-fallback]\n' "$0" >&2
  exit 2
fi
rust_image=$2
carrier=${3:-relay-quic}
case "$carrier" in relay-quic|tcp-fallback) ;; *) echo "invalid lab carrier" >&2; exit 1 ;; esac
state="$(docker volume create --label laneway.test=connector-enrollment)"
declare -a containers=()
stage="starting the isolated controller and relay"
cleanup() {
  local result=$?
  if [ "$result" -ne 0 ]; then
    echo "Connector test failed while $stage" >&2
    for container in "${containers[@]}"; do
      docker logs --tail 20 "$container" >&2 2>/dev/null || true
    done
  fi
  for container in "${containers[@]}"; do
    docker rm -f "$container" >/dev/null 2>&1 || true
  done
  docker volume rm "$state" >/dev/null
}
trap cleanup EXIT

# The fixture runs inside a container with a differently owned, read-only checkout.
lab="$(docker run -d --network none -e GOFLAGS=-buildvcs=false -v "$root:/src:ro" \
  -v "$state:/state" \
  -v laneway-rust-lab-gomod:/go/pkg/mod -v laneway-rust-lab-gobuild:/gobuild \
  "$lab_image" bash /src/integration/rust-lab/connector-cutover.sh --fixture "$carrier")"
containers+=("$lab")
for _ in {1..180}; do
  docker logs "$lab" 2>&1 | grep -q 'connector fixture ready' && break
  [ "$(docker inspect -f '{{.State.Running}}' "$lab")" = true ] || { docker logs "$lab"; exit 1; }
  sleep 1
done
docker logs "$lab" 2>&1 | grep -q 'connector fixture ready'

start() {
  active="$(docker run -d --pull never --network "container:$lab" --user 65532:65532 --read-only \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=0700,uid=65532,gid=65532 \
    --tmpfs /run/laneway:rw,noexec,nosuid,nodev,mode=0700,uid=65532,gid=65532 \
    --health-interval 1s --health-start-period 1s \
    -v "$state:/var/lib/laneway" "$@" "$rust_image")"
  containers=("$active" "${containers[@]}")
  for _ in {1..25}; do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$active")" != healthy ] || return 0
    [ "$(docker inspect -f '{{.State.Running}}' "$active")" = true ] || break
    sleep 1
  done
  docker logs "$active" >&2
  return 1
}

identity_bytes() {
  docker exec "$lab" sh -ec 'cd /state/connector; sha256sum ca.crt node.crt node.key wireguard.key connector.toml'
}

read_node() {
  local status version
  for _ in {1..50}; do
    status="$(docker exec "$active" /usr/local/bin/laneway status --socket /run/laneway/lanewayd.sock --json)"
    printf '%s\n' "$status" | grep -Eq '"selected_path":[[:space:]]*"'"$carrier"'"' && break
    sleep 1
  done
  printf '%s\n' "$status" | grep -Eq '"selected_path":[[:space:]]*"'"$carrier"'"' || {
    docker logs "$active" >&2
    return 1
  }
  printf '%s\n' "$status" | grep -Eq '"interface":[[:space:]]*"userspace"' || {
    echo "Connector did not start in userspace mode" >&2
    return 1
  }
  version="$(printf '%s\n' "$status" |
    sed -n 's/^[[:space:]]*"product_version": "\([^"]*\)"[,]*$/\1/p')"
  [ "$version" = "$rust_version" ] || { echo "running Connector did not report its image build version" >&2; return 1; }
  printf '%s\n' "$status" |
    sed -n 's/^[[:space:]]*"node_id": "\([0-9a-f]\{32\}\)"[,]*$/\1/p'
}

check_rust_process() {
  docker top "$active" -eo pid,comm | awk 'NR > 1 { if ($2 != "lanewayd-rs") exit 1; seen++ } END { if (seen != 1) exit 1 }'
}

rust_version="$(docker run --rm --pull never --network none "$rust_image" version)"
stage="enrolling a new Rust Connector"
start -e SETUP_TOKEN_FILE=/var/lib/laneway/setup.token
node_id="$(read_node)"
[ -n "$node_id" ]
check_rust_process
identity="$(identity_bytes)"
docker exec "$lab" rm -- /state/setup.token
stage="restarting the Rust Connector with only its saved identity"
docker stop --time 5 "$active" >/dev/null
start
[ "$(read_node)" = "$node_id" ]
check_rust_process
[ "$(identity_bytes)" = "$identity" ]
echo "PASS: fresh Rust Connector enrollment and restart over $carrier"
