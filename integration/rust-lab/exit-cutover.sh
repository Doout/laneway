#!/usr/bin/env bash
# Run the two packaged Exit Nodes against the same disposable identity and LAN.
set -euo pipefail

fixture() {
  export PATH="/opt/rootless-lab:$PATH"
  work=/tmp/exit-fixture
  mkdir -m 0700 "$work"
  trap 'for pid in $(jobs -pr); do kill "$pid" 2>/dev/null || true; done
    ip netns delete exit-client 2>/dev/null || true
    ip netns delete exit-lan 2>/dev/null || true' EXIT
  cd /src/go
  go build -o "$work/laneway" ./cmd/laneway
  go build -o "$work/controller" ./integration/rustnodecontroller
  go build -o "$work/relay" ./cmd/laneway-relay
  go build -o "$work/netprobe" ./integration/netprobe

  ip netns add exit-client
  ip netns add exit-lan
  for ns in exit-client exit-lan; do ip -n "$ns" link set lo up; done
  ip link add ctl0 type veth peer name client0 netns exit-client
  ip link add wan0 type veth peer name lan0 netns exit-lan
  ip addr add 10.229.0.1/24 dev ctl0
  ip addr add 192.168.77.1/24 dev wan0
  ip link set ctl0 up
  ip link set wan0 up
  ip -n exit-client addr add 10.229.0.2/24 dev client0
  ip -n exit-client link set client0 up
  ip -n exit-lan addr add 192.168.77.2/24 dev lan0
  ip -n exit-lan link set lan0 up

  cli="$work/laneway"
  network=71000000000000000000000000000001
  controller=71000000000000000000000000000002
  relay=71000000000000000000000000000003
  controller_name=controller.migration.test
  relay_name=relay.migration.test
  printf '%s\n' exit-cutover-disposable-admin-token >"$work/admin.token"
  chmod 0600 "$work/admin.token"
  "$cli" pki init -out-dir "$work/pki" >/dev/null
  "$cli" pki controller -ca-cert "$work/pki/ca.crt" -ca-key "$work/pki/ca.key" \
    -network-id "$network" -service-id "$controller" -dns "$controller_name" \
    -out-cert "$work/pki/controller.crt" -out-key "$work/pki/controller.key" >/dev/null
  "$cli" pki relay -ca-cert "$work/pki/ca.crt" -ca-key "$work/pki/ca.key" \
    -network-id "$network" -service-id "$relay" -dns "$relay_name" \
    -out-cert "$work/pki/relay.crt" -out-key "$work/pki/relay.key" >/dev/null
  "$work/controller" -listen 0.0.0.0:8443 -quic-listen 0.0.0.0:8443 \
    -database "$work/controller.db" -ca-cert "$work/pki/ca.crt" -ca-key "$work/pki/ca.key" \
    -controller-cert "$work/pki/controller.crt" -controller-key "$work/pki/controller.key" \
    -admin-token-file "$work/admin.token" -snapshot-validity 5s >"$work/controller.log" 2>&1 &
  local control_pid=$!
  wait_fixture_log "$control_pid" "$work/controller.log" "test controller listening"
  admin=(--controller https://10.229.0.1:8443 --ca "$work/pki/ca.crt" --server-name "$controller_name"
    --controller-network-id "$network" --controller-service-id "$controller" --admin-token-file "$work/admin.token")
  "$cli" controller network create --network-id "$network" --name exit-cutover \
    --ipv4-pool 100.115.9.0/24 "${admin[@]}" >/dev/null
  "$cli" controller relay register --network-id "$network" --service-id "$relay" \
    --name lab-relay --endpoint relay:4433 "${admin[@]}" >/dev/null
  "$cli" controller acl add --network-id "$network" --priority 100 --action accept \
    --selector '{"ip_protocol":"IP_PROTOCOL_ANY"}' --description exit-cutover-allow "${admin[@]}" >/dev/null
  cp "$work/pki/ca.crt" /secrets/ca.crt
  enroll() {
    local name="$1" dir="$2"
    "$cli" controller enrollment-token issue --network-id "$network" --label "$name" --expires-in 10m "${admin[@]}" |
      jq -er '.enrollment_token' >"$work/join.token"
    chmod 0600 "$work/join.token"
    "$cli" join --token-file "$work/join.token" --controller https://10.229.0.1:8443 \
      --ca "$work/pki/ca.crt" --server-name "$controller_name" \
      --controller-network-id "$network" --controller-service-id "$controller" \
      --name "$name" --out-cert "$dir/node.crt" --out-key "$dir/node.key" \
      --out-wireguard-key "$dir/wireguard.key"
  }
  joined="$(enroll exit-cutover /secrets)"
  gateway="$(sed -n 's/.* node=\([0-9a-f]\{32\}\) .*/\1/p' <<<"$joined")"
  [[ "$gateway" =~ ^[0-9a-f]{32}$ ]]
  printf '%s\n' "$gateway" >"$work/gateway.id"
  enroll exit-client "$work" >/dev/null
  "$cli" controller node capabilities --node-id "$gateway" --exit-node "${admin[@]}" >/dev/null

  cat >"$work/relay.toml" <<EOF
mode = "relay"
state_dir = "$work/relay-state"
[tls]
certificate = "$work/pki/relay.crt"
private_key = "$work/pki/relay.key"
ca = "$work/pki/ca.crt"
[relay]
listen = "0.0.0.0:4433"
[tcp_fallback]
listen = "0.0.0.0:8444"
[controller]
endpoint = "https://10.229.0.1:8443"
quic_endpoint = "10.229.0.1:8443"
server_name = "$controller_name"
network_id = "$network"
service_id = "$controller"
poll_interval = "250ms"
EOF
  "$work/relay" -config "$work/relay.toml" >"$work/relay.log" 2>&1 &
  local relay_pid=$!
  wait_fixture_log "$relay_pid" "$work/relay.log" "TCP-fallback="

  # The gateway dials a name that deliberately does not appear on the cert,
  # just like the production Compose `controller` service alias.
  configs() {
    local profile="$1" directory="$2" state="$3" socket="$4" host="$5" serving="$6" port="$7"
    local ca="$work/pki/ca.crt"
    if [[ "$serving" == true ]]; then ca=/secrets/ca.crt; fi
    cat <<EOF
mode = "node"
state_dir = "$state"
socket_path = "$socket"
[tls]
certificate = "$directory/node.crt"
private_key = "$directory/node.key"
ca = "$ca"
server_name = "$relay_name"
[node]
name = "$profile"
relay_address = "relay:4433"
relay_network_id = "$network"
relay_service_id = "$relay"
reconnect_min = "50ms"
reconnect_max = "500ms"
[controller]
endpoint = "https://$host:8443"
quic_endpoint = "$host:8443"
server_name = "$controller_name"
network_id = "$network"
service_id = "$controller"
poll_interval = "250ms"
[tcp_fallback]
address = "relay:8444"
[direct]
enabled = true
listen = "0.0.0.0:$port"
[routing]
output_interface = "wan0"
nat = true
[exit]
serve = $serving
failure_mode = "closed"
EOF
  }
  configs exit-cutover /secrets /var/lib/laneway /run/laneway/lanewayd.sock controller true 4434 >/secrets/exit-node.toml
  configs exit-client "$work" "$work/client-state" "$work/client.sock" 10.229.0.1 false 4435 >"$work/client.toml"
  printf '%s\n' 'dns_servers = ["192.168.77.2"]' >>"$work/client.toml"
  # A Go client requires systemd-resolved settings when selecting an exit.
  # This fixture does not resolve any name through that client or touch host DNS.
  test ! -e /usr/bin/resolvectl
  cat >/usr/bin/resolvectl <<'EOF'
#!/bin/sh
set -eu
command=$1 interface=$2
test "$interface" = lane0
directory=/tmp/exit-fixture
case "$command" in
  revert) rm -f "$directory/resolver-dns" "$directory/resolver-domain" "$directory/resolver-default-route" ;;
  dns|domain|default-route)
    shift 2
    file="$directory/resolver-$command"
    if [ "$#" -gt 0 ]; then
      printf '%s\n' "$*" >"$file"
    else
      value=""
      if [ -f "$file" ]; then value="$(cat "$file")"; fi
      printf 'Link 1 (%s): %s\n' "$interface" "$value"
    fi
    ;;
  *) exit 2 ;;
esac
EOF
  chmod 0755 /usr/bin/resolvectl
  chown 65532:65532 /secrets/* /state
  printf '%s\n' 'keep across image changes' > /state/rollback-marker
  "$cli" exit enable --family ipv4 --config /secrets/exit-node.toml |
    jq -er '.advertisements[0].route_id' >"$work/route.id"
  "$cli" controller route approve --route-id "$(cat "$work/route.id")" "${admin[@]}" >/dev/null

  ip netns exec exit-client "$cli" node run -config "$work/client.toml" >"$work/client.log" 2>&1 &
  local client_pid=$!
  wait_fixture_log "$client_pid" "$work/client.log" "interface=lane0"
  ip netns exec exit-client "$cli" exit use "$gateway" --socket "$work/client.sock" >/dev/null
  echo "exit cutover fixture ready"
  wait "$control_pid" "$relay_pid" "$client_pid"
}

wait_fixture_log() {
  local pid="$1" file="$2" pattern="$3"
  for _ in {1..100}; do
    if grep -Fq "$pattern" "$file"; then return 0; fi
    kill -0 "$pid" || break
    sleep 0.1
  done
  tail -n 20 "$file" >&2
  return 1
}

probe() {
  export PATH="/opt/rootless-lab:$PATH"
  local work=/tmp/exit-fixture label="$1" port="$2"
  ip netns exec exit-lan "$work/netprobe" udp-server -listen "192.168.77.2:$port" >"$work/$label.log" 2>&1 &
  probe_server_pid=$!
  trap 'kill "$probe_server_pid" 2>/dev/null || true' EXIT
  wait_fixture_log "$probe_server_pid" "$work/$label.log" "ready=udp-server"
  ip netns exec exit-client "$work/netprobe" udp-client \
    -target "192.168.77.2:$port" -message "$label" -timeout 15s
  wait "$probe_server_pid"
  trap - EXIT
  grep -Fq 'remote=192.168.77.1:' "$work/$label.log"
}

case "${1:-}" in
  --fixture) fixture; exit ;;
  --probe) shift; probe "$@"; exit ;;
esac

root="$(cd "$(dirname "$0")/../.." && pwd)"
lab_image="${LANEWAY_RUST_LAB_IMAGE:-laneway-rust-lab:local}"
go_image="${1:-laneway-go-exit:migration-lab}"
rust_image="${2:-laneway-rust-exit:migration-lab}"
case "$(docker info --format '{{json .SecurityOptions}}')" in
  *'"name=rootless"'*) ;;
  *) echo 'Use a rootless Docker lab with TUN support' >&2; exit 1 ;;
esac
for image in "$lab_image" "$go_image" "$rust_image"; do docker image inspect "$image" >/dev/null; done

lab="" gateway_container="" secrets="" state=""
stage=volumes
cleanup() {
  local result=$?
  if [[ $result -ne 0 ]]; then
    echo "Exit cutover failed during $stage" >&2
    if [[ -n "$gateway_container" ]]; then docker logs --tail 20 "$gateway_container" >&2 || true; fi
    if [[ -n "$lab" ]]; then
      docker logs --tail 20 "$lab" >&2 || true
      docker exec "$lab" bash -c 'for log in /tmp/exit-fixture/{controller,relay,client}.log; do
        if test -e "$log"; then tail -n 12 "$log"; fi
      done' >&2 || true
    fi
  fi
  if [[ -n "$gateway_container" ]]; then docker rm -f "$gateway_container" >/dev/null || true; fi
  if [[ -n "$lab" ]]; then docker rm -f "$lab" >/dev/null || true; fi
  if [[ -n "$secrets" ]]; then docker volume rm "$secrets" >/dev/null || true; fi
  if [[ -n "$state" ]]; then docker volume rm "$state" >/dev/null || true; fi
}
trap cleanup EXIT
secrets="$(docker volume create --label laneway.test=exit-cutover)"
state="$(docker volume create --label laneway.test=exit-cutover)"
stage=isolated-fixture
lab="$(docker run -d --network none --add-host controller:127.0.0.1 --add-host relay:10.229.0.1 \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --security-opt systempaths=unconfined --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
  -v "$root:/src:ro" -v "$secrets:/secrets" -v "$state:/state" \
  -v laneway-rust-lab-gomod:/go/pkg/mod -v laneway-rust-lab-gobuild:/gobuild \
  "$lab_image" bash /src/integration/rust-lab/exit-cutover.sh --fixture)"
for _ in {1..160}; do
  if docker logs "$lab" 2>&1 | grep -Fq 'exit cutover fixture ready'; then break; fi
  [[ "$(docker inspect -f '{{.State.Running}}' "$lab")" == true ]] || break
  sleep 0.25
done
docker logs "$lab" 2>&1 | grep -Fq 'exit cutover fixture ready'
gateway="$(docker exec "$lab" cat /tmp/exit-fixture/gateway.id)"
config=/secrets/exit-node.toml
state_manifest() {
  docker exec "$lab" bash -ec '
    find /secrets /state -printf "%y:%m:%u:%g:%p:%l\n" | sort
    find /secrets /state -type f -print0 | sort -z | xargs -0 sha256sum
  '
}

case_config=(-v "$secrets:/secrets:ro")
stage=offline-validation
docker run --rm --network none --read-only --cap-drop ALL "${case_config[@]}" \
  --entrypoint /usr/local/bin/lanewayd-rs "$rust_image" --exit-config "$config" --check-config

start_gateway() {
  local image="$1" process="$2" carrier="${3:-}" status version
  gateway_container="$(docker run -d --network "container:$lab" --read-only --user 65532:65532 \
    --cap-drop ALL --cap-add NET_ADMIN --device /dev/net/tun \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=0700,uid=65532,gid=65532 \
    --tmpfs /run/laneway:rw,noexec,nosuid,nodev,mode=0700,uid=65532,gid=65532 \
    "${case_config[@]}" -v "$state:/var/lib/laneway" "$image" -config "$config")"
  for _ in {1..120}; do
    if docker exec "$gateway_container" /usr/local/bin/laneway-healthcheck -unix /run/laneway/lanewayd.sock >/dev/null 2>&1; then break; fi
    [[ "$(docker inspect -f '{{.State.Running}}' "$gateway_container")" == true ]] || break
    sleep 0.25
  done
  docker exec "$gateway_container" /usr/local/bin/laneway-healthcheck -unix /run/laneway/lanewayd.sock
  status="$(docker exec "$gateway_container" /usr/local/bin/laneway status -config "$config" -json)"
  version="$(docker exec -i "$lab" jq -er --arg node "$gateway" \
    'select(.node_id == $node and .exit.serving and .exit.nat_ready) | .product_version' <<<"$status")"
  [[ "$(docker exec "$gateway_container" cat /sys/class/net/lane0/mtu)" == 1200 ]]
  docker exec "$gateway_container" sh -ec '
    pid="$(pgrep -xo "$1")"
    grep -Eq "^Uid:[[:space:]]+65532[[:space:]]+65532[[:space:]]+65532[[:space:]]+65532$" "/proc/$pid/status"
    grep -Eq "^NoNewPrivs:[[:space:]]+1$" "/proc/$pid/status"
    test "$(grep -Ec "^Cap(Inh|Prm|Eff|Bnd|Amb):[[:space:]]+0000000000001000$" "/proc/$pid/status")" -eq 5
  ' sh "$process"
  if [[ "$process" == lanewayd-rs ]]; then
    # This goes over HTTPS, not the QUIC control connection, and proves the
    # private dial address still works with the certificate's distinct name.
    local reported=false
    for _ in {1..240}; do
      local path
      path="$(docker exec "$lab" /tmp/exit-fixture/netprobe endpoint-health \
        -database /tmp/exit-fixture/controller.db -node-id "$gateway" -product-version "$version" 2>/dev/null || true)"
      if [[ -n "$path" && ( -z "$carrier" || "$path" == "$carrier" ) ]]; then
        reported=true
        break
      fi
      sleep 0.1
    done
    [[ "$reported" == true ]]
  fi
}

stop_gateway() {
  docker stop --time 20 "$gateway_container" >/dev/null
  [[ "$(docker inspect -f '{{.State.ExitCode}}' "$gateway_container")" == 0 ]]
  docker rm "$gateway_container" >/dev/null
  gateway_container=""
  if docker exec "$lab" ip link show lane0 >/dev/null 2>&1; then return 1; fi
  local tables
  tables="$(docker exec "$lab" nft list tables)"
  if grep -Eq ' (laneway_exit|laneway_rs_exit)$' <<<"$tables"; then return 1; fi
  [[ "$(docker exec "$lab" sysctl -n net.ipv4.ip_forward)" == 1 ]]
  [[ "$(docker exec "$lab" sysctl -n net.ipv6.conf.all.forwarding)" == 1 ]]
}

stage=go-baseline
start_gateway "$go_image" laneway
docker exec "$lab" bash /src/integration/rust-lab/exit-cutover.sh --probe go-baseline 9781
stop_gateway
before="$(state_manifest)"

stage=rust-replacement
start_gateway "$rust_image" lanewayd-rs
docker exec "$lab" bash /src/integration/rust-lab/exit-cutover.sh --probe rust-replacement 9782
stop_gateway
[[ "$(state_manifest)" == "$before" ]]

stage=rust-tcp-fallback
# Keep the client's QUIC relay connection. Only the gateway's UDP link to
# the relay and the two peers' direct UDP link are blocked in the fixture.
docker exec "$lab" nft add table inet exit_cutover_fixture
docker exec "$lab" nft add chain inet exit_cutover_fixture output '{ type filter hook output priority 0; policy accept; }'
docker exec "$lab" nft add rule inet exit_cutover_fixture output udp sport 4434 udp dport 4433 drop
docker exec "$lab" nft add rule inet exit_cutover_fixture output udp sport 4434 udp dport 4435 drop
docker exec "$lab" nft add chain inet exit_cutover_fixture input '{ type filter hook input priority 0; policy accept; }'
docker exec "$lab" nft add rule inet exit_cutover_fixture input udp dport 4434 drop
start_gateway "$rust_image" lanewayd-rs relay_tcp
docker exec "$lab" bash /src/integration/rust-lab/exit-cutover.sh --probe rust-tcp-fallback 9784
stop_gateway
docker exec "$lab" nft delete table inet exit_cutover_fixture
[[ "$(state_manifest)" == "$before" ]]

stage=go-rollback
start_gateway "$go_image" laneway
docker exec "$lab" bash /src/integration/rust-lab/exit-cutover.sh --probe go-rollback 9783
stop_gateway
[[ "$(state_manifest)" == "$before" ]]
echo 'PASS: packaged Go → Rust → Go durable Exit preserves identity, MTU, NAT, and kernel cleanup, including Rust TCP fallback'
