#!/usr/bin/env bash
set -euo pipefail

if [[ "${LANEWAY_RUN_PRIVILEGED:-0}" != "1" ]]; then
  echo "SKIP: set LANEWAY_RUN_PRIVILEGED=1 on a disposable Linux Docker host"
  exit 0
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "ERROR: Docker Exit integration must run as root on a disposable host" >&2
  exit 1
fi
for command in docker go jq ip nft sed openssl; do
  command -v "${command}" >/dev/null || { echo "ERROR: missing ${command}" >&2; exit 1; }
done
[[ -c /dev/net/tun ]] || { echo "ERROR: /dev/net/tun is unavailable" >&2; exit 1; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_id="${GITHUB_RUN_ID:-local}-$$"
owner="dev.laneway.integration.run=${run_id}"
prefix="lw-exit-${run_id}"
work_dir="$(mktemp -d -t laneway-docker-exit.XXXXXX)"
control_network="${prefix}-control"
egress_network="${prefix}-egress"
internet_network="${prefix}-internet"
controller_name="${prefix}-controller"
relay_name="${prefix}-relay"
client_name="${prefix}-client"
gateway_name="${prefix}-gateway"
external_name="${prefix}-external"
nat_name="${prefix}-nat"
controller_image="${prefix}-controller:dev"
relay_image="${prefix}-relay:dev"
admin_image="${prefix}-admin:dev"
node_image="${prefix}-node:dev"
probe_image="${prefix}-probe:dev"
client_volume="${prefix}-client-state"
gateway_volume="${prefix}-gateway-state"

snapshot_routes() { ip -j route show table all | jq -S 'sort_by(.table // 0, .dst // "", .dev // "", .gateway // "")'; }
snapshot_rules() {
  nft -s list ruleset 2>/dev/null |
    sed -E 's/ counter packets [0-9]+ bytes [0-9]+//g; s/ # handle [0-9]+//g'
}
snapshot_docker() {
  {
    docker ps -a --no-trunc --format 'container {{.ID}} {{.Names}}'
    docker network ls --no-trunc --format 'network {{.ID}} {{.Name}}'
    docker volume ls --format 'volume {{.Name}}'
  } | sort
}

snapshot_routes >"${work_dir}/host-routes.before"
snapshot_rules >"${work_dir}/host-nft.before"
snapshot_docker >"${work_dir}/docker.before"

owned_container() {
  [[ "$(docker inspect -f "{{ index .Config.Labels \"dev.laneway.integration.run\" }}" "$1" 2>/dev/null || true)" == "${run_id}" ]]
}
owned_network() {
  [[ "$(docker network inspect -f "{{ index .Labels \"dev.laneway.integration.run\" }}" "$1" 2>/dev/null || true)" == "${run_id}" ]]
}
owned_volume() {
  [[ "$(docker volume inspect -f "{{ index .Labels \"dev.laneway.integration.run\" }}" "$1" 2>/dev/null || true)" == "${run_id}" ]]
}
owned_image() {
  [[ "$(docker image inspect -f "{{ index .Config.Labels \"dev.laneway.integration.run\" }}" "$1" 2>/dev/null || true)" == "${run_id}" ]]
}

cleanup() {
  local result=$?
  set +e
  if [[ ${result} -ne 0 ]]; then
    for container in "${controller_name}" "${relay_name}" "${client_name}" "${gateway_name}" "${nat_name}" "${external_name}"; do
      if owned_container "${container}"; then
        echo "==> ${container} diagnostics" >&2
        docker logs --tail 240 "${container}" 2>&1 |
          sed -E 's/(enrollment[_ -]?token|admin[_ -]?token)([=: ]+)[^ ]+/\1\2<redacted>/Ig' >&2
      fi
    done
  fi
  for container in "${external_name}" "${nat_name}" "${client_name}" "${gateway_name}" "${relay_name}" "${controller_name}"; do
    owned_container "${container}" && docker rm -f "${container}" >/dev/null 2>&1
  done
  for network in "${internet_network}" "${egress_network}" "${control_network}"; do
    owned_network "${network}" && docker network rm "${network}" >/dev/null 2>&1
  done
  for volume in "${client_volume}" "${gateway_volume}"; do
    owned_volume "${volume}" && docker volume rm "${volume}" >/dev/null 2>&1
  done
  for image in "${probe_image}" "${node_image}" "${admin_image}" "${relay_image}" "${controller_image}"; do
    owned_image "${image}" && docker image rm -f "${image}" >/dev/null 2>&1
  done
  rm -rf -- "${work_dir}"
  exit "${result}"
}
trap cleanup EXIT INT TERM

wait_log() {
  local container="$1" pattern="$2"
  for _ in $(seq 1 180); do
    docker logs "${container}" 2>&1 | grep -Fq "${pattern}" && return 0
    [[ "$(docker inspect -f '{{.State.Running}}' "${container}" 2>/dev/null || true)" == "true" ]] || break
    sleep 0.25
  done
  echo "ERROR: ${container} did not report ${pattern}" >&2
  return 1
}

wait_status() {
  local container="$1" config="$2" pattern="$3"
  for _ in $(seq 1 240); do
    if docker exec --user 65532:65532 "${container}" /usr/local/bin/laneway status -config "${config}" 2>/dev/null | grep -Fq "${pattern}"; then
      return 0
    fi
    sleep 0.25
  done
  echo "ERROR: ${container} status did not reach ${pattern}" >&2
  return 1
}

wait_peer_path() {
  local container="$1" config="$2" peer="$3" expected="$4"
  for _ in $(seq 1 240); do
    if docker exec --user 65532:65532 "${container}" /usr/local/bin/laneway peers -config "${config}" -json 2>/dev/null |
      jq -e --arg peer "${peer}" --arg path "${expected}" '.[] | select(.node_id == $peer and .path == $path)' >/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  echo "ERROR: ${container} peer ${peer} did not reach ${expected}" >&2
  return 1
}

echo "==> build pinned product images and a scratch-only test probe"
docker build --quiet --label "${owner}" --build-arg BINARY=laneway-controller -t "${controller_image}" -f "${repo_root}/deploy/containers/Dockerfile" "${repo_root}" >/dev/null
docker build --quiet --label "${owner}" --build-arg BINARY=laneway-relay -t "${relay_image}" -f "${repo_root}/deploy/containers/Dockerfile" "${repo_root}" >/dev/null
docker build --quiet --label "${owner}" --build-arg BINARY=laneway -t "${admin_image}" -f "${repo_root}/deploy/containers/Dockerfile" "${repo_root}" >/dev/null
docker build --quiet --label "${owner}" -t "${node_image}" -f "${repo_root}/deploy/containers/Dockerfile.exit-node" "${repo_root}" >/dev/null
mkdir -p "${work_dir}/probe-context"
(cd "${repo_root}/go" && CGO_ENABLED=0 go build -trimpath -o "${work_dir}/probe-context/netprobe" ./integration/netprobe)
cat >"${work_dir}/probe-context/Dockerfile" <<'EOF'
FROM scratch
COPY netprobe /netprobe
ENTRYPOINT ["/netprobe"]
EOF
docker build --quiet --label "${owner}" -t "${probe_image}" "${work_dir}/probe-context" >/dev/null

echo "==> create uniquely owned Docker networks and state volumes"
docker network create --label "${owner}" "${control_network}" >/dev/null
docker network create --label "${owner}" "${egress_network}" >/dev/null
docker network create --label "${owner}" "${internet_network}" >/dev/null
docker volume create --label "${owner}" "${client_volume}" >/dev/null
docker volume create --label "${owner}" "${gateway_volume}" >/dev/null

mkdir -p "${work_dir}"/{controller,relay,admin,client,gateway}
chmod 0755 "${work_dir}" "${work_dir}"/{controller,relay,admin,client,gateway}
network_id="41000000000000000000000000000001"
controller_service="41000000000000000000000000000002"
relay_service="41000000000000000000000000000003"
admin_token="docker-exit-integration-admin-token-${run_id}"
printf '%s\n' "${admin_token}" >"${work_dir}/admin/admin.token"
chmod 0600 "${work_dir}/admin/admin.token"

go_bin="${work_dir}/laneway"
(cd "${repo_root}/go" && go build -trimpath -o "${go_bin}" ./cmd/laneway)
"${go_bin}" pki init -out-dir "${work_dir}/controller" >/dev/null
"${go_bin}" pki controller -ca-cert "${work_dir}/controller/ca.crt" -ca-key "${work_dir}/controller/ca.key" \
  -network-id "${network_id}" -service-id "${controller_service}" -dns "${controller_name}" \
  -out-cert "${work_dir}/controller/controller.crt" -out-key "${work_dir}/controller/controller.key"
"${go_bin}" pki relay -ca-cert "${work_dir}/controller/ca.crt" -ca-key "${work_dir}/controller/ca.key" \
  -network-id "${network_id}" -service-id "${relay_service}" -dns "${relay_name}" \
  -out-cert "${work_dir}/relay/relay.crt" -out-key "${work_dir}/relay/relay.key"
for directory in relay admin client gateway; do
  cp "${work_dir}/controller/ca.crt" "${work_dir}/${directory}/ca.crt"
done

cat >"${work_dir}/controller/controller.toml" <<EOF
mode = "controller"
state_dir = "/state"
socket_path = "/tmp/controller.sock"
[tls]
certificate = "/secrets/controller.crt"
private_key = "/secrets/controller.key"
ca = "/secrets/ca.crt"
[controller]
listen = ":8443"
quic_listen = ":8443"
database = "/state/controller.db"
ca_private_key = "/secrets/ca.key"
admin_token_file = "/admin/admin.token"
leaf_validity = "24h"
EOF

chown -R 65532:65532 "${work_dir}"/{controller,relay,admin,client,gateway}
docker run -d --name "${controller_name}" --hostname "${controller_name}" --label "${owner}" \
  --network "${control_network}" --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m,uid=65532,gid=65532 \
  --tmpfs /state:rw,noexec,nosuid,nodev,size=32m,uid=65532,gid=65532 \
  -v "${work_dir}/controller:/secrets:ro" -v "${work_dir}/admin:/admin:ro" \
  "${controller_image}" -config /secrets/controller.toml >/dev/null
wait_log "${controller_name}" "laneway-controller HTTPS="

admin() {
  docker run --rm --label "${owner}" --network "${control_network}" --read-only --cap-drop ALL \
    --security-opt no-new-privileges -v "${work_dir}/admin:/admin:ro" \
    -v "${work_dir}/controller/ca.crt:/ca.crt:ro" "${admin_image}" "$@"
}
admin_connection=(--controller "https://${controller_name}:8443" --ca /ca.crt --server-name "${controller_name}" \
  --controller-network-id "${network_id}" --controller-service-id "${controller_service}" --admin-token-file /admin/admin.token)
admin controller network create --network-id "${network_id}" --name docker-exit --ipv4-pool 100.117.0.0/24 "${admin_connection[@]}" >/dev/null
admin controller relay register --network-id "${network_id}" --service-id "${relay_service}" \
  --name docker-relay --endpoint "${relay_name}:4433" "${admin_connection[@]}" >/dev/null

issue_token() {
  local label="$1" directory="$2"
  admin controller enrollment-token issue --network-id "${network_id}" --label "${label}" --expires-in 10m "${admin_connection[@]}" |
    jq -r '.enrollment_token' >"${directory}/enrollment.token"
  chmod 0600 "${directory}/enrollment.token"
  chown 65532:65532 "${directory}/enrollment.token"
}
issue_token docker-client "${work_dir}/client"
issue_token docker-gateway "${work_dir}/gateway"

join_node() {
  local name="$1" directory="$2"
  docker run --rm --label "${owner}" --network "${control_network}" --read-only --cap-drop ALL \
    --security-opt no-new-privileges -v "${directory}:/node" \
    -v "${work_dir}/controller/ca.crt:/ca.crt:ro" "${admin_image}" join \
    --token-file /node/enrollment.token --controller "https://${controller_name}:8443" --ca /ca.crt \
    --server-name "${controller_name}" --controller-network-id "${network_id}" \
    --controller-service-id "${controller_service}" --name "${name}" \
    --out-cert /node/node.crt --out-key /node/node.key \
    --out-wireguard-key /node/wireguard.key >/dev/null
  rm -f -- "${directory}/enrollment.token"
}
join_node docker-client "${work_dir}/client"
join_node docker-gateway "${work_dir}/gateway"
client_id="$(openssl x509 -in "${work_dir}/client/node.crt" -noout -ext subjectAltName | sed -n 's/.*node\/\([0-9a-f]\{32\}\).*/\1/p')"
gateway_id="$(openssl x509 -in "${work_dir}/gateway/node.crt" -noout -ext subjectAltName | sed -n 's/.*node\/\([0-9a-f]\{32\}\).*/\1/p')"
[[ "${client_id}" =~ ^[0-9a-f]{32}$ && "${gateway_id}" =~ ^[0-9a-f]{32}$ ]] || { echo "ERROR: enrollment identity parse failed" >&2; exit 1; }
admin controller node capabilities --node-id "${gateway_id}" --exit-node "${admin_connection[@]}" >/dev/null
acl_json="$(admin controller acl add --network-id "${network_id}" --priority 100 --action accept \
  --selector '{"ip_protocol":"IP_PROTOCOL_ANY"}' --description docker-exit-allow "${admin_connection[@]}")"
[[ "$(jq -r '.rule_id' <<<"${acl_json}")" =~ ^[0-9a-f]{32}$ ]] || { echo "ERROR: ACL creation failed" >&2; exit 1; }

cat >"${work_dir}/relay/relay.toml" <<EOF
mode = "relay"
state_dir = "/tmp/state"
socket_path = "/tmp/relay.sock"
[tls]
certificate = "/secrets/relay.crt"
private_key = "/secrets/relay.key"
ca = "/secrets/ca.crt"
[relay]
listen = ":4433"
packet_rate_bits_per_second = 2000000
packet_burst_bytes = 65536
[tcp_fallback]
listen = ":8443"
[controller]
endpoint = "https://${controller_name}:8443"
quic_endpoint = "${controller_name}:8443"
server_name = "${controller_name}"
network_id = "${network_id}"
service_id = "${controller_service}"
poll_interval = "250ms"
EOF

node_config() {
  local directory="$1" name="$2" listen_port="$3" serve="$4" output="$5"
  cat >"${directory}/node.toml" <<EOF
mode = "node"
state_dir = "/var/lib/laneway"
socket_path = "/run/laneway/lanewayd.sock"
[tls]
certificate = "/secrets/node.crt"
private_key = "/secrets/node.key"
ca = "/secrets/ca.crt"
server_name = "${relay_name}"
[node]
name = "${name}"
relay_address = "${relay_name}:4433"
relay_network_id = "${network_id}"
relay_service_id = "${relay_service}"
reconnect_min = "100ms"
reconnect_max = "1s"
[controller]
endpoint = "https://${controller_name}:8443"
quic_endpoint = "${controller_name}:8443"
server_name = "${controller_name}"
network_id = "${network_id}"
service_id = "${controller_service}"
poll_interval = "250ms"
[tcp_fallback]
address = "${relay_name}:8443"
quic_probe_interval = "1s"
[direct]
enabled = true
listen = "0.0.0.0:${listen_port}"
probe_interval = "100ms"
probe_timeout = "2s"
rendezvous_interval = "2s"
[wireguard]
private_key = "/secrets/wireguard.key"
mtu = 1200
[routing]
output_interface = "${output}"
nat = true
[exit]
serve = ${serve}
failure_mode = "closed"
EOF
}
node_config "${work_dir}/client" docker-client 4435 false eth0
node_config "${work_dir}/gateway" docker-gateway 4434 true eth1
chown -R 65532:65532 "${work_dir}"/{relay,client,gateway}

docker run -d --name "${relay_name}" --hostname "${relay_name}" --label "${owner}" --network "${control_network}" \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532 \
  -v "${work_dir}/relay:/secrets:ro" "${relay_image}" -config /secrets/relay.toml -diagnostics 127.0.0.1:6060 >/dev/null
wait_log "${relay_name}" "laneway-relay QUIC="

node_create() {
  local name="$1" directory="$2" volume="$3"
  docker create --name "${name}" --hostname "${name}" --label "${owner}" --network "${control_network}" \
    --user 65532:65532 --read-only --cap-drop ALL --cap-add NET_ADMIN \
    --security-opt no-new-privileges --device /dev/net/tun:/dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532 \
    --tmpfs /run/laneway:rw,noexec,nosuid,nodev,size=4m,uid=65532,gid=65532 \
    -v "${volume}:/var/lib/laneway" -v "${directory}:/secrets:ro" \
    -v "${work_dir}/probe-context/netprobe:/test/netprobe:ro" \
    "${node_image}" -config /secrets/node.toml >/dev/null
}
node_create "${client_name}" "${work_dir}/client" "${client_volume}"
node_create "${gateway_name}" "${work_dir}/gateway" "${gateway_volume}"
for node_name in "${client_name}" "${gateway_name}"; do
  docker inspect "${node_name}" | jq -e '
    .[0].Config.User == "65532:65532" and
    .[0].HostConfig.Privileged == false and
    .[0].HostConfig.NetworkMode != "host" and
    .[0].HostConfig.CapAdd == ["NET_ADMIN"] and
    .[0].HostConfig.SecurityOpt == ["no-new-privileges"] and
    (.[0].HostConfig.Devices | length == 1) and
    .[0].HostConfig.Devices[0].PathOnHost == "/dev/net/tun" and
    .[0].HostConfig.Devices[0].PathInContainer == "/dev/net/tun"
  ' >/dev/null
done
docker network connect "${egress_network}" "${gateway_name}"
docker start "${client_name}" "${gateway_name}" >/dev/null
wait_log "${client_name}" "interface=lane0"
wait_log "${gateway_name}" "interface=lane0"
docker exec "${client_name}" sh -c 'test "$(cat /sys/class/net/lane0/mtu)" = 1200'
docker exec "${gateway_name}" sh -c 'test "$(cat /sys/class/net/lane0/mtu)" = 1200 && ip link show eth1 >/dev/null'

echo "==> create a second, disposable cone-like NAT between the Exit bridge and Internet fixture"
docker create --name "${nat_name}" --hostname "${nat_name}" --label "${owner}" --network "${egress_network}" \
  --user 0:0 --read-only --cap-drop ALL --cap-add NET_ADMIN --security-opt no-new-privileges \
  --sysctl net.ipv4.ip_forward=1 --entrypoint /bin/sh "${node_image}" -c \
  'nft add table ip laneway_test_nat; nft add chain ip laneway_test_nat postrouting "{ type nat hook postrouting priority srcnat; policy accept; }"; nft add rule ip laneway_test_nat postrouting oifname eth1 masquerade; exec sleep infinity' >/dev/null
docker network connect "${internet_network}" "${nat_name}"
docker start "${nat_name}" >/dev/null
nat_egress_ip="$(docker inspect -f "{{with index .NetworkSettings.Networks \"${egress_network}\"}}{{.IPAddress}}{{end}}" "${nat_name}")"
nat_internet_ip="$(docker inspect -f "{{with index .NetworkSettings.Networks \"${internet_network}\"}}{{.IPAddress}}{{end}}" "${nat_name}")"
[[ -n "${nat_egress_ip}" && -n "${nat_internet_ip}" ]] || { echo "ERROR: double-NAT fixture addresses are unavailable" >&2; exit 1; }

echo "==> controller authorizes the container Exit and the client selects it"
exit_json="$(docker exec --user 65532:65532 "${gateway_name}" /usr/local/bin/laneway exit enable --family ipv4 --config /secrets/node.toml)"
exit_route_id="$(jq -r '.advertisements[0].route_id' <<<"${exit_json}")"
[[ "${exit_route_id}" =~ ^[0-9a-f]{32}$ ]] || { echo "ERROR: Exit route advertisement failed" >&2; exit 1; }
admin controller route approve --route-id "${exit_route_id}" "${admin_connection[@]}" >/dev/null
for _ in $(seq 1 120); do
  docker exec "${gateway_name}" nft list table inet laneway_exit >/dev/null 2>&1 && break
  sleep 0.25
done
docker exec "${gateway_name}" nft list table inet laneway_exit >/dev/null
docker exec --user 65532:65532 "${client_name}" /usr/local/bin/laneway exit use docker-gateway -config /secrets/node.toml >/dev/null
wait_status "${client_name}" /secrets/node.toml "exit=${gateway_id} authorized=true"

run_external_flow() {
  local label="$1"
  owned_container "${external_name}" && docker rm -f "${external_name}" >/dev/null
  docker run -d --name "${external_name}" --label "${owner}" --network "${internet_network}" "${probe_image}" \
    udp-server -listen :9201 >/dev/null
  wait_log "${external_name}" "ready=udp-server"
  local target
  target="$(docker inspect -f "{{with index .NetworkSettings.Networks \"${internet_network}\"}}{{.IPAddress}}{{end}}" "${external_name}")"
  docker exec "${gateway_name}" ip route replace "${target}/32" via "${nat_egress_ip}" dev eth1
  docker exec "${client_name}" /test/netprobe udp-client -target "${target}:9201" -message "${label}" -timeout 15s >/dev/null
  for _ in $(seq 1 40); do
    docker logs "${external_name}" 2>&1 | grep -Fq "remote=${nat_internet_ip}:" && return 0
    sleep 0.1
  done
  echo "ERROR: external server did not observe container Exit NAT" >&2
  return 1
}

echo "==> fixed-port direct path forwards and NATs inside the Exit namespace"
wait_peer_path "${client_name}" /secrets/node.toml "${gateway_id}" direct
run_external_flow docker-exit-direct

echo "==> restrictive peer UDP forces capped relay fallback while controller remains healthy"
docker exec "${client_name}" nft add table inet laneway_test_direct_block
docker exec "${client_name}" nft add chain inet laneway_test_direct_block output '{ type filter hook output priority filter; policy accept; }'
docker exec "${client_name}" nft add rule inet laneway_test_direct_block output udp dport 4434 drop
docker exec "${gateway_name}" nft add table inet laneway_test_direct_block
docker exec "${gateway_name}" nft add chain inet laneway_test_direct_block output '{ type filter hook output priority filter; policy accept; }'
docker exec "${gateway_name}" nft add rule inet laneway_test_direct_block output udp dport 4435 drop
wait_peer_path "${client_name}" /secrets/node.toml "${gateway_id}" relay-quic
run_external_flow docker-exit-relay

echo "==> saturate only relay packet data while authenticated controller requests remain healthy"
owned_container "${external_name}" && docker rm -f "${external_name}" >/dev/null
docker run -d --name "${external_name}" --label "${owner}" --network "${internet_network}" "${probe_image}" \
  udp-echo-server -listen :9202 >/dev/null
wait_log "${external_name}" "ready=udp-echo-server"
saturation_target="$(docker inspect -f "{{with index .NetworkSettings.Networks \"${internet_network}\"}}{{.IPAddress}}{{end}}" "${external_name}")"
docker exec "${gateway_name}" ip route replace "${saturation_target}/32" via "${nat_egress_ip}" dev eth1
docker exec "${client_name}" /test/netprobe udp-bench-client -target "${saturation_target}:9202" \
  -scenario docker-exit-relay-saturation -scope controller-authorized-double-nat \
  -duration 750ms -size 1200 -pps 3000 -flows 1 >/dev/null
throttled="$(docker run --rm --label "${owner}" --network "container:${relay_name}" "${probe_image}" \
  metric -url http://127.0.0.1:6060/metrics -name laneway_throttled_packets_total)"
[[ "${throttled}" =~ ^[0-9]+$ && "${throttled}" -gt 0 ]] || { echo "ERROR: relay did not expose saturation drops" >&2; exit 1; }
admin controller audit --network-id "${network_id}" --limit 1 "${admin_connection[@]}" >/dev/null
docker exec "${client_name}" nft delete table inet laneway_test_direct_block
docker exec "${gateway_name}" nft delete table inet laneway_test_direct_block
wait_peer_path "${client_name}" /secrets/node.toml "${gateway_id}" direct

echo "==> graceful restart and SIGKILL restart recreate only container-owned state"
docker stop --time 20 "${gateway_name}" >/dev/null
docker start "${gateway_name}" >/dev/null
wait_log "${gateway_name}" "interface=lane0"
for _ in $(seq 1 120); do docker exec "${gateway_name}" nft list table inet laneway_exit >/dev/null 2>&1 && break; sleep 0.25; done
run_external_flow docker-exit-graceful-restart
docker kill --signal KILL "${gateway_name}" >/dev/null
docker start "${gateway_name}" >/dev/null
wait_log "${gateway_name}" "interface=lane0"
for _ in $(seq 1 120); do docker exec "${gateway_name}" nft list table inet laneway_exit >/dev/null 2>&1 && break; sleep 0.25; done
run_external_flow docker-exit-crash-restart

echo "==> remove owned Docker resources and prove foreign host/container state is unchanged"
for container in "${external_name}" "${nat_name}" "${client_name}" "${gateway_name}" "${relay_name}" "${controller_name}"; do
  owned_container "${container}" && docker rm -f "${container}" >/dev/null
done
for network in "${internet_network}" "${egress_network}" "${control_network}"; do owned_network "${network}" && docker network rm "${network}" >/dev/null; done
for volume in "${client_volume}" "${gateway_volume}"; do owned_volume "${volume}" && docker volume rm "${volume}" >/dev/null; done
snapshot_routes >"${work_dir}/host-routes.after"
snapshot_rules >"${work_dir}/host-nft.after"
snapshot_docker >"${work_dir}/docker.after"
diff -u "${work_dir}/host-routes.before" "${work_dir}/host-routes.after"
diff -u "${work_dir}/host-nft.before" "${work_dir}/host-nft.after"
diff -u "${work_dir}/docker.before" "${work_dir}/docker.after"
echo "PASS: isolated Docker Exit direct/relay NAT, MTU, graceful/crash restart, and exact host-state restoration"
