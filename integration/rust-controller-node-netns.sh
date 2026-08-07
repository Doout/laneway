#!/usr/bin/env bash
set -euo pipefail

if [[ "${LANEWAY_RUN_PRIVILEGED:-0}" != "1" ]]; then
  echo "SKIP: set LANEWAY_RUN_PRIVILEGED=1 to run the Go-controller/Rust-node gate"
  exit 0
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "ERROR: the Go-controller/Rust-node gate requires root" >&2
  exit 1
fi
for command in cargo go ip nft grep sed; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "ERROR: required command is missing: ${command}" >&2
    exit 1
  fi
done
if [[ ! -c /dev/net/tun ]]; then
  echo "ERROR: /dev/net/tun is unavailable" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d -t laneway-rust-controller.XXXXXX)"
prefix="lwrc$$_"
switch="${prefix}s"
controller_ns="${prefix}c"
relay_ns="${prefix}r"
rust_ns="${prefix}n"
gateway_ns="${prefix}g"
lan_ns="${prefix}l"
declare -a namespaces=()
declare -A active_processes=()
last_pid=""
link_index=0

cleanup() {
  for pid in "${!active_processes[@]}"; do
    kill -TERM "${pid}" >/dev/null 2>&1 || true
  done
  for pid in "${!active_processes[@]}"; do
    wait "${pid}" >/dev/null 2>&1 || true
  done
  for namespace in "${namespaces[@]:-}"; do
    ip netns delete "${namespace}" >/dev/null 2>&1 || true
  done
  if [[ "${LANEWAY_KEEP_INTEGRATION_WORK:-0}" == "1" ]]; then
    echo "integration artifacts retained at ${work_dir}" >&2
  else
    rm -rf -- "${work_dir}"
  fi
}
trap cleanup EXIT INT TERM

start_process() {
  local namespace="$1" log="$2"
  shift 2
  ip netns exec "${namespace}" "$@" >"${log}" 2>&1 &
  last_pid=$!
  active_processes["${last_pid}"]=1
}

stop_process() {
  local pid="$1"
  kill -TERM "${pid}" >/dev/null 2>&1 || true
  for _ in $(seq 1 240); do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      wait "${pid}" >/dev/null 2>&1 || true
      unset "active_processes[${pid}]"
      return 0
    fi
    sleep 0.05
  done
  echo "ERROR: process ${pid} did not stop" >&2
  return 1
}

wait_log() {
  local pid="$1" log="$2" pattern="$3"
  for _ in $(seq 1 240); do
    if grep -q -- "${pattern}" "${log}" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      echo "ERROR: process ${pid} stopped before log pattern: ${pattern}" >&2
      sed -n '1,260p' "${log}" >&2 || true
      return 1
    fi
    sleep 0.05
  done
  echo "ERROR: timed out waiting for log pattern: ${pattern}" >&2
  sed -n '1,260p' "${log}" >&2 || true
  return 1
}

wait_route() {
  local namespace="$1" prefix="$2" present="$3"
  for _ in $(seq 1 240); do
    local found=0
    if ip -n "${namespace}" route show exact "${prefix}" 2>/dev/null | grep -q .; then
      found=1
    fi
    if [[ "${found}" == "${present}" ]]; then
      return 0
    fi
    sleep 0.05
  done
  echo "ERROR: route ${prefix} presence did not become ${present}" >&2
  ip -n "${namespace}" route show >&2 || true
  return 1
}

wait_relay_sessions() {
  local expected="$1"
  for _ in $(seq 1 240); do
    local sessions
    sessions="$(ip netns exec "${relay_ns}" "${work_dir}/netprobe" metric \
      -url http://127.0.0.1:6060/metrics -name laneway_relay_sessions 2>/dev/null || true)"
    if [[ "${sessions}" == "${expected}" ]]; then
      return 0
    fi
    sleep 0.05
  done
  echo "ERROR: relay sessions did not become ${expected}" >&2
  sed -n '1,260p' "${work_dir}/relay.log" >&2 || true
  return 1
}

json_string_field() {
  local field="$1"
  sed -n 's/^[[:space:]]*"'"${field}"'": "\([^"]*\)"[,]*$/\1/p'
}

add_namespace() {
  local namespace="$1"
  ip netns add "${namespace}"
  namespaces+=("${namespace}")
  ip -n "${namespace}" link set lo up
}

attach_switch() {
  local target="$1" interface_name="$2" address="$3"
  link_index=$((link_index + 1))
  local switch_end="s${link_index}x$$" target_end="t${link_index}x$$"
  ip link add "${switch_end}" type veth peer name "${target_end}"
  ip link set "${switch_end}" netns "${switch}"
  ip link set "${target_end}" netns "${target}"
  ip -n "${switch}" link set "${switch_end}" master br0
  ip -n "${switch}" link set "${switch_end}" up
  ip -n "${target}" link set "${target_end}" name "${interface_name}"
  ip -n "${target}" address add "${address}" dev "${interface_name}"
  ip -n "${target}" link set "${interface_name}" up
}

udp_success() {
  local port="$1" message="$2"
  start_process "${lan_ns}" "${work_dir}/${message}-server.log" \
    "${work_dir}/netprobe" udp-server -listen "192.168.77.2:${port}"
  local server_pid="${last_pid}"
  wait_log "${server_pid}" "${work_dir}/${message}-server.log" "ready=udp-server"
  ip netns exec "${rust_ns}" "${work_dir}/netprobe" udp-client \
    -target "192.168.77.2:${port}" -message "${message}" -timeout 5s
  wait "${server_pid}"
  unset "active_processes[${server_pid}]"
  grep -q 'remote=192.168.77.1:' "${work_dir}/${message}-server.log"
}

udp_denied() {
  local port="$1" message="$2"
  start_process "${lan_ns}" "${work_dir}/${message}-server.log" \
    "${work_dir}/netprobe" udp-server -listen "192.168.77.2:${port}"
  local server_pid="${last_pid}"
  wait_log "${server_pid}" "${work_dir}/${message}-server.log" "ready=udp-server"
  if ip netns exec "${rust_ns}" "${work_dir}/netprobe" udp-client \
      -target "192.168.77.2:${port}" -message "${message}" -timeout 2s; then
    echo "ERROR: traffic unexpectedly passed during ${message}" >&2
    return 1
  fi
  kill -TERM "${server_pid}" >/dev/null 2>&1 || true
  wait "${server_pid}" >/dev/null 2>&1 || true
  unset "active_processes[${server_pid}]"
}

echo "==> building the real controller service fixture, product binaries, and Rust node"
(
  cd "${repo_root}/go"
  go build -o "${work_dir}/laneway" ./cmd/laneway
  go build -o "${work_dir}/lanewayd" ./cmd/lanewayd
  go build -o "${work_dir}/laneway-relay" ./cmd/laneway-relay
  go build -o "${work_dir}/netprobe" ./integration/netprobe
  go build -o "${work_dir}/rustnodecontroller" ./integration/rustnodecontroller
)
cargo build --quiet --locked --manifest-path "${repo_root}/rust/Cargo.toml" -p lanewayd-rs
cp "${repo_root}/rust/target/debug/lanewayd-rs" "${work_dir}/rust-node"

network_id="21000000000000000000000000000001"
controller_service="21000000000000000000000000000002"
relay_service="21000000000000000000000000000003"
controller_endpoint="https://10.254.0.1:8443"
controller_quic_endpoint="10.254.0.1:8443"
admin_token="laneway-rust-controller-integration-admin-token-00000001"
printf '%s\n' "${admin_token}" >"${work_dir}/admin.token"
chmod 600 "${work_dir}/admin.token"
"${work_dir}/laneway" pki init -out-dir "${work_dir}/pki" >/dev/null
"${work_dir}/laneway" pki controller \
  -ca-cert "${work_dir}/pki/ca.crt" -ca-key "${work_dir}/pki/ca.key" \
  -network-id "${network_id}" -service-id "${controller_service}" -ip 10.254.0.1 \
  -out-cert "${work_dir}/pki/controller.crt" -out-key "${work_dir}/pki/controller.key"
"${work_dir}/laneway" pki relay \
  -ca-cert "${work_dir}/pki/ca.crt" -ca-key "${work_dir}/pki/ca.key" \
  -network-id "${network_id}" -service-id "${relay_service}" -ip 10.254.0.2 \
  -out-cert "${work_dir}/pki/relay.crt" -out-key "${work_dir}/pki/relay.key"

add_namespace "${switch}"
ip -n "${switch}" link add br0 type bridge
ip -n "${switch}" link set br0 up
for namespace in "${controller_ns}" "${relay_ns}" "${rust_ns}" "${gateway_ns}" "${lan_ns}"; do
  add_namespace "${namespace}"
done
attach_switch "${controller_ns}" eth0 10.254.0.1/24
attach_switch "${relay_ns}" eth0 10.254.0.2/24
attach_switch "${rust_ns}" eth0 10.254.0.3/24
attach_switch "${gateway_ns}" eth0 10.254.0.4/24

ip link add "lg$$" type veth peer name "ll$$"
ip link set "lg$$" netns "${gateway_ns}"
ip link set "ll$$" netns "${lan_ns}"
ip -n "${gateway_ns}" link set "lg$$" name lan1
ip -n "${lan_ns}" link set "ll$$" name eth0
ip -n "${gateway_ns}" address add 192.168.77.1/24 dev lan1
ip -n "${lan_ns}" address add 192.168.77.2/24 dev eth0
ip -n "${gateway_ns}" link set lan1 up
ip -n "${lan_ns}" link set eth0 up
ip netns exec "${gateway_ns}" sysctl -qw net.ipv4.ip_forward=0

controller_command=(
  "${work_dir}/rustnodecontroller"
  -listen 10.254.0.1:8443
  -quic-listen 10.254.0.1:8443
  -database "${work_dir}/controller.db"
  -ca-cert "${work_dir}/pki/ca.crt"
  -ca-key "${work_dir}/pki/ca.key"
  -controller-cert "${work_dir}/pki/controller.crt"
  -controller-key "${work_dir}/pki/controller.key"
  -admin-token-file "${work_dir}/admin.token"
  -snapshot-validity 2s
  -initial-node-delay 1500ms
)
start_process "${controller_ns}" "${work_dir}/controller.log" "${controller_command[@]}"
controller_pid="${last_pid}"
wait_log "${controller_pid}" "${work_dir}/controller.log" "test controller listening"

admin_connection=(
  --controller "${controller_endpoint}"
  --ca "${work_dir}/pki/ca.crt"
  --controller-network-id "${network_id}"
  --controller-service-id "${controller_service}"
  --admin-token-file "${work_dir}/admin.token"
)
ip netns exec "${controller_ns}" "${work_dir}/laneway" controller network create \
  --network-id "${network_id}" --name rust-node-live --ipv4-pool 100.115.0.0/24 \
  "${admin_connection[@]}" >"${work_dir}/network.json"
ip netns exec "${controller_ns}" "${work_dir}/laneway" controller relay register \
  --network-id "${network_id}" --service-id "${relay_service}" \
  --name rust-live-relay --endpoint 10.254.0.2:4433 \
  "${admin_connection[@]}" >"${work_dir}/relay-registration.json"

rust_token_json="$(ip netns exec "${controller_ns}" "${work_dir}/laneway" controller enrollment-token issue \
  --network-id "${network_id}" --label rust-node --expires-in 10m "${admin_connection[@]}")"
gateway_token_json="$(ip netns exec "${controller_ns}" "${work_dir}/laneway" controller enrollment-token issue \
  --network-id "${network_id}" --label gateway --expires-in 10m "${admin_connection[@]}")"
rust_token="$(printf '%s\n' "${rust_token_json}" | json_string_field enrollment_token)"
gateway_token="$(printf '%s\n' "${gateway_token_json}" | json_string_field enrollment_token)"
if [[ -z "${rust_token}" || -z "${gateway_token}" ]]; then
  echo "ERROR: controller enrollment tokens were not returned" >&2
  exit 1
fi

rust_join="$(ip netns exec "${rust_ns}" "${work_dir}/laneway" join "${rust_token}" \
  --controller "${controller_endpoint}" --ca "${work_dir}/pki/ca.crt" \
  --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
  --name rust-controller-node --out-cert "${work_dir}/pki/rust.crt" --out-key "${work_dir}/pki/rust.key")"
gateway_join="$(ip netns exec "${gateway_ns}" "${work_dir}/laneway" join "${gateway_token}" \
  --controller "${controller_endpoint}" --ca "${work_dir}/pki/ca.crt" \
  --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
  --name go-gateway --out-cert "${work_dir}/pki/gateway.crt" --out-key "${work_dir}/pki/gateway.key")"
rust_id="$(printf '%s\n' "${rust_join}" | sed -n 's/.* node=\([0-9a-f]\{32\}\) .*/\1/p')"
gateway_id="$(printf '%s\n' "${gateway_join}" | sed -n 's/.* node=\([0-9a-f]\{32\}\) .*/\1/p')"
rust_overlay="$(printf '%s\n' "${rust_join}" | sed -n 's/.* overlay=\([^, ]*\).*/\1/p')"
gateway_overlay="$(printf '%s\n' "${gateway_join}" | sed -n 's/.* overlay=\([^, ]*\).*/\1/p')"
rust_address="${rust_overlay%/32}"
gateway_address="${gateway_overlay%/32}"
if [[ ! "${rust_id}" =~ ^[0-9a-f]{32}$ || ! "${gateway_id}" =~ ^[0-9a-f]{32}$ || \
      -z "${rust_address}" || -z "${gateway_address}" ]]; then
  echo "ERROR: failed to parse enrollment results" >&2
  printf '%s\n%s\n' "${rust_join}" "${gateway_join}" >&2
  exit 1
fi
ip netns exec "${controller_ns}" "${work_dir}/laneway" controller node capabilities \
  --node-id "${gateway_id}" --subnet-router "${admin_connection[@]}" >"${work_dir}/capabilities.json"
acl_json="$(ip netns exec "${controller_ns}" "${work_dir}/laneway" controller acl add \
  --network-id "${network_id}" --priority 100 --action accept \
  --selector '{"ip_protocol":"IP_PROTOCOL_ANY"}' --description rust-live-allow \
  "${admin_connection[@]}")"
acl_id="$(printf '%s\n' "${acl_json}" | json_string_field rule_id)"
if [[ ! "${acl_id}" =~ ^[0-9a-f]{32}$ ]]; then
  echo "ERROR: failed to parse ACL rule ID" >&2
  exit 1
fi

cat >"${work_dir}/relay.toml" <<EOF
mode = "relay"
state_dir = "${work_dir}/relay-state"
socket_path = "${work_dir}/relay.sock"
[tls]
certificate = "${work_dir}/pki/relay.crt"
private_key = "${work_dir}/pki/relay.key"
ca = "${work_dir}/pki/ca.crt"
[relay]
listen = "10.254.0.2:4433"
[controller]
endpoint = "${controller_endpoint}"
quic_endpoint = "${controller_quic_endpoint}"
network_id = "${network_id}"
service_id = "${controller_service}"
poll_interval = "100ms"
EOF

cat >"${work_dir}/gateway.toml" <<EOF
mode = "node"
state_dir = "${work_dir}/gateway-state"
socket_path = "${work_dir}/gateway.sock"
[tls]
certificate = "${work_dir}/pki/gateway.crt"
private_key = "${work_dir}/pki/gateway.key"
ca = "${work_dir}/pki/ca.crt"
[node]
name = "go-gateway"
relay_address = "10.254.0.2:4433"
relay_network_id = "${network_id}"
relay_service_id = "${relay_service}"
reconnect_min = "50ms"
reconnect_max = "500ms"
[controller]
endpoint = "${controller_endpoint}"
quic_endpoint = "${controller_quic_endpoint}"
network_id = "${network_id}"
service_id = "${controller_service}"
poll_interval = "100ms"
[routing]
advertise = ["192.168.77.0/24"]
nat = true
output_interface = "lan1"
EOF

cat >"${work_dir}/rust.toml" <<EOF
mode = "node"
socket_path = "${work_dir}/rust.sock"
exit_intent_path = "${work_dir}/rust-exit-intent.json"
[identity]
network_id = "${network_id}"
node_id = "${rust_id}"
[tls]
certificate = "${work_dir}/pki/rust.crt"
private_key = "${work_dir}/pki/rust.key"
ca = "${work_dir}/pki/ca.crt"
[controller]
endpoint = "${controller_endpoint}"
quic_endpoint = "${controller_quic_endpoint}"
server_name = "10.254.0.1"
service_id = "${controller_service}"
poll_interval = "100ms"
timeout = "3s"
[tun]
name = "lane0"
mtu = 1280
configure = true
[relay]
address = "10.254.0.2:4433"
server_name = "10.254.0.2"
service_id = "${relay_service}"
queue_depth = 32
max_routes = 64
handshake_timeout = "5s"
idle_timeout = "15s"
keepalive = "5s"
reconnect_min = "50ms"
reconnect_max = "500ms"
quic_recovery_interval = "5s"
[direct]
listen = "0.0.0.0:4434"
EOF

echo "==> bootstrap is held before TUN creation, then the controller assignment is applied"
start_process "${rust_ns}" "${work_dir}/rust.log" env RUST_LOG=info \
  "${work_dir}/rust-node" --config "${work_dir}/rust.toml"
rust_pid="${last_pid}"
wait_log "${controller_pid}" "${work_dir}/controller.log" "holding initial node configuration request"
if ip -n "${rust_ns}" link show lane0 >/dev/null 2>&1; then
  echo "ERROR: Rust node created lane0 before its initial NodeConfiguration" >&2
  exit 1
fi
wait_log "${controller_pid}" "${work_dir}/controller.log" "node configuration response status=200"
wait_log "${rust_pid}" "${work_dir}/rust.log" "native Rust Laneway agent started"
for _ in $(seq 1 120); do
  if ip -n "${rust_ns}" -4 address show dev lane0 2>/dev/null | grep -q "${rust_address}/32"; then
    break
  fi
  sleep 0.05
done
ip -n "${rust_ns}" -4 address show dev lane0 | grep -q "${rust_address}/32"
if [[ "$(ip -n "${rust_ns}" -o -4 address show dev lane0 | wc -l)" != "1" ]]; then
  echo "ERROR: Rust node applied an address outside its controller assignment" >&2
  ip -n "${rust_ns}" address show dev lane0 >&2
  exit 1
fi

start_process "${relay_ns}" "${work_dir}/relay.log" "${work_dir}/laneway-relay" \
  -config "${work_dir}/relay.toml" -diagnostics 127.0.0.1:6060
relay_pid="${last_pid}"
wait_log "${relay_pid}" "${work_dir}/relay.log" "listening"
start_process "${gateway_ns}" "${work_dir}/gateway.log" "${work_dir}/lanewayd" \
  -config "${work_dir}/gateway.toml" -diagnostics 127.0.0.1:6061
gateway_pid="${last_pid}"
wait_log "${gateway_pid}" "${work_dir}/gateway.log" "interface=lane0"
wait_relay_sessions 2

echo "==> approved route mutation is installed transactionally and carries a real packet"
if ip -n "${rust_ns}" route show exact 192.168.77.0/24 | grep -q .; then
  echo "ERROR: Rust node installed the unapproved subnet route" >&2
  exit 1
fi
route_json="$(ip netns exec "${gateway_ns}" "${work_dir}/laneway" route advertise 192.168.77.0/24 \
  --kind subnet --mode nat --controller "${controller_endpoint}" --ca "${work_dir}/pki/ca.crt" \
  --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
  --cert "${work_dir}/pki/gateway.crt" --key "${work_dir}/pki/gateway.key")"
route_id="$(printf '%s\n' "${route_json}" | json_string_field route_id)"
if [[ ! "${route_id}" =~ ^[0-9a-f]{32}$ ]]; then
  echo "ERROR: failed to parse advertised route ID" >&2
  exit 1
fi
ip netns exec "${controller_ns}" "${work_dir}/laneway" controller route approve \
  --route-id "${route_id}" "${admin_connection[@]}" >"${work_dir}/route-approval.json"
wait_route "${rust_ns}" 192.168.77.0/24 1
for _ in $(seq 1 200); do
  if ip netns exec "${gateway_ns}" nft list table inet laneway 2>/dev/null | grep -q '192.168.77.0/24' && \
     [[ "$(ip netns exec "${gateway_ns}" sysctl -n net.ipv4.ip_forward)" == "1" ]]; then
    break
  fi
  sleep 0.05
done
ip netns exec "${gateway_ns}" nft list table inet laneway | grep -q '192.168.77.0/24'
udp_success 9701 rust-route-allowed

echo "==> deleting the only ACL rule leaves the route present but fails traffic closed"
ip netns exec "${controller_ns}" "${work_dir}/laneway" controller acl delete \
  --rule-id "${acl_id}" "${admin_connection[@]}" >"${work_dir}/acl-delete.json"
sleep 0.6
ip -n "${rust_ns}" route show exact 192.168.77.0/24 | grep -q 'dev lane0'
udp_denied 9702 rust-acl-denied

echo "==> an explicit replacement ACL restores the same authorized route"
replacement_acl="$(ip netns exec "${controller_ns}" "${work_dir}/laneway" controller acl add \
  --network-id "${network_id}" --priority 100 --action accept \
  --selector '{"ip_protocol":"IP_PROTOCOL_ANY"}' --description rust-live-restored \
  "${admin_connection[@]}")"
replacement_acl_id="$(printf '%s\n' "${replacement_acl}" | json_string_field rule_id)"
if [[ ! "${replacement_acl_id}" =~ ^[0-9a-f]{32}$ ]]; then
  echo "ERROR: replacement ACL was not created" >&2
  exit 1
fi
udp_success 9703 rust-acl-restored

echo "==> certificate revocation closes the established gateway path"
gateway_info="$("${work_dir}/netprobe" certificate-info -cert "${work_dir}/pki/gateway.crt")"
gateway_serial="$(printf '%s\n' "${gateway_info}" | sed -n 's/.* serial=\([0-9a-f]*\)$/\1/p')"
if [[ ! "${gateway_serial}" =~ ^[0-9a-f]{2,64}$ ]]; then
  echo "ERROR: failed to extract the gateway certificate serial" >&2
  exit 1
fi
ip netns exec "${controller_ns}" "${work_dir}/laneway" controller certificate revoke \
  --network-id "${network_id}" --serial "${gateway_serial}" --reason rust-live-revoke \
  "${admin_connection[@]}" >"${work_dir}/certificate-revocation.json"
wait_relay_sessions 1
ip -n "${rust_ns}" route show exact 192.168.77.0/24 | grep -q 'dev lane0'
udp_denied 9704 rust-revoked-path

echo "==> controller outage expires the last bounded lease and removes native authority"
stop_process "${controller_pid}"
for _ in $(seq 1 160); do
  address_present=0
  route_present=0
  if ip -n "${rust_ns}" -4 address show dev lane0 2>/dev/null | grep -q "${rust_address}/32"; then
    address_present=1
  fi
  if ip -n "${rust_ns}" route show exact 192.168.77.0/24 2>/dev/null | grep -q .; then
    route_present=1
  fi
  if [[ "${address_present}" == "0" && "${route_present}" == "0" ]]; then
    break
  fi
  sleep 0.05
done
if ! kill -0 "${rust_pid}" >/dev/null 2>&1; then
  echo "ERROR: Rust node exited instead of remaining fail-closed for controller recovery" >&2
  sed -n '1,320p' "${work_dir}/rust.log" >&2
  exit 1
fi
if ip -n "${rust_ns}" -4 address show dev lane0 2>/dev/null | grep -q "${rust_address}/32" || \
   ip -n "${rust_ns}" route show exact 192.168.77.0/24 2>/dev/null | grep -q .; then
  echo "ERROR: expired controller lease retained Rust native address or route authority" >&2
  ip -n "${rust_ns}" address show dev lane0 >&2 || true
  ip -n "${rust_ns}" route show >&2 || true
  sed -n '1,320p' "${work_dir}/rust.log" >&2
  exit 1
fi
grep -q 'authority expired' "${work_dir}/rust.log"

stop_process "${gateway_pid}"
stop_process "${relay_pid}"
stop_process "${rust_pid}"
echo "PASS: real Go controller drove Rust-node bootstrap, route/ACL mutation, revocation, and outage expiry"
