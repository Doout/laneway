#!/usr/bin/env bash
set -euo pipefail

if [[ "${LANEWAY_RUN_PRIVILEGED:-0}" != "1" ]]; then
  echo "SKIP: set LANEWAY_RUN_PRIVILEGED=1 to run the controller/Rust-node gate"
  exit 0
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "ERROR: the controller/Rust-node gate requires root" >&2
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
node_controller="${LANEWAY_NODE_TEST_CONTROLLER:-go}"
test_durable_exit="${LANEWAY_NODE_TEST_DURABLE_EXIT:-0}"
test_wireguard="${LANEWAY_NODE_TEST_WIREGUARD:-0}"
case "${node_controller}" in go|rust) ;; *) echo "Expected go or rust controller" >&2; exit 1 ;; esac

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
    local process_state=""
    if [[ -r "/proc/${pid}/stat" ]]; then
      process_state="$(sed -n 's/^.*) \([A-Z]\) .*/\1/p' "/proc/${pid}/stat" 2>/dev/null || true)"
    fi
    if ! kill -0 "${pid}" >/dev/null 2>&1 || [[ "${process_state}" == "Z" ]]; then
      wait "${pid}" >/dev/null 2>&1 || true
      unset "active_processes[${pid}]"
      return 0
    fi
    sleep 0.05
  done
  kill -KILL "${pid}" >/dev/null 2>&1 || true
  wait "${pid}" >/dev/null 2>&1 || true
  unset "active_processes[${pid}]"
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
  go build -o "${work_dir}/lanewayd" ./cmd/laneway
  go build -o "${work_dir}/laneway-relay" ./cmd/laneway-relay
  go build -o "${work_dir}/netprobe" ./integration/netprobe
  go build -o "${work_dir}/rustnodecontroller" ./integration/rustnodecontroller
)
cargo build --quiet --locked --manifest-path "${repo_root}/rust/Cargo.toml" -p lanewayd-rs -p laneway-healthcheck
cp "${repo_root}/rust/target/debug/lanewayd-rs" "${work_dir}/rust-node"
if [[ "${node_controller}" == "rust" ]]; then
  cargo build --quiet --locked --manifest-path "${repo_root}/rust/Cargo.toml" -p laneway-controller -p laneway-relay
  cp "${repo_root}/rust/target/debug/laneway-controller" "${work_dir}/rust-controller"
  cp "${repo_root}/rust/target/debug/laneway-relay" "${work_dir}/rust-relay"
fi

network_id="21000000000000000000000000000001"
controller_service="21000000000000000000000000000002"
relay_service="21000000000000000000000000000003"
controller_endpoint="https://10.254.0.1:8443"
controller_quic_endpoint="10.254.0.1:8443"
admin_token="laneway-rust-controller-integration-admin-token-00000001"
printf '%s\n' "${admin_token}" >"${work_dir}/admin.token"
chmod 600 "${work_dir}/admin.token"
"${work_dir}/laneway" pki init -out-dir "${work_dir}/pki" >/dev/null
# These public-looking addresses exist only on the disconnected lab bridge.
# The existing MaxMind test fixture resolves the node address to London.
location_controller_ip="81.2.69.141"
location_node_ip="81.2.69.142"
location_fixture="${repo_root}/go/internal/nodelocation/testdata/GeoIP2-City-Test.mmdb"
"${work_dir}/laneway" pki controller \
  -ca-cert "${work_dir}/pki/ca.crt" -ca-key "${work_dir}/pki/ca.key" \
  -network-id "${network_id}" -service-id "${controller_service}" -ip "10.254.0.1,127.0.0.1,${location_controller_ip}" \
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
if [[ "${test_wireguard}" != "1" ]]; then
  controller_command+=(-first-enrollment-validity 30s)
fi
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
rust_role=()
if [[ "${test_wireguard}" == "1" ]]; then
  rust_role=(--class ephemeral --session-lifetime 10m --exit-node --requested-name rust-controller-node)
fi
rust_token_json="$(ip netns exec "${controller_ns}" "${work_dir}/laneway" controller enrollment-token issue \
  --network-id "${network_id}" --label rust-node --expires-in 10m "${rust_role[@]}" "${admin_connection[@]}")"
gateway_token_json="$(ip netns exec "${controller_ns}" "${work_dir}/laneway" controller enrollment-token issue \
  --network-id "${network_id}" --label gateway --expires-in 10m "${admin_connection[@]}")"
rust_token="$(printf '%s\n' "${rust_token_json}" | json_string_field enrollment_token)"
gateway_token="$(printf '%s\n' "${gateway_token_json}" | json_string_field enrollment_token)"
if [[ -z "${rust_token}" || -z "${gateway_token}" ]]; then
  echo "ERROR: controller enrollment tokens were not returned" >&2
  exit 1
fi
printf '%s\n' "${rust_token}" >"${work_dir}/rust.token"
printf '%s\n' "${gateway_token}" >"${work_dir}/gateway.token"
chmod 0600 "${work_dir}/rust.token" "${work_dir}/gateway.token"

if [[ "${test_wireguard}" == "1" ]]; then
  rust_join="$(ip netns exec "${rust_ns}" "${work_dir}/netprobe" enroll-exit --token-file "${work_dir}/rust.token" \
    --controller "${controller_endpoint}" --ca "${work_dir}/pki/ca.crt" \
    --network-id "${network_id}" --service-id "${controller_service}" \
    --name rust-controller-node --out-prefix "${work_dir}/pki/rust")"
else
  rust_join="$(ip netns exec "${rust_ns}" "${work_dir}/laneway" join --token-file "${work_dir}/rust.token" \
    --controller "${controller_endpoint}" --ca "${work_dir}/pki/ca.crt" \
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
    --name rust-controller-node --out-cert "${work_dir}/pki/rust.crt" --out-key "${work_dir}/pki/rust.key" \
    --out-wireguard-key "${work_dir}/pki/rust.wireguard.key")"
fi
gateway_join="$(ip netns exec "${gateway_ns}" "${work_dir}/laneway" join --token-file "${work_dir}/gateway.token" \
  --controller "${controller_endpoint}" --ca "${work_dir}/pki/ca.crt" \
  --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
  --name go-gateway --out-cert "${work_dir}/pki/gateway.crt" --out-key "${work_dir}/pki/gateway.key" \
  --out-wireguard-key "${work_dir}/pki/gateway.wireguard.key")"
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
node_endpoint="${controller_endpoint}"
node_quic_endpoint="${controller_quic_endpoint}"
node_server_name="10.254.0.1"
gateway_endpoint="${node_endpoint}"
gateway_server_name="${node_server_name}"
native_controller_pid=""
relay_metrics=""
management_connection=("${admin_connection[@]}")
advertiser_namespace="${gateway_ns}"
advertiser_endpoint="${controller_endpoint}"
health_location=()
if [[ "${node_controller}" == "rust" ]]; then
  ip -n "${controller_ns}" address add "${location_controller_ip}/28" dev eth0
  ip -n "${rust_ns}" address add "${location_node_ip}/28" dev eth0
  ip -n "${relay_ns}" address add 81.2.69.140/28 dev eth0
  node_endpoint="https://${location_controller_ip}:9443"
  node_quic_endpoint="${location_controller_ip}:9443"
  node_server_name="${location_controller_ip}"
  health_location=(-public-ip "${location_node_ip}" -location "London, GB")
  relay_metrics='metrics_listen = "127.0.0.1:6060"'
  # Keep HTTPS loopback-only. Allow just the lab node's HTTPS connection to
  # reach that listener through TCP DNAT, without terminating its mTLS.
  # Node and relay still fetch control snapshots over QUIC.
  ip netns exec "${controller_ns}" sysctl -qw net.ipv4.conf.eth0.route_localnet=1
  ip netns exec "${controller_ns}" nft add table ip lab_health
  ip netns exec "${controller_ns}" nft add chain ip lab_health prerouting \
    '{ type nat hook prerouting priority dstnat; policy accept; }'
  ip netns exec "${controller_ns}" nft add rule ip lab_health prerouting \
    iifname eth0 ip saddr "${location_node_ip}" ip daddr "${location_controller_ip}" tcp dport 9443 dnat to 127.0.0.1:9443
  if [[ "${test_durable_exit}" == "1" ]]; then
    gateway_location_ip="81.2.69.139"
    ip -n "${gateway_ns}" address add "${gateway_location_ip}/28" dev eth0
    ip netns exec "${controller_ns}" nft add rule ip lab_health prerouting \
      iifname eth0 ip saddr "${gateway_location_ip}" ip daddr "${location_controller_ip}" tcp dport 9443 dnat to 127.0.0.1:9443
    gateway_endpoint="${node_endpoint}"
    gateway_server_name="${node_server_name}"
  fi
  start_process "${controller_ns}" "${work_dir}/native-controller.log" \
    "${work_dir}/rust-controller" serve "${work_dir}/controller.db" 127.0.0.1:9443 \
    "${work_dir}/pki/controller.crt" "${work_dir}/pki/controller.key" \
    --node-client-ca "${work_dir}/pki/ca.crt" --node-issuer "${work_dir}/pki/ca.crt" "${work_dir}/pki/ca.key" 3600 \
    --root-token-file "${work_dir}/admin.token" \
    --node-quic --quic-listen "${node_quic_endpoint}" --snapshot-validity 2 \
    --location-database "${location_fixture}"
  native_controller_pid="${last_pid}"
  wait_log "${native_controller_pid}" "${work_dir}/native-controller.log" "listening quic://${node_quic_endpoint}"
  advertiser_namespace="${controller_ns}"
  advertiser_endpoint="https://127.0.0.1:9443"
  management_connection=(
    --controller "${advertiser_endpoint}" --ca "${work_dir}/pki/ca.crt"
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}"
    --admin-token-file "${work_dir}/admin.token"
  )
fi

relay_registration="$(ip netns exec "${controller_ns}" "${work_dir}/laneway" controller relay register \
  --network-id "${network_id}" --service-id "${relay_service}" \
  --name rust-live-relay --endpoint 10.254.0.2:4433 "${management_connection[@]}")"
relay_id="$(printf '%s\n' "${relay_registration}" | json_string_field relay_id)"
if [[ ! "${relay_id}" =~ ^[0-9a-f]{32}$ ]]; then
  echo "ERROR: failed to parse registered relay ID" >&2
  exit 1
fi

ip netns exec "${controller_ns}" "${work_dir}/laneway" controller node capabilities \
  --node-id "${gateway_id}" --subnet-router "${management_connection[@]}" >"${work_dir}/capabilities.json"

acl_json="$(ip netns exec "${controller_ns}" "${work_dir}/laneway" controller acl add \
  --network-id "${network_id}" --priority 100 --action accept \
  --selector '{"ip_protocol":"IP_PROTOCOL_ANY"}' --description rust-live-allow \
  "${management_connection[@]}")"
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
${relay_metrics}
[controller]
endpoint = "${node_endpoint}"
quic_endpoint = "${node_quic_endpoint}"
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
# This gate asserts relay forwarding. The mixed-node gate covers direct paths.
[direct]
enabled = false
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
auto_renew_certificate = true
endpoint = "${node_endpoint}"
quic_endpoint = "${node_quic_endpoint}"
server_name = "${node_server_name}"
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
[forwarding.exit_client]
authorized = true
failure_mode = "closed"
EOF

if [[ "${test_wireguard}" == "1" ]]; then
  command -v wg >/dev/null || { echo "ERROR: wireguard-tools is required" >&2; exit 1; }
  fixture_binary="$(cargo test --locked --manifest-path "${repo_root}/rust/Cargo.toml" \
    -p lanewayd-rs --test wireguard_packet_lab --no-run --message-format=json |
    jq -ser '[.[] | select(.target.name=="wireguard_packet_lab" and .executable!=null) | .executable]
      | if length==1 then .[0] else error("expected one WireGuard test executable") end')"
  cat >>"${work_dir}/relay.toml" <<'EOF'
[tcp_fallback]
listen = "10.254.0.2:4435"
EOF
  if [[ "${node_controller}" == "rust" ]]; then
    start_process "${relay_ns}" "${work_dir}/relay.log" "${work_dir}/rust-relay" --config "${work_dir}/relay.toml"
    relay_ready="listening"
  else
    start_process "${relay_ns}" "${work_dir}/relay.log" "${work_dir}/laneway-relay" \
      -config "${work_dir}/relay.toml" -diagnostics 127.0.0.1:6060
    relay_ready="TCP-fallback="
  fi
  wait_log "${last_pid}" "${work_dir}/relay.log" "${relay_ready}"
  sed '/^advertise = /d' "${work_dir}/gateway.toml" >"${work_dir}/wg-go.toml"
  cat >>"${work_dir}/wg-go.toml" <<EOF
[wireguard]
enabled = true
private_key = "${work_dir}/pki/gateway.wireguard.key"
interface = "lane0"
mtu = 1280
EOF
  start_process "${gateway_ns}" "${work_dir}/gateway.log" "${work_dir}/lanewayd" \
    -config "${work_dir}/wg-go.toml"
  wait_log "${last_pid}" "${work_dir}/gateway.log" "interface=lane0"

  rust_key="$(base64 -w0 <"${work_dir}/pki/rust.wireguard.key" | wg pubkey)"
  gateway_key="$(base64 -w0 <"${work_dir}/pki/gateway.wireguard.key" | wg pubkey)"
  rust_generation="$(sed -n 's/.* generation=\([0-9]\+\)$/\1/p' <<<"${rust_join}")"
  [[ "${rust_generation}" =~ ^[1-9][0-9]*$ ]]
  ip -n "${rust_ns}" link add dev lane0 type wireguard
  base64 -w0 <"${work_dir}/pki/rust.wireguard.key" | ip netns exec "${rust_ns}" wg set lane0 \
    private-key /dev/stdin listen-port 57001 peer "${gateway_key}" \
    allowed-ips "${gateway_overlay}" endpoint 127.0.0.1:57002
  ip -n "${rust_ns}" addr add "${rust_overlay}" dev lane0
  ip -n "${rust_ns}" link set dev lane0 mtu 1280 up
  ip -n "${rust_ns}" route add "${gateway_overlay}" dev lane0
  cat >>"${work_dir}/rust.toml" <<'EOF'
[tcp_fallback]
address = "10.254.0.2:4435"
EOF

  for transport in quic tcp; do
    if [[ "${transport}" == tcp ]]; then
      ip netns exec "${rust_ns}" nft add table inet lab_block_relay
      ip netns exec "${rust_ns}" nft add chain inet lab_block_relay output '{ type filter hook output priority 0; policy accept; }'
      ip netns exec "${rust_ns}" nft add rule inet lab_block_relay output udp dport 4433 drop
      connected="Rust agent relay TCP fallback connected"
    else
      connected="Rust agent relay connected"
    fi
    echo "==> kernel WireGuard packets cross the ${node_controller} relay over ${transport}"
    start_process "${rust_ns}" "${work_dir}/wg-rust-${transport}.log" env RUST_LOG=info \
      LANEWAY_WG_CONFIG="${work_dir}/rust.toml" LANEWAY_WG_LOCAL_PUBLIC="${rust_key}" \
      LANEWAY_WG_PEER_PUBLIC="${gateway_key}" LANEWAY_WG_PEER_ID="${gateway_id}" \
      LANEWAY_WG_EXIT_GENERATION="${rust_generation}" \
      "${fixture_binary}" --ignored --exact --nocapture kernel_relay_bridge
    bridge_pid="${last_pid}"
    wait_log "${bridge_pid}" "${work_dir}/wg-rust-${transport}.log" "${connected}"
    wait_relay_sessions 2
    start_process "${gateway_ns}" "${work_dir}/wg-probe-${transport}.log" \
      "${work_dir}/netprobe" udp-echo-server -listen "${gateway_address}:9791"
    echo_pid="${last_pid}"
    wait_log "${echo_pid}" "${work_dir}/wg-probe-${transport}.log" "ready=udp-echo-server"
    for _ in $(seq 1 12); do
      if ip netns exec "${rust_ns}" "${work_dir}/netprobe" udp-client \
        -target "${gateway_address}:9791" -message "wireguard-${transport}" -timeout 1s; then break; fi
    done
    ip netns exec "${rust_ns}" "${work_dir}/netprobe" udp-client \
      -target "${gateway_address}:9791" -message "wireguard-${transport}-verified" -timeout 5s
    if [[ "${transport}" == tcp ]]; then
      # A 1280-byte inner IPv4 packet produces 1312 bytes of ciphertext,
      # which must not hit the legacy 1280-byte raw-IP record ceiling.
      printf -v full_payload '%01252d' 0
      ip netns exec "${rust_ns}" "${work_dir}/netprobe" udp-client \
        -target "${gateway_address}:9791" -message "${full_payload}" -timeout 5s >/dev/null
      echo "verified full-MTU WireGuard ciphertext over TCP"
      ip netns exec "${controller_ns}" "${work_dir}/laneway" controller node revoke \
        --node-id "${rust_id}" --reason wireguard-transport-lab "${management_connection[@]}" >/dev/null
      wait_log "${bridge_pid}" "${work_dir}/wg-rust-${transport}.log" "controller rejected node authority"
      if ip netns exec "${rust_ns}" "${work_dir}/netprobe" udp-client \
        -target "${gateway_address}:9791" -message revoked-wireguard -timeout 2s; then
        echo "ERROR: revoked ephemeral identity still exchanged kernel packets" >&2
        exit 1
      fi
    fi
    ip netns exec "${rust_ns}" wg show lane0 latest-handshakes | awk '$2 > 0 { found = 1 } END { exit !found }'
    stop_process "${echo_pid}"
    stop_process "${bridge_pid}"
    if [[ "${transport}" == quic ]]; then
      grep -Fq 'test kernel_relay_bridge ... ok' "${work_dir}/wg-rust-${transport}.log"
    fi
  done
  echo "PASS: the ephemeral Rust peer and durable Go peer exchange encrypted kernel traffic across the ${node_controller} relay"
  exit 0
fi

echo "==> Rust node bootstraps and renews its certificate at the ${node_controller} controller"
old_info="$("${work_dir}/netprobe" certificate-info -cert "${work_dir}/pki/rust.crt")"
old_serial="${old_info##* serial=}"
[[ "${old_serial}" =~ ^[0-9a-f]{2,64}$ ]]
initial_key_hash="$(sha256sum "${work_dir}/pki/rust.key")"
start_process "${rust_ns}" "${work_dir}/rust.log" env RUST_LOG=info \
  "${work_dir}/rust-node" --config "${work_dir}/rust.toml"
rust_pid="${last_pid}"
if [[ "${node_controller}" == "go" ]]; then
  wait_log "${controller_pid}" "${work_dir}/controller.log" "holding initial node configuration request"
  if ip -n "${rust_ns}" link show lane0 >/dev/null 2>&1; then
    echo "ERROR: Rust node created lane0 before its initial NodeConfiguration" >&2
    exit 1
  fi
  wait_log "${controller_pid}" "${work_dir}/controller.log" "node configuration response status=200"
fi
wait_log "${rust_pid}" "${work_dir}/rust.log" "native Rust Laneway agent started"
wait_log "${rust_pid}" "${work_dir}/rust.log" "renewed node certificate; restarting authenticated connections"
for _ in $(seq 1 160); do
  if [[ "$(grep -c 'native Rust Laneway agent started' "${work_dir}/rust.log")" -ge 2 ]]; then break; fi
  sleep 0.05
done
if [[ "$(grep -c 'native Rust Laneway agent started' "${work_dir}/rust.log")" -lt 2 ]]; then
  echo "ERROR: renewed credentials were not loaded into the Rust node" >&2
  tail -25 "${work_dir}/rust.log" >&2
  exit 1
fi
new_info="$("${work_dir}/netprobe" certificate-info -cert "${work_dir}/pki/rust.crt")"
[[ "${new_info% serial=*}" == "${old_info% serial=*}" && "${new_info##* serial=}" != "${old_serial}" ]]
[[ "$(sha256sum "${work_dir}/pki/rust.key")" == "${initial_key_hash}" ]]
echo "==> revoking the superseded Rust certificate before testing routed traffic"
ip netns exec "${controller_ns}" "${work_dir}/laneway" controller certificate revoke \
  --network-id "${network_id}" --serial "${old_serial}" --reason rust-renewal-test \
  "${management_connection[@]}" >"${work_dir}/old-certificate-revocation.json"
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

if [[ "${node_controller}" == "rust" ]]; then
  start_process "${relay_ns}" "${work_dir}/relay.log" "${work_dir}/rust-relay" --config "${work_dir}/relay.toml"
else
  start_process "${relay_ns}" "${work_dir}/relay.log" "${work_dir}/laneway-relay" \
    -config "${work_dir}/relay.toml" -diagnostics 127.0.0.1:6060
fi
relay_pid="${last_pid}"
wait_log "${relay_pid}" "${work_dir}/relay.log" "listening"
if [[ "${test_durable_exit}" == "1" ]]; then
  ip netns exec "${controller_ns}" "${work_dir}/laneway" controller node capabilities \
    --node-id "${gateway_id}" --exit-node "${management_connection[@]}" >"${work_dir}/exit-capability.json"
  cat >"${work_dir}/rust-gateway.toml" <<EOF
mode = "node"
socket_path = "${work_dir}/rust-gateway.sock"
[identity]
network_id = "${network_id}"
node_id = "${gateway_id}"
[tls]
certificate = "${work_dir}/pki/gateway.crt"
private_key = "${work_dir}/pki/gateway.key"
ca = "${work_dir}/pki/ca.crt"
[controller]
endpoint = "${gateway_endpoint}"
quic_endpoint = "${node_quic_endpoint}"
server_name = "${gateway_server_name}"
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
[forwarding]
exit_gateway = true
exit_gateway_controller_sources = true
exit_output_interface = "lan1"
EOF
  echo "==> Rust durable exit boots before approval and leaves the host unchanged"
  start_process "${gateway_ns}" "${work_dir}/rust-gateway.log" env RUST_LOG=info \
    "${work_dir}/rust-node" --config "${work_dir}/rust-gateway.toml"
  gateway_pid="${last_pid}"
  wait_log "${gateway_pid}" "${work_dir}/rust-gateway.log" "native Rust Laneway agent started"
  wait_relay_sessions 2
  gateway_table() {
    ip netns exec "${gateway_ns}" nft list table inet laneway_rs_exit
  }
  gateway_forwarding() {
    ip netns exec "${gateway_ns}" sysctl -n net.ipv4.ip_forward
  }
  assert_gateway_inactive() {
    if gateway_table >/dev/null 2>&1 || [[ "$(gateway_forwarding)" != "0" ]]; then
      echo "ERROR: inactive exit left forwarding state installed" >&2
      return 1
    fi
  }
  gateway_connection=(
    --controller "${advertiser_endpoint}" --ca "${work_dir}/pki/ca.crt"
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}"
    --cert "${work_dir}/pki/gateway.crt" --key "${work_dir}/pki/gateway.key"
  )
  approve_exit() {
    local response
    response="$(ip netns exec "${advertiser_namespace}" "${work_dir}/laneway" route advertise 0.0.0.0/0 \
      --kind exit --mode nat "${gateway_connection[@]}")"
    exit_route_id="$(printf '%s\n' "${response}" | json_string_field route_id)"
    [[ "${exit_route_id}" =~ ^[0-9a-f]{32}$ ]]
    ip netns exec "${controller_ns}" "${work_dir}/laneway" controller route approve \
      --route-id "${exit_route_id}" "${management_connection[@]}" >"${work_dir}/exit-approval.json"
    for _ in $(seq 1 200); do
      if gateway_table 2>/dev/null | grep -Fq "ip saddr ${rust_address}"; then
        break
      fi
      sleep 0.05
    done
    gateway_table | grep -Fq "ip saddr ${rust_address}"
    gateway_table | grep -Fq 'laneway-rust-exit-denied'
    [[ "$(gateway_forwarding)" == "1" ]]
  }
  assert_gateway_inactive
  if "${work_dir}/laneway" exit use "${gateway_id}" --socket "${work_dir}/rust.sock" >/dev/null 2>&1; then
    echo "ERROR: an unapproved exit was selected" >&2
    exit 1
  fi
  echo "==> approval installs a scoped NAT exit and forwards real overlay traffic"
  approve_exit
  for _ in $(seq 1 120); do
    if "${work_dir}/laneway" exit use "${gateway_id}" --socket "${work_dir}/rust.sock" >"${work_dir}/exit-selection.log" 2>&1; then
      break
    fi
    sleep 0.05
  done
  grep -q 'selected exit node' "${work_dir}/exit-selection.log"
  udp_success 9721 rust-exit-approved
  echo "==> withdrawal removes outgoing NAT and restores the host forwarding baseline"
  ip netns exec "${advertiser_namespace}" "${work_dir}/laneway" controller route withdraw \
    --route-id "${exit_route_id}" "${gateway_connection[@]}" >"${work_dir}/exit-withdrawal.json"
  for _ in $(seq 1 200); do
    if ! gateway_table >/dev/null 2>&1 && [[ "$(gateway_forwarding)" == "0" ]]; then
      break
    fi
    sleep 0.05
  done
  assert_gateway_inactive
  udp_denied 9722 rust-exit-withdrawn
  echo "==> re-approval restores forwarding without restarting either Rust process"
  approve_exit
  udp_success 9723 rust-exit-restored
  kill -0 "${rust_pid}" "${gateway_pid}"
  stop_process "${gateway_pid}"
  assert_gateway_inactive
  if ip -n "${gateway_ns}" link show lane0 >/dev/null 2>&1; then
    echo "ERROR: gateway left a TUN device after shutdown" >&2
    exit 1
  fi
  echo "PASS: durable Rust exit forwards only while approved by the ${node_controller} controller"
  exit 0
fi
start_process "${gateway_ns}" "${work_dir}/gateway.log" "${work_dir}/lanewayd" \
  -config "${work_dir}/gateway.toml" -diagnostics 127.0.0.1:6061
gateway_pid="${last_pid}"
wait_log "${gateway_pid}" "${work_dir}/gateway.log" "interface=lane0"
wait_relay_sessions 2
"${repo_root}/rust/target/debug/laneway-healthcheck" -unix "${work_dir}/rust.sock"

echo "==> approved route mutation is installed transactionally and carries a real packet"
if ip -n "${rust_ns}" route show exact 192.168.77.0/24 | grep -q .; then
  echo "ERROR: Rust node installed the unapproved subnet route" >&2
  exit 1
fi
route_json="$(ip netns exec "${advertiser_namespace}" "${work_dir}/laneway" route advertise 192.168.77.0/24 \
  --kind subnet --mode nat --controller "${advertiser_endpoint}" --ca "${work_dir}/pki/ca.crt" \
  --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
  --cert "${work_dir}/pki/gateway.crt" --key "${work_dir}/pki/gateway.key")"
route_id="$(printf '%s\n' "${route_json}" | json_string_field route_id)"
if [[ ! "${route_id}" =~ ^[0-9a-f]{32}$ ]]; then
  echo "ERROR: failed to parse advertised route ID" >&2
  exit 1
fi
wait_route "${rust_ns}" 192.168.77.0/24 0
ip netns exec "${controller_ns}" "${work_dir}/laneway" controller route approve \
  --route-id "${route_id}" "${management_connection[@]}" >"${work_dir}/route-approval.json"
wait_route "${rust_ns}" 192.168.77.0/24 1
for _ in $(seq 1 200); do
  if ip netns exec "${gateway_ns}" nft list table inet laneway 2>/dev/null | grep -q '192.168.77.0/24' && \
     [[ "$(ip netns exec "${gateway_ns}" sysctl -n net.ipv4.ip_forward)" == "1" ]]; then
    break
  fi
  sleep 0.05
done
ip netns exec "${gateway_ns}" nft list table inet laneway | grep -q '192.168.77.0/24'
relay_forwarded_packets() {
  ip netns exec "${relay_ns}" "${work_dir}/netprobe" metric \
    -url http://127.0.0.1:6060/metrics -name laneway_relay_forwarded_packets_total
}
if [[ "${node_controller}" == "rust" ]]; then
  forwarded_before="$(relay_forwarded_packets)"
fi
udp_success 9701 rust-route-allowed
if [[ "${node_controller}" == "rust" ]]; then
  forwarded_after="$(relay_forwarded_packets)"
  if (( forwarded_after < forwarded_before + 2 )); then
    echo "ERROR: the request and reply did not use the Rust relay" >&2
    exit 1
  fi
fi

echo "==> live Rust node reports its authenticated carrier and routes; the controller observes its source"
reported_carrier=""
for _ in $(seq 1 150); do
  reported_carrier="$("${work_dir}/netprobe" endpoint-health -database "${work_dir}/controller.db" \
    -node-id "${rust_id}" "${health_location[@]}" 2>/dev/null || true)"
  if [[ "${reported_carrier}" == "relay_quic" ]]; then
    break
  fi
  sleep 0.1
done
if [[ "${reported_carrier}" != "relay_quic" ]]; then
  echo "ERROR: controller did not receive current Rust node relay health" >&2
  tail -70 "${work_dir}/rust.log" >&2
  exit 1
fi

if [[ "${node_controller}" == "rust" ]]; then
  echo "==> disabling the relay closes live sessions and stops forwarding"
  ip netns exec "${controller_ns}" "${work_dir}/laneway" controller relay disable \
    --relay-id "${relay_id}" "${management_connection[@]}" >"${work_dir}/relay-disable.json"
  wait_relay_sessions 0
  udp_denied 9709 rust-relay-disabled

  echo "==> updating the relay to enabled restores sessions and traffic without a restart"
  ip netns exec "${controller_ns}" "${work_dir}/laneway" controller relay update \
    --relay-id "${relay_id}" --name rust-live-relay-restored --endpoint 10.254.0.2:4433 \
    --enabled "${management_connection[@]}" >"${work_dir}/relay-update.json"
  wait_relay_sessions 2
  wait_route "${rust_ns}" 192.168.77.0/24 1
  udp_success 9710 rust-relay-restored
fi

echo "==> deleting the only ACL rule leaves the route present but fails traffic closed"
ip netns exec "${controller_ns}" "${work_dir}/laneway" controller acl delete \
  --rule-id "${acl_id}" "${management_connection[@]}" >"${work_dir}/acl-delete.json"
sleep 0.6
ip -n "${rust_ns}" route show exact 192.168.77.0/24 | grep -q 'dev lane0'
udp_denied 9702 rust-acl-denied

echo "==> an explicit replacement ACL restores the same authorized route"
replacement_acl="$(ip netns exec "${controller_ns}" "${work_dir}/laneway" controller acl add \
  --network-id "${network_id}" --priority 100 --action accept \
  --selector '{"ip_protocol":"IP_PROTOCOL_ANY"}' --description rust-live-restored \
  "${management_connection[@]}")"
replacement_acl_id="$(printf '%s\n' "${replacement_acl}" | json_string_field rule_id)"
if [[ ! "${replacement_acl_id}" =~ ^[0-9a-f]{32}$ ]]; then
  echo "ERROR: replacement ACL was not created" >&2
  exit 1
fi
udp_success 9703 rust-acl-restored

if [[ "${node_controller}" == "rust" ]]; then
  rust_workload_connection=(
    --controller "${advertiser_endpoint}" --ca "${work_dir}/pki/ca.crt"
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}"
    --cert "${work_dir}/pki/rust.crt" --key "${work_dir}/pki/rust.key"
  )
  if ip netns exec "${advertiser_namespace}" "${work_dir}/laneway" controller route withdraw \
    --route-id "${route_id}" "${rust_workload_connection[@]}" >"${work_dir}/foreign-withdrawal.log" 2>&1; then
    echo "ERROR: a different node withdrew the gateway's route" >&2
    exit 1
  fi
  grep -q 'ERROR_CODE_PERMISSION_DENIED' "${work_dir}/foreign-withdrawal.log"
  if ip netns exec "${advertiser_namespace}" "${work_dir}/laneway" route advertise 192.0.2.0/24 \
    --kind subnet --mode nat "${rust_workload_connection[@]}" >"${work_dir}/unprivileged-advertisement.log" 2>&1; then
    echo "ERROR: a node without subnet-router capability advertised a route" >&2
    exit 1
  fi
  grep -q 'node lacks route capability' "${work_dir}/unprivileged-advertisement.log"
  echo "==> a route owner withdraws through Rust; the route disappears and packets stop"
  ip netns exec "${advertiser_namespace}" "${work_dir}/laneway" controller route withdraw \
    --route-id "${route_id}" --controller "${advertiser_endpoint}" --ca "${work_dir}/pki/ca.crt" \
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
    --cert "${work_dir}/pki/gateway.crt" --key "${work_dir}/pki/gateway.key" >"${work_dir}/route-withdrawal.json"
  wait_route "${rust_ns}" 192.168.77.0/24 0
  udp_denied 9705 rust-route-withdrawn

  echo "==> assigning the same subnet through Rust reinstalls it and restores traffic"
  ip netns exec "${controller_ns}" "${work_dir}/laneway" controller route assign \
    --network-id "${network_id}" --connector "${gateway_id}" --to 192.168.77.0/24 \
    "${management_connection[@]}" >"${work_dir}/route-assignment.json"
  wait_route "${rust_ns}" 192.168.77.0/24 1
  udp_success 9706 rust-route-reassigned

  echo "==> removing the router capability withdraws its route and stops traffic"
  ip netns exec "${controller_ns}" "${work_dir}/laneway" controller node capabilities \
    --node-id "${gateway_id}" "${management_connection[@]}" >"${work_dir}/capability-removal.json"
  wait_route "${rust_ns}" 192.168.77.0/24 0
  udp_denied 9707 rust-capability-removed
  ip netns exec "${controller_ns}" "${work_dir}/laneway" controller route assign \
    --network-id "${network_id}" --connector "${gateway_id}" --to 192.168.77.0/24 \
    "${management_connection[@]}" >"${work_dir}/route-restoration.json"
  wait_route "${rust_ns}" 192.168.77.0/24 1
  udp_success 9708 rust-capability-restored
fi

echo "==> certificate revocation closes the established gateway path"
gateway_info="$("${work_dir}/netprobe" certificate-info -cert "${work_dir}/pki/gateway.crt")"
gateway_serial="$(printf '%s\n' "${gateway_info}" | sed -n 's/.* serial=\([0-9a-f]*\)$/\1/p')"
if [[ ! "${gateway_serial}" =~ ^[0-9a-f]{2,64}$ ]]; then
  echo "ERROR: failed to extract the gateway certificate serial" >&2
  exit 1
fi
ip netns exec "${controller_ns}" "${work_dir}/laneway" controller certificate revoke \
  --network-id "${network_id}" --serial "${gateway_serial}" --reason rust-live-revoke \
  "${management_connection[@]}" >"${work_dir}/certificate-revocation.json"
wait_relay_sessions 1
ip -n "${rust_ns}" route show exact 192.168.77.0/24 | grep -q 'dev lane0'
udp_denied 9704 rust-revoked-path

echo "==> controller outage expires the last bounded lease and removes native authority"
if [[ -n "${native_controller_pid}" ]]; then
  stop_process "${native_controller_pid}"
else
  # ip netns exec may retain a parent wrapper on some iproute2 versions.
  # Signal only processes in this disposable controller namespace.
  while read -r namespace_pid; do
    if [[ -n "${namespace_pid}" ]]; then
      kill -KILL "${namespace_pid}" >/dev/null 2>&1 || true
    fi
  done < <(ip netns pids "${controller_ns}")
  kill -KILL "${controller_pid}" >/dev/null 2>&1 || true
  wait "${controller_pid}" >/dev/null 2>&1 || true
  unset "active_processes[${controller_pid}]"
fi
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
if [[ "${node_controller}" == "rust" ]]; then
  wait_relay_sessions 0
  kill -0 "${relay_pid}"
fi

stop_process "${gateway_pid}"
stop_process "${relay_pid}"
stop_process "${rust_pid}"
echo "PASS: ${node_controller} controller drove Rust-node bootstrap, route/ACL mutation, revocation, and outage expiry"
