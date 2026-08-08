#!/usr/bin/env bash
set -euo pipefail

if [[ "${LANEWAY_RUN_PRIVILEGED:-0}" != "1" ]]; then
  echo "SKIP: set LANEWAY_RUN_PRIVILEGED=1 to run full-stack namespace tests"
  exit 0
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "ERROR: full-stack namespace tests require root" >&2
  exit 1
fi

work_dir="${LANEWAY_INTEGRATION_WORK_DIR:-$(mktemp -d -t laneway-fullstack.XXXXXX)}"
owns_work_dir=0
if [[ -z "${LANEWAY_INTEGRATION_WORK_DIR:-}" ]]; then
  owns_work_dir=1
fi
prefix="lw$$_"
declare -a namespaces=()
declare -a processes=()
declare -a netns_etc_dirs=()
netns_etc_parent_created=0
link_index=0
last_pid=""

if [[ -n "${LANEWAY_KERNEL_BENCHMARK_OUTPUT:-}" ]]; then
  if [[ "${LANEWAY_KERNEL_BENCHMARK_OUTPUT}" != /* ]]; then
    echo "ERROR: LANEWAY_KERNEL_BENCHMARK_OUTPUT must be an absolute path" >&2
    exit 1
  fi
  : >"${LANEWAY_KERNEL_BENCHMARK_OUTPUT}"
fi

cleanup() {
  for pid in "${processes[@]:-}"; do
    kill -TERM "${pid}" >/dev/null 2>&1 || true
  done
  for pid in "${processes[@]:-}"; do
    wait "${pid}" >/dev/null 2>&1 || true
  done
  for namespace in "${namespaces[@]:-}"; do
    ip netns delete "${namespace}" >/dev/null 2>&1 || true
  done
  for directory in "${netns_etc_dirs[@]:-}"; do
    rm -f -- "${directory}/hosts"
    rmdir -- "${directory}" >/dev/null 2>&1 || true
  done
  if [[ "${netns_etc_parent_created}" == "1" ]]; then
    rmdir -- /etc/netns >/dev/null 2>&1 || true
  fi
  if [[ "${owns_work_dir}" == "1" ]]; then
    rm -rf -- "${work_dir}"
  fi
}
trap cleanup EXIT INT TERM

for binary in laneway lanewayd laneway-relay laneway-controller netprobe; do
  if [[ ! -x "${work_dir}/${binary}" ]]; then
    echo "ERROR: missing integration binary ${work_dir}/${binary}" >&2
    exit 1
  fi
done

add_namespace() {
  local namespace="$1"
  ip netns add "${namespace}"
  namespaces+=("${namespace}")
  ip -n "${namespace}" link set lo up
}

set_namespace_host() {
  local namespace="$1" address="$2" hostname="$3"
  local directory="/etc/netns/${namespace}"
  if [[ -e "${directory}" ]]; then
    echo "ERROR: refusing to replace existing namespace configuration ${directory}" >&2
    return 1
  fi
  if [[ ! -d /etc/netns ]]; then
    mkdir -- /etc/netns
    netns_etc_parent_created=1
  fi
  mkdir -- "${directory}"
  netns_etc_dirs+=("${directory}")
  printf '127.0.0.1 localhost\n%s %s\n' "${address}" "${hostname}" >"${directory}/hosts"
  chmod 644 "${directory}/hosts"
}

add_switch() {
  local namespace="$1"
  add_namespace "${namespace}"
  ip -n "${namespace}" link add br0 type bridge
  ip -n "${namespace}" link set br0 up
}

attach_switch() {
  local switch="$1" target="$2" interface_name="$3" address="$4"
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

connect_namespaces() {
  local left="$1" left_interface="$2" left_address="$3"
  local right="$4" right_interface="$5" right_address="$6"
  link_index=$((link_index + 1))
  local left_end="l${link_index}x$$" right_end="r${link_index}x$$"
  ip link add "${left_end}" type veth peer name "${right_end}"
  ip link set "${left_end}" netns "${left}"
  ip link set "${right_end}" netns "${right}"
  ip -n "${left}" link set "${left_end}" name "${left_interface}"
  ip -n "${right}" link set "${right_end}" name "${right_interface}"
  ip -n "${left}" address add "${left_address}" dev "${left_interface}"
  ip -n "${right}" address add "${right_address}" dev "${right_interface}"
  ip -n "${left}" link set "${left_interface}" up
  ip -n "${right}" link set "${right_interface}" up
}

start_process() {
  local namespace="$1" log="$2"
  shift 2
  ip netns exec "${namespace}" "$@" >"${log}" 2>&1 &
  last_pid=$!
  processes+=("${last_pid}")
}

stop_process() {
  local pid="$1"
  kill -TERM "${pid}" >/dev/null 2>&1 || true
  for _ in $(seq 1 100); do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      wait "${pid}" >/dev/null 2>&1 || true
      return 0
    fi
    sleep 0.05
  done
  echo "ERROR: process ${pid} did not stop" >&2
  return 1
}

wait_log() {
  local pid="$1" log="$2" pattern="$3"
  for _ in $(seq 1 200); do
    if grep -q -- "${pattern}" "${log}" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      echo "ERROR: process ${pid} stopped before ${pattern}" >&2
      sed -n '1,240p' "${log}" >&2 || true
      return 1
    fi
    sleep 0.05
  done
  echo "ERROR: timed out waiting for ${pattern}" >&2
  sed -n '1,240p' "${log}" >&2 || true
  return 1
}

assert_foreground_network_clean() {
  local namespace="$1" log="$2" label="$3"
  for _ in $(seq 1 200); do
    if ! ip -n "${namespace}" link show lane0 >/dev/null 2>&1 && \
       ! ip -n "${namespace}" rule show | grep -q 'lookup 51820' && \
       ! ip -n "${namespace}" route show table 51820 2>/dev/null | grep -q . && \
       ! ip netns exec "${namespace}" pgrep -f '[l]aneway.*_network-helper' >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.05
  done
  echo "ERROR: foreground connect ${label} left temporary networking or helper state" >&2
  ip -n "${namespace}" link show >&2
  ip -n "${namespace}" rule show >&2
  ip -n "${namespace}" route show table 51820 >&2 2>/dev/null || true
  sed -n '1,260p' "${log}" >&2 || true
  return 1
}

wait_selected_path() {
  local namespace="$1" config="$2" expected="$3" pid="$4" log="$5"
  local selected=""
  for _ in $(seq 1 600); do
    selected="$(ip netns exec "${namespace}" "${work_dir}/laneway" status \
      --config "${config}" --json 2>/dev/null | json_string_field selected_path || true)"
    if [[ "${selected}" == "${expected}" ]]; then
      return 0
    fi
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      echo "ERROR: process ${pid} stopped while waiting for path ${expected}" >&2
      sed -n '1,260p' "${log}" >&2 || true
      return 1
    fi
    sleep 0.1
  done
  echo "ERROR: timed out waiting for path ${expected}; selected=${selected:-unknown}" >&2
  ip netns exec "${namespace}" "${work_dir}/laneway" status --config "${config}" --json >&2 || true
  sed -n '1,260p' "${log}" >&2 || true
  return 1
}

run_kernel_udp_benchmark() {
  local server_namespace="$1" client_namespace="$2" listen="$3" target="$4" scenario="$5" log="$6"
  if [[ -z "${LANEWAY_KERNEL_BENCHMARK_OUTPUT:-}" ]]; then
    return 0
  fi
  start_process "${server_namespace}" "${log}" "${work_dir}/netprobe" udp-echo-server -listen "${listen}"
  local benchmark_server_pid="${last_pid}"
  wait_log "${benchmark_server_pid}" "${log}" "ready=udp-echo-server"
  ip netns exec "${client_namespace}" "${work_dir}/netprobe" udp-bench-client \
    -target "${target}" -scenario "${scenario}" \
    -scope production-kernel-tun-routes-nat-nftables \
    -duration "${LANEWAY_KERNEL_BENCHMARK_DURATION:-1s}" \
    -pps "${LANEWAY_KERNEL_BENCHMARK_PPS:-1000}" \
    -flows "${LANEWAY_KERNEL_BENCHMARK_FLOWS:-1}" \
    -size "${LANEWAY_KERNEL_BENCHMARK_SIZE:-1200}" >>"${LANEWAY_KERNEL_BENCHMARK_OUTPUT}"
  stop_process "${benchmark_server_pid}"
}

issue_identity_set() {
  local directory="$1" relay_ip="$2" network_id="$3" node_a="$4" node_b="$5" service_id="$6"
  mkdir -p "${directory}"
  "${work_dir}/laneway" pki init -out-dir "${directory}" >/dev/null
  "${work_dir}/laneway" pki relay -ca-cert "${directory}/ca.crt" -ca-key "${directory}/ca.key" \
    -network-id "${network_id}" -service-id "${service_id}" -ip "${relay_ip}" \
    -out-cert "${directory}/relay.crt" -out-key "${directory}/relay.key"
  "${work_dir}/laneway" pki node -ca-cert "${directory}/ca.crt" -ca-key "${directory}/ca.key" \
    -network-id "${network_id}" -node-id "${node_a}" \
    -out-cert "${directory}/a.crt" -out-key "${directory}/a.key"
  "${work_dir}/laneway" pki node -ca-cert "${directory}/ca.crt" -ca-key "${directory}/ca.key" \
    -network-id "${network_id}" -node-id "${node_b}" \
    -out-cert "${directory}/b.crt" -out-key "${directory}/b.key"
}

network_id="00000000000000000000000000000001"
node_a_id="00000000000000000000000000000002"
node_b_id="00000000000000000000000000000003"
relay_id="00000000000000000000000000000004"

run_overlay_and_subnet() {
  local case_dir="${work_dir}/overlay-subnet"
  local switch="${prefix}os" relay="${prefix}or" node_a="${prefix}oa" node_b="${prefix}ob" lan_host="${prefix}oh"
  issue_identity_set "${case_dir}" "10.250.0.1" "${network_id}" "${node_a_id}" "${node_b_id}" "${relay_id}"
  add_switch "${switch}"
  add_namespace "${relay}"
  add_namespace "${node_a}"
  add_namespace "${node_b}"
  add_namespace "${lan_host}"
  attach_switch "${switch}" "${relay}" eth0 10.250.0.1/24
  attach_switch "${switch}" "${node_a}" eth0 10.250.0.2/24
  attach_switch "${switch}" "${node_b}" eth0 10.250.0.3/24
  connect_namespaces "${node_b}" lan1 192.168.50.1/24 "${lan_host}" eth0 192.168.50.2/24
  ip -n "${node_b}" -6 address add fd42:50::1/64 dev lan1 nodad
  ip -n "${lan_host}" -6 address add fd42:50::2/64 dev eth0 nodad

  cat >"${case_dir}/relay.toml" <<EOF
mode = "relay"
state_dir = "${case_dir}/relay-state"
socket_path = "${case_dir}/relay.sock"
[tls]
certificate = "${case_dir}/relay.crt"
private_key = "${case_dir}/relay.key"
ca = "${case_dir}/ca.crt"
[relay]
listen = "10.250.0.1:4433"
[[peers]]
network_id = "${network_id}"
node_id = "${node_a_id}"
prefixes = ["100.96.0.1/32", "fd42:96::1/128"]
[[peers]]
network_id = "${network_id}"
node_id = "${node_b_id}"
prefixes = ["100.96.0.2/32", "fd42:96::2/128", "192.168.50.0/24", "fd42:50::/64"]
EOF
  cat >"${case_dir}/a.toml" <<EOF
mode = "node"
state_dir = "${case_dir}/a-state"
socket_path = "${case_dir}/a.sock"
[tls]
certificate = "${case_dir}/a.crt"
private_key = "${case_dir}/a.key"
ca = "${case_dir}/ca.crt"
[node]
name = "fullstack-a"
relay_address = "10.250.0.1:4433"
relay_network_id = "${network_id}"
relay_service_id = "${relay_id}"
overlay_addresses = ["100.96.0.1/32", "fd42:96::1/128"]
reconnect_min = "50ms"
reconnect_max = "500ms"
[[peers]]
network_id = "${network_id}"
node_id = "${node_b_id}"
prefixes = ["100.96.0.2/32", "fd42:96::2/128", "192.168.50.0/24", "fd42:50::/64"]
EOF
  cat >"${case_dir}/b.toml" <<EOF
mode = "node"
state_dir = "${case_dir}/b-state"
socket_path = "${case_dir}/b.sock"
[tls]
certificate = "${case_dir}/b.crt"
private_key = "${case_dir}/b.key"
ca = "${case_dir}/ca.crt"
[node]
name = "fullstack-gateway"
relay_address = "10.250.0.1:4433"
relay_network_id = "${network_id}"
relay_service_id = "${relay_id}"
overlay_addresses = ["100.96.0.2/32", "fd42:96::2/128"]
reconnect_min = "50ms"
reconnect_max = "500ms"
[routing]
advertise = ["192.168.50.0/24", "fd42:50::/64"]
nat = true
output_interface = "lan1"
[[peers]]
network_id = "${network_id}"
node_id = "${node_a_id}"
prefixes = ["100.96.0.1/32", "fd42:96::1/128"]
EOF

  start_process "${relay}" "${case_dir}/relay.log" "${work_dir}/laneway-relay" -config "${case_dir}/relay.toml" -diagnostics 127.0.0.1:6060
  local relay_pid="${last_pid}"
  wait_log "${relay_pid}" "${case_dir}/relay.log" "listening"
  start_process "${node_a}" "${case_dir}/a.log" "${work_dir}/lanewayd" -config "${case_dir}/a.toml" -diagnostics 127.0.0.1:6061
  local node_a_pid="${last_pid}"
  start_process "${node_b}" "${case_dir}/b.log" "${work_dir}/lanewayd" -config "${case_dir}/b.toml" -diagnostics 127.0.0.1:6062
  local node_b_pid="${last_pid}"
  wait_log "${node_a_pid}" "${case_dir}/a.log" "interface=lane0"
  wait_log "${node_b_pid}" "${case_dir}/b.log" "interface=lane0"
  ip -n "${node_a}" -6 -o address show dev lane0 | grep -q 'fd42:96::1/128'
  ip -n "${node_b}" -6 -o address show dev lane0 | grep -q 'fd42:96::2/128'
  ip -n "${node_a}" -6 route show exact fd42:96::2/128 | grep -q 'dev lane0'
  if [[ "${LANEWAY_INTEGRATION_DEBUG_HOLD:-0}" == "1" ]]; then
    echo "DEBUG: holding overlay topology namespaces ${node_a} ${node_b} ${relay}"
    sleep 60
  fi

  echo "==> real application packet crosses both kernel TUNs and the QUIC relay"
  start_process "${node_b}" "${case_dir}/overlay-server.log" "${work_dir}/netprobe" udp-server -listen 100.96.0.2:9101
  local server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/overlay-server.log" "ready=udp-server"
  ip netns exec "${node_a}" "${work_dir}/netprobe" udp-client -target 100.96.0.2:9101 -message overlay
  wait "${server_pid}"
  grep -q 'remote=100.96.0.1:' "${case_dir}/overlay-server.log"

  echo "==> real IPv6 application packet crosses both kernel TUNs and the QUIC relay"
  start_process "${node_b}" "${case_dir}/overlay6-server.log" "${work_dir}/netprobe" udp-server -listen '[fd42:96::2]:9104'
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/overlay6-server.log" "ready=udp-server"
  ip netns exec "${node_a}" "${work_dir}/netprobe" udp-client -target '[fd42:96::2]:9104' -message overlay6
  wait "${server_pid}"
  grep -q 'remote=\[fd42:96::1\]:' "${case_dir}/overlay6-server.log"

  echo "==> real subnet packet is NATed at the Laneway gateway"
  start_process "${lan_host}" "${case_dir}/nat-server.log" "${work_dir}/netprobe" udp-server -listen 192.168.50.2:9102
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/nat-server.log" "ready=udp-server"
  ip netns exec "${node_a}" "${work_dir}/netprobe" udp-client -target 192.168.50.2:9102 -message subnet-nat
  wait "${server_pid}"
  grep -q 'remote=192.168.50.1:' "${case_dir}/nat-server.log"
  run_kernel_udp_benchmark "${lan_host}" "${node_a}" 192.168.50.2:9192 192.168.50.2:9192 \
    subnet-nat-kernel "${case_dir}/nat-benchmark-server.log"

  echo "==> real IPv6 subnet packet is NAT66-masqueraded at the Laneway gateway"
  start_process "${lan_host}" "${case_dir}/nat6-server.log" "${work_dir}/netprobe" udp-server -listen '[fd42:50::2]:9105'
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/nat6-server.log" "ready=udp-server"
  ip netns exec "${node_a}" "${work_dir}/netprobe" udp-client -target '[fd42:50::2]:9105' -message subnet-nat6
  wait "${server_pid}"
  grep -q 'remote=\[fd42:50::1\]:' "${case_dir}/nat6-server.log"

  echo "==> the same subnet flow preserves its overlay source in routed mode"
  stop_process "${node_b_pid}"
  sed -i 's/nat = true/nat = false/' "${case_dir}/b.toml"
  ip -n "${lan_host}" route add 100.96.0.0/16 via 192.168.50.1
  ip -n "${lan_host}" -6 route add fd42:96::/64 via fd42:50::1
  start_process "${node_b}" "${case_dir}/b-routed.log" "${work_dir}/lanewayd" -config "${case_dir}/b.toml"
  node_b_pid="${last_pid}"
  wait_log "${node_b_pid}" "${case_dir}/b-routed.log" "interface=lane0"
  start_process "${lan_host}" "${case_dir}/routed-server.log" "${work_dir}/netprobe" udp-server -listen 192.168.50.2:9103
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/routed-server.log" "ready=udp-server"
  ip netns exec "${node_a}" "${work_dir}/netprobe" udp-client -target 192.168.50.2:9103 -message subnet-routed
  wait "${server_pid}"
  grep -q 'remote=100.96.0.1:' "${case_dir}/routed-server.log"
  run_kernel_udp_benchmark "${lan_host}" "${node_a}" 192.168.50.2:9193 192.168.50.2:9193 \
    subnet-routed-kernel "${case_dir}/routed-benchmark-server.log"

  echo "==> the IPv6 subnet flow preserves its overlay source in routed mode"
  start_process "${lan_host}" "${case_dir}/routed6-server.log" "${work_dir}/netprobe" udp-server -listen '[fd42:50::2]:9106'
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/routed6-server.log" "ready=udp-server"
  ip netns exec "${node_a}" "${work_dir}/netprobe" udp-client -target '[fd42:50::2]:9106' -message subnet-routed6
  wait "${server_pid}"
  grep -q 'remote=\[fd42:96::1\]:' "${case_dir}/routed6-server.log"

  stop_process "${node_a_pid}"
  stop_process "${node_b_pid}"
  stop_process "${relay_pid}"
}

run_exit_flow() {
  local case_dir="${work_dir}/exit"
  local switch="${prefix}es" relay="${prefix}er" client="${prefix}ec" gateway="${prefix}eg" external="${prefix}ex"
  issue_identity_set "${case_dir}" "10.251.0.1" "${network_id}" "${node_a_id}" "${node_b_id}" "${relay_id}"
  add_switch "${switch}"
  add_namespace "${relay}"
  add_namespace "${client}"
  add_namespace "${gateway}"
  add_namespace "${external}"
  attach_switch "${switch}" "${relay}" eth0 10.251.0.1/24
  attach_switch "${switch}" "${client}" eth0 10.251.0.2/24
  attach_switch "${switch}" "${gateway}" eth0 10.251.0.3/24
  connect_namespaces "${gateway}" wan0 198.18.0.1/24 "${external}" eth0 198.18.0.2/24
  ip -n "${gateway}" -6 address add fd42:18::1/64 dev wan0 nodad
  ip -n "${external}" -6 address add fd42:18::2/64 dev eth0 nodad

  cat >"${case_dir}/relay.toml" <<EOF
mode = "relay"
state_dir = "${case_dir}/relay-state"
socket_path = "${case_dir}/relay.sock"
[tls]
certificate = "${case_dir}/relay.crt"
private_key = "${case_dir}/relay.key"
ca = "${case_dir}/ca.crt"
[relay]
listen = "10.251.0.1:4433"
[[peers]]
network_id = "${network_id}"
node_id = "${node_a_id}"
prefixes = ["100.97.0.1/32", "fd42:97::1/128"]
[[peers]]
network_id = "${network_id}"
node_id = "${node_b_id}"
prefixes = ["100.97.0.2/32", "fd42:97::2/128", "198.18.0.0/24", "fd42:18::/64"]
EOF
  cat >"${case_dir}/client.toml" <<EOF
mode = "node"
state_dir = "${case_dir}/client-state"
socket_path = "${case_dir}/client.sock"
[tls]
certificate = "${case_dir}/a.crt"
private_key = "${case_dir}/a.key"
ca = "${case_dir}/ca.crt"
[node]
name = "exit-client"
relay_address = "10.251.0.1:4433"
relay_network_id = "${network_id}"
relay_service_id = "${relay_id}"
overlay_addresses = ["100.97.0.1/32", "fd42:97::1/128"]
reconnect_min = "50ms"
reconnect_max = "500ms"
[[peers]]
network_id = "${network_id}"
node_id = "${node_b_id}"
prefixes = ["100.97.0.2/32", "fd42:97::2/128", "198.18.0.0/24", "fd42:18::/64"]
EOF
  cat >"${case_dir}/gateway.toml" <<EOF
mode = "node"
state_dir = "${case_dir}/gateway-state"
socket_path = "${case_dir}/gateway.sock"
[tls]
certificate = "${case_dir}/b.crt"
private_key = "${case_dir}/b.key"
ca = "${case_dir}/ca.crt"
[node]
name = "exit-gateway"
relay_address = "10.251.0.1:4433"
relay_network_id = "${network_id}"
relay_service_id = "${relay_id}"
overlay_addresses = ["100.97.0.2/32", "fd42:97::2/128"]
reconnect_min = "50ms"
reconnect_max = "500ms"
[routing]
advertise = ["198.18.0.0/24", "fd42:18::/64"]
nat = false
output_interface = "wan0"
[[peers]]
network_id = "${network_id}"
node_id = "${node_a_id}"
prefixes = ["100.97.0.1/32", "fd42:97::1/128"]
EOF

  start_process "${relay}" "${case_dir}/relay.log" "${work_dir}/laneway-relay" -config "${case_dir}/relay.toml"
  local relay_pid="${last_pid}"
  wait_log "${relay_pid}" "${case_dir}/relay.log" "listening"
  start_process "${client}" "${case_dir}/client.log" "${work_dir}/lanewayd" -config "${case_dir}/client.toml"
  local client_pid="${last_pid}"
  start_process "${gateway}" "${case_dir}/gateway.log" "${work_dir}/lanewayd" -config "${case_dir}/gateway.toml"
  local gateway_pid="${last_pid}"
  wait_log "${client_pid}" "${case_dir}/client.log" "interface=lane0"
  wait_log "${gateway_pid}" "${case_dir}/gateway.log" "interface=lane0"

  start_process "${client}" "${case_dir}/exit-client.log" "${work_dir}/netprobe" exit-client -interface lane0 -transport-bypass 10.251.0.1 -ipv6
  local exit_client_pid="${last_pid}"
  wait_log "${exit_client_pid}" "${case_dir}/exit-client.log" "ready=exit-client"
  start_process "${gateway}" "${case_dir}/exit-gateway.log" "${work_dir}/netprobe" exit-gateway -input lane0 -output wan0 -overlay-source 100.97.0.1/32 -overlay-source6 fd42:97::1/128
  local exit_gateway_pid="${last_pid}"
  wait_log "${exit_gateway_pid}" "${case_dir}/exit-gateway.log" "ready=exit-gateway"

  ip -n "${client}" -4 rule show priority 11000 | grep -q 'lookup 51820'
  ip -n "${client}" -6 rule show priority 11000 | grep -q 'lookup 51820'
  ip -n "${client}" route show table 51820 exact 0.0.0.0/1 | grep -q 'dev lane0'
  ip -n "${client}" route show table 51820 exact 128.0.0.0/1 | grep -q 'dev lane0'
  ip -n "${client}" route show table 51820 exact 10.251.0.1/32 | grep -q 'dev eth0'
  ip -n "${client}" -6 route show table 51820 exact ::/1 | grep -q 'dev lane0'
  ip -n "${client}" -6 route show table 51820 exact 8000::/1 | grep -q 'dev lane0'
  echo "==> selected exit carries a real external packet and gateway-NATs it"
  start_process "${external}" "${case_dir}/external-server.log" "${work_dir}/netprobe" udp-server -listen 198.18.0.2:9201
  local server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/external-server.log" "ready=udp-server"
  ip netns exec "${client}" "${work_dir}/netprobe" udp-client -target 198.18.0.2:9201 -message exit-flow
  wait "${server_pid}"
  grep -q 'remote=198.18.0.1:' "${case_dir}/external-server.log"
  run_kernel_udp_benchmark "${external}" "${client}" 198.18.0.2:9292 198.18.0.2:9292 \
    exit-nat-kernel "${case_dir}/exit-benchmark-server.log"

  echo "==> selected IPv6 exit carries a real external packet and NAT66-masquerades it"
  start_process "${external}" "${case_dir}/external6-server.log" "${work_dir}/netprobe" udp-server -listen '[fd42:18::2]:9202'
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/external6-server.log" "ready=udp-server"
  ip netns exec "${client}" "${work_dir}/netprobe" udp-client -target '[fd42:18::2]:9202' -message exit6-flow
  wait "${server_pid}"
  grep -q 'remote=\[fd42:18::1\]:' "${case_dir}/external6-server.log"

  stop_process "${exit_client_pid}"
  stop_process "${exit_gateway_pid}"
  stop_process "${client_pid}"
  stop_process "${gateway_pid}"
  stop_process "${relay_pid}"
}

run_direct_nat_flow() {
  local case_dir="${work_dir}/direct-nat"
  local switch="${prefix}ds" relay="${prefix}dr" node_a="${prefix}da" node_b="${prefix}db"
  local router_a="${prefix}d1" router_b="${prefix}d2"
  issue_identity_set "${case_dir}" "10.252.0.1" "${network_id}" "${node_a_id}" "${node_b_id}" "${relay_id}"
  add_switch "${switch}"
  add_namespace "${relay}"
  add_namespace "${node_a}"
  add_namespace "${node_b}"
  add_namespace "${router_a}"
  add_namespace "${router_b}"
  attach_switch "${switch}" "${relay}" eth0 10.252.0.1/24
  attach_switch "${switch}" "${router_a}" wan0 10.252.0.2/24
  attach_switch "${switch}" "${router_b}" wan0 10.252.0.3/24
  connect_namespaces "${router_a}" lan0 10.10.1.1/24 "${node_a}" eth0 10.10.1.2/24
  connect_namespaces "${router_b}" lan0 10.10.2.1/24 "${node_b}" eth0 10.10.2.2/24
  ip -n "${node_a}" route add default via 10.10.1.1
  ip -n "${node_b}" route add default via 10.10.2.1
  ip netns exec "${router_a}" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "${router_b}" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "${router_a}" nft add table ip direct_nat
  ip netns exec "${router_a}" nft add chain ip direct_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'
  ip netns exec "${router_a}" nft add chain ip direct_nat postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'
  ip netns exec "${router_a}" nft add rule ip direct_nat prerouting iifname wan0 ip daddr 10.252.0.2 udp dport 41001 counter dnat to 10.10.1.2:41001
  ip netns exec "${router_a}" nft add rule ip direct_nat postrouting oifname wan0 ip saddr 10.10.1.2 udp sport 41001 counter snat to 10.252.0.2:41001
  ip netns exec "${router_b}" nft add table ip direct_nat
  ip netns exec "${router_b}" nft add chain ip direct_nat prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'
  ip netns exec "${router_b}" nft add chain ip direct_nat postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'
  ip netns exec "${router_b}" nft add rule ip direct_nat prerouting iifname wan0 ip daddr 10.252.0.3 udp dport 41002 counter dnat to 10.10.2.2:41002
  ip netns exec "${router_b}" nft add rule ip direct_nat postrouting oifname wan0 ip saddr 10.10.2.2 udp sport 41002 counter snat to 10.252.0.3:41002

  cat >"${case_dir}/relay.toml" <<EOF
mode = "relay"
state_dir = "${case_dir}/relay-state"
socket_path = "${case_dir}/relay.sock"
[tls]
certificate = "${case_dir}/relay.crt"
private_key = "${case_dir}/relay.key"
ca = "${case_dir}/ca.crt"
[relay]
listen = "10.252.0.1:4433"
[[peers]]
network_id = "${network_id}"
node_id = "${node_a_id}"
prefixes = ["100.98.0.1/32"]
[[peers]]
network_id = "${network_id}"
node_id = "${node_b_id}"
prefixes = ["100.98.0.2/32"]
EOF
  cat >"${case_dir}/a.toml" <<EOF
mode = "node"
state_dir = "${case_dir}/a-state"
socket_path = "${case_dir}/a.sock"
[tls]
certificate = "${case_dir}/a.crt"
private_key = "${case_dir}/a.key"
ca = "${case_dir}/ca.crt"
[node]
name = "direct-nat-a"
relay_address = "10.252.0.1:4433"
relay_network_id = "${network_id}"
relay_service_id = "${relay_id}"
overlay_addresses = ["100.98.0.1/32"]
reconnect_min = "50ms"
reconnect_max = "500ms"
[direct]
enabled = true
listen = "0.0.0.0:41001"
candidate_ttl = "30s"
probe_interval = "50ms"
probe_timeout = "5s"
max_candidates = 8
[[peers]]
network_id = "${network_id}"
node_id = "${node_b_id}"
prefixes = ["100.98.0.2/32"]
EOF
  cat >"${case_dir}/b.toml" <<EOF
mode = "node"
state_dir = "${case_dir}/b-state"
socket_path = "${case_dir}/b.sock"
[tls]
certificate = "${case_dir}/b.crt"
private_key = "${case_dir}/b.key"
ca = "${case_dir}/ca.crt"
[node]
name = "direct-nat-b"
relay_address = "10.252.0.1:4433"
relay_network_id = "${network_id}"
relay_service_id = "${relay_id}"
overlay_addresses = ["100.98.0.2/32"]
reconnect_min = "50ms"
reconnect_max = "500ms"
[direct]
enabled = true
listen = "0.0.0.0:41002"
candidate_ttl = "30s"
probe_interval = "50ms"
probe_timeout = "5s"
max_candidates = 8
[[peers]]
network_id = "${network_id}"
node_id = "${node_a_id}"
prefixes = ["100.98.0.1/32"]
EOF

  start_process "${relay}" "${case_dir}/relay.log" "${work_dir}/laneway-relay" -config "${case_dir}/relay.toml" -diagnostics 127.0.0.1:6060
  local relay_pid="${last_pid}"
  wait_log "${relay_pid}" "${case_dir}/relay.log" "listening"
  start_process "${node_a}" "${case_dir}/a.log" "${work_dir}/lanewayd" -config "${case_dir}/a.toml" -diagnostics 127.0.0.1:6061
  local node_a_pid="${last_pid}"
  start_process "${node_b}" "${case_dir}/b.log" "${work_dir}/lanewayd" -config "${case_dir}/b.toml" -diagnostics 127.0.0.1:6062
  local node_b_pid="${last_pid}"
  wait_log "${node_a_pid}" "${case_dir}/a.log" "interface=lane0"
  wait_log "${node_b_pid}" "${case_dir}/b.log" "interface=lane0"

  local promoted=0 metric_value=""
  for _ in $(seq 1 200); do
    metric_value="$(ip netns exec "${node_a}" "${work_dir}/netprobe" metric -url http://127.0.0.1:6061/metrics -name laneway_path_switches_total 2>/dev/null || true)"
    if [[ "${metric_value:-0}" =~ ^[0-9]+$ ]] && (( metric_value > 0 )); then
      promoted=1
      break
    fi
    sleep 0.05
  done
  if [[ "${promoted}" != "1" ]]; then
    echo "ERROR: direct path did not promote through the two NAT namespaces" >&2
    ip netns exec "${router_a}" nft list table ip direct_nat >&2 || true
    ip netns exec "${router_b}" nft list table ip direct_nat >&2 || true
    sed -n '1,240p' "${case_dir}/a.log" >&2
    sed -n '1,240p' "${case_dir}/b.log" >&2
    if [[ "${LANEWAY_INTEGRATION_DEBUG_HOLD:-0}" == "1" ]]; then
      echo "DEBUG: holding direct topology namespaces ${node_a} ${router_a} ${node_b} ${router_b} ${relay}" >&2
      sleep 60
    fi
    return 1
  fi

  local forwarded_before forwarded_after
  forwarded_before="$(ip netns exec "${relay}" "${work_dir}/netprobe" metric -url http://127.0.0.1:6060/metrics -name laneway_forwarded_packets_total)"
  echo "==> kernel packet crosses the promoted direct path through both simulated NATs"
  start_process "${node_b}" "${case_dir}/direct-server.log" "${work_dir}/netprobe" udp-server -listen 100.98.0.2:9301
  local server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/direct-server.log" "ready=udp-server"
  ip netns exec "${node_a}" "${work_dir}/netprobe" udp-client -target 100.98.0.2:9301 -message direct-nat -once -timeout 3s
  wait "${server_pid}"
  sleep 0.1
  forwarded_after="$(ip netns exec "${relay}" "${work_dir}/netprobe" metric -url http://127.0.0.1:6060/metrics -name laneway_forwarded_packets_total)"
  if [[ "${forwarded_after}" != "${forwarded_before}" ]]; then
    echo "ERROR: direct application packet traversed relay: before=${forwarded_before} after=${forwarded_after}" >&2
    return 1
  fi
  grep -q 'remote=100.98.0.1:' "${case_dir}/direct-server.log"

  stop_process "${node_a_pid}"
  stop_process "${node_b_pid}"
  stop_process "${relay_pid}"
}

json_string_field() {
  local field="$1"
  sed -n 's/^[[:space:]]*"'"${field}"'": "\([^"]*\)"[,]*$/\1/p'
}

run_controller_wireguard_carriers() {
  local case_dir="${work_dir}/controller-wireguard"
  local switch="${prefix}ws" controller="${prefix}wc" relay="${prefix}wr"
  local node_a="${prefix}wa" node_b="${prefix}wb" internet="${prefix}wi"
  local network_id="20000000000000000000000000000001"
  local controller_service="20000000000000000000000000000002"
  local relay_service="20000000000000000000000000000003"
  local controller_endpoint="https://10.254.0.1:8443"
  local controller_quic_endpoint="10.254.0.1:8443"
  local admin_token="laneway-wireguard-fullstack-admin-token-000000000000001"

  mkdir -p "${case_dir}"
  printf '%s\n' "${admin_token}" >"${case_dir}/admin.token"
  chmod 600 "${case_dir}/admin.token"
  "${work_dir}/laneway" pki init -out-dir "${case_dir}" >/dev/null
  "${work_dir}/laneway" pki controller -ca-cert "${case_dir}/ca.crt" -ca-key "${case_dir}/ca.key" \
    -network-id "${network_id}" -service-id "${controller_service}" -ip 10.254.0.1 \
    -out-cert "${case_dir}/controller.crt" -out-key "${case_dir}/controller.key"
  "${work_dir}/laneway" pki relay -ca-cert "${case_dir}/ca.crt" -ca-key "${case_dir}/ca.key" \
    -network-id "${network_id}" -service-id "${relay_service}" -ip 10.254.0.2 \
    -out-cert "${case_dir}/relay.crt" -out-key "${case_dir}/relay.key"

  add_switch "${switch}"
  add_namespace "${controller}"
  add_namespace "${relay}"
  add_namespace "${node_a}"
  add_namespace "${node_b}"
	add_namespace "${internet}"
  attach_switch "${switch}" "${controller}" eth0 10.254.0.1/24
  attach_switch "${switch}" "${relay}" eth0 10.254.0.2/24
  attach_switch "${switch}" "${node_a}" eth0 10.254.0.3/24
  attach_switch "${switch}" "${node_b}" eth0 10.254.0.4/24
  connect_namespaces "${node_b}" wan0 198.51.100.1/24 "${internet}" eth0 198.51.100.2/24

  cat >"${case_dir}/controller.toml" <<EOF
mode = "controller"
state_dir = "${case_dir}/controller-state"
socket_path = "${case_dir}/controller.sock"
[tls]
certificate = "${case_dir}/controller.crt"
private_key = "${case_dir}/controller.key"
ca = "${case_dir}/ca.crt"
[controller]
listen = "10.254.0.1:8443"
quic_listen = "10.254.0.1:8443"
database = "${case_dir}/controller.db"
ca_private_key = "${case_dir}/ca.key"
admin_token_file = "${case_dir}/admin.token"
leaf_validity = "24h"
EOF
  start_process "${controller}" "${case_dir}/controller.log" \
    "${work_dir}/laneway-controller" -config "${case_dir}/controller.toml" -diagnostics 127.0.0.1:6063
  local controller_pid="${last_pid}"
  wait_log "${controller_pid}" "${case_dir}/controller.log" "laneway-controller HTTPS="

  local -a admin_connection=(
    --controller "${controller_endpoint}" --ca "${case_dir}/ca.crt"
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}"
    --admin-token-file "${case_dir}/admin.token"
  )
  ip netns exec "${controller}" "${work_dir}/laneway" controller network create \
    --network-id "${network_id}" --name wireguard-fullstack \
    --ipv4-pool 100.100.0.0/24 --ipv6-pool fd00:100::/120 \
    "${admin_connection[@]}" >"${case_dir}/network.json"
  ip netns exec "${controller}" "${work_dir}/laneway" controller relay register \
    --network-id "${network_id}" --service-id "${relay_service}" \
    --name wireguard-relay --endpoint 10.254.0.2:4433 \
    "${admin_connection[@]}" >"${case_dir}/relay-registration.json"

  local token_a token_b join_a join_b node_a_id node_b_id overlays_a overlays_b overlay_a4 overlay_a6 overlay_b4 overlay_b6
  token_a="$(ip netns exec "${controller}" "${work_dir}/laneway" controller enrollment-token issue \
    --network-id "${network_id}" --label wireguard-a --expires-in 10m "${admin_connection[@]}" | \
    json_string_field enrollment_token)"
  token_b="$(ip netns exec "${controller}" "${work_dir}/laneway" controller enrollment-token issue \
    --network-id "${network_id}" --label wireguard-b --expires-in 10m "${admin_connection[@]}" | \
    json_string_field enrollment_token)"
  join_a="$(ip netns exec "${node_a}" "${work_dir}/laneway" join "${token_a}" \
    --controller "${controller_endpoint}" --ca "${case_dir}/ca.crt" \
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
    --name wireguard-a --out-cert "${case_dir}/a.crt" --out-key "${case_dir}/a.key" \
    --out-wireguard-key "${case_dir}/a.wireguard.key")"
  join_b="$(ip netns exec "${node_b}" "${work_dir}/laneway" join "${token_b}" \
    --controller "${controller_endpoint}" --ca "${case_dir}/ca.crt" \
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
    --name wireguard-b --out-cert "${case_dir}/b.crt" --out-key "${case_dir}/b.key" \
    --out-wireguard-key "${case_dir}/b.wireguard.key")"
  node_a_id="$(printf '%s\n' "${join_a}" | sed -n 's/.* node=\([0-9a-f]\{32\}\) .*/\1/p')"
  node_b_id="$(printf '%s\n' "${join_b}" | sed -n 's/.* node=\([0-9a-f]\{32\}\) .*/\1/p')"
  overlays_a="$(printf '%s\n' "${join_a}" | sed -n 's/.* overlay=\([^ ]*\) certificate=.*/\1/p')"
  overlays_b="$(printf '%s\n' "${join_b}" | sed -n 's/.* overlay=\([^ ]*\) certificate=.*/\1/p')"
  overlay_a4="${overlays_a%%,*}"
  overlay_a6="${overlays_a#*,}"
  overlay_b4="${overlays_b%%,*}"
  overlay_b6="${overlays_b#*,}"
  if [[ ! "${node_a_id}" =~ ^[0-9a-f]{32}$ || ! "${node_b_id}" =~ ^[0-9a-f]{32}$ || \
        "${overlay_a4}" == "${overlay_a6}" || "${overlay_b4}" == "${overlay_b6}" ]]; then
    echo "ERROR: failed to parse dual-stack WireGuard enrollments" >&2
    printf '%s\n%s\n' "${join_a}" "${join_b}" >&2
    return 1
  fi
  ip netns exec "${controller}" "${work_dir}/laneway" controller acl add \
    --network-id "${network_id}" --priority 100 --action accept \
    --selector '{"ip_protocol":"IP_PROTOCOL_ANY"}' --description wireguard-fullstack-allow \
    "${admin_connection[@]}" >"${case_dir}/acl.json"
  ip netns exec "${controller}" "${work_dir}/laneway" controller node capabilities \
    --node-id "${node_b_id}" --exit-node "${admin_connection[@]}" >"${case_dir}/exit-capability.json"

  cat >"${case_dir}/relay.toml" <<EOF
mode = "relay"
state_dir = "${case_dir}/relay-state"
socket_path = "${case_dir}/relay.sock"
[tls]
certificate = "${case_dir}/relay.crt"
private_key = "${case_dir}/relay.key"
ca = "${case_dir}/ca.crt"
[relay]
listen = "10.254.0.2:4433"
idle_timeout = "20s"
[tcp_fallback]
listen = "10.254.0.2:443"
handshake_timeout = "2s"
write_timeout = "2s"
idle_timeout = "10s"
keepalive_period = "2s"
queue_depth = 128
[controller]
endpoint = "${controller_endpoint}"
quic_endpoint = "${controller_quic_endpoint}"
network_id = "${network_id}"
service_id = "${controller_service}"
poll_interval = "100ms"
EOF
  cat >"${case_dir}/a.toml" <<EOF
mode = "node"
state_dir = "${case_dir}/a-state"
socket_path = "${case_dir}/a.sock"
[tls]
certificate = "${case_dir}/a.crt"
private_key = "${case_dir}/a.key"
ca = "${case_dir}/ca.crt"
[node]
name = "wireguard-a"
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
[tcp_fallback]
address = "10.254.0.2:443"
handshake_timeout = "2s"
write_timeout = "2s"
idle_timeout = "10s"
keepalive_period = "2s"
quic_probe_interval = "1s"
queue_depth = 128
[direct]
enabled = true
listen = "10.254.0.3:41001"
candidate_ttl = "30s"
probe_interval = "100ms"
probe_timeout = "2s"
rendezvous_interval = "1s"
max_candidates = 8
[wireguard]
enabled = true
private_key = "${case_dir}/a.wireguard.key"
interface = "lane0"
listen_port = 51821
mtu = 1280
[exit]
failure_mode = "closed"
dns_servers = ["1.1.1.1"]
local_lan_bypasses = ["10.254.0.0/24"]
EOF
  cat >"${case_dir}/b.toml" <<EOF
mode = "node"
state_dir = "${case_dir}/b-state"
socket_path = "${case_dir}/b.sock"
[tls]
certificate = "${case_dir}/b.crt"
private_key = "${case_dir}/b.key"
ca = "${case_dir}/ca.crt"
[node]
name = "wireguard-b"
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
[tcp_fallback]
address = "10.254.0.2:443"
handshake_timeout = "2s"
write_timeout = "2s"
idle_timeout = "10s"
keepalive_period = "2s"
quic_probe_interval = "1s"
queue_depth = 128
[direct]
enabled = true
listen = "10.254.0.4:41002"
candidate_ttl = "30s"
probe_interval = "100ms"
probe_timeout = "2s"
rendezvous_interval = "1s"
max_candidates = 8
[wireguard]
enabled = true
private_key = "${case_dir}/b.wireguard.key"
interface = "lane0"
listen_port = 51822
mtu = 1280
[routing]
output_interface = "wan0"
[exit]
serve = true
EOF

  # A namespace-local resolvectl shim exercises the real exit DNS transaction
  # without depending on a host systemd-resolved instance.
  mkdir -p "${case_dir}/resolver-state"
  cat >"${case_dir}/resolvectl" <<'EOF'
#!/bin/sh
set -eu
property="${1:-}"
interface="${2:-}"
if [ -z "${property}" ] || [ -z "${interface}" ] || [ -z "${LANEWAY_RESOLVE_STATE:-}" ]; then
  exit 2
fi
index="$(cat "/sys/class/net/${interface}/ifindex")"
state="${LANEWAY_RESOLVE_STATE}/${index}.${property}"
if [ "${property}" = "revert" ]; then
  rm -f "${LANEWAY_RESOLVE_STATE}/${index}.dns" "${LANEWAY_RESOLVE_STATE}/${index}.domain" \
    "${LANEWAY_RESOLVE_STATE}/${index}.default-route"
  exit 0
fi
shift 2
if [ "$#" -eq 0 ]; then
  value=""
  if [ -f "${state}" ]; then
    value="$(sed -n '1p' "${state}")"
  fi
  printf 'Link %s (%s): %s\n' "${index}" "${interface}" "${value}"
  exit 0
fi
printf '%s\n' "$*" >"${state}"
EOF
  chmod 700 "${case_dir}/resolvectl"

  # Keep direct candidates unreachable while leaving controller and relay UDP
  # untouched. Each table belongs solely to this disposable namespace.
  for namespace in "${node_a}" "${node_b}"; do
    ip netns exec "${namespace}" nft add table inet laneway_wg_direct_block
    ip netns exec "${namespace}" nft add chain inet laneway_wg_direct_block output \
      '{ type filter hook output priority -20; policy accept; }'
  done
  ip netns exec "${node_a}" nft add rule inet laneway_wg_direct_block output \
    ip daddr 10.254.0.4 udp dport 41002 drop
  ip netns exec "${node_b}" nft add rule inet laneway_wg_direct_block output \
    ip daddr 10.254.0.3 udp dport 41001 drop

  start_process "${relay}" "${case_dir}/relay.log" \
    "${work_dir}/laneway-relay" -config "${case_dir}/relay.toml" -diagnostics 127.0.0.1:6060
  local relay_pid="${last_pid}"
  wait_log "${relay_pid}" "${case_dir}/relay.log" "laneway-relay QUIC="
  start_process "${node_a}" "${case_dir}/a.log" env \
    PATH="${case_dir}:${PATH}" LANEWAY_RESOLVE_STATE="${case_dir}/resolver-state" \
    "${work_dir}/lanewayd" -config "${case_dir}/a.toml" -diagnostics 127.0.0.1:6061
  local node_a_pid="${last_pid}"
  start_process "${node_b}" "${case_dir}/b.log" \
    "${work_dir}/lanewayd" -config "${case_dir}/b.toml" -diagnostics 127.0.0.1:6062
  local node_b_pid="${last_pid}"
  wait_log "${node_a_pid}" "${case_dir}/a.log" "interface=lane0"
  wait_log "${node_b_pid}" "${case_dir}/b.log" "interface=lane0"
  local lane_a_ifindex lane_b_ifindex
  lane_a_ifindex="$(ip netns exec "${node_a}" cat /sys/class/net/lane0/ifindex)"
  lane_b_ifindex="$(ip netns exec "${node_b}" cat /sys/class/net/lane0/ifindex)"

  echo "==> encrypted WireGuard packets carry dual-stack traffic over relay QUIC"
  wait_selected_path "${node_a}" "${case_dir}/a.toml" wireguard-relay-quic "${node_a_pid}" "${case_dir}/a.log"
  wait_selected_path "${node_b}" "${case_dir}/b.toml" wireguard-relay-quic "${node_b_pid}" "${case_dir}/b.log"
  start_process "${node_b}" "${case_dir}/relay-quic4.log" "${work_dir}/netprobe" udp-server -listen "${overlay_b4%/*}:9601"
  local server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/relay-quic4.log" "ready=udp-server"
  ip netns exec "${node_a}" "${work_dir}/netprobe" udp-client -target "${overlay_b4%/*}:9601" -message wireguard-relay-quic4
  wait "${server_pid}"
  start_process "${node_a}" "${case_dir}/relay-quic6.log" "${work_dir}/netprobe" udp-server -listen "[${overlay_a6%/*}]:9602"
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/relay-quic6.log" "ready=udp-server"
  ip netns exec "${node_b}" "${work_dir}/netprobe" udp-client -target "[${overlay_a6%/*}]:9602" -message wireguard-relay-quic6
  wait "${server_pid}"

  echo "==> blocking external UDP demotes the same WireGuard tunnel to relay TCP"
  for namespace in "${node_a}" "${node_b}"; do
    ip netns exec "${namespace}" nft add table inet laneway_wg_udp_block
    ip netns exec "${namespace}" nft add chain inet laneway_wg_udp_block output \
      '{ type filter hook output priority -10; policy accept; }'
    ip netns exec "${namespace}" nft add rule inet laneway_wg_udp_block output \
      oifname eth0 meta l4proto udp drop
  done
  wait_selected_path "${node_a}" "${case_dir}/a.toml" wireguard-relay-tcp "${node_a_pid}" "${case_dir}/a.log"
  wait_selected_path "${node_b}" "${case_dir}/b.toml" wireguard-relay-tcp "${node_b_pid}" "${case_dir}/b.log"
  start_process "${node_b}" "${case_dir}/relay-tcp4.log" "${work_dir}/netprobe" udp-server -listen "${overlay_b4%/*}:9603"
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/relay-tcp4.log" "ready=udp-server"
  ip netns exec "${node_a}" "${work_dir}/netprobe" udp-client -target "${overlay_b4%/*}:9603" -message wireguard-relay-tcp4
  wait "${server_pid}"
  start_process "${node_b}" "${case_dir}/relay-tcp6.log" "${work_dir}/netprobe" udp-server -listen "[${overlay_b6%/*}]:9604"
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/relay-tcp6.log" "ready=udp-server"
  ip netns exec "${node_a}" "${work_dir}/netprobe" udp-client -target "[${overlay_b6%/*}]:9604" -message wireguard-relay-tcp6
  wait "${server_pid}"

  echo "==> restoring UDP promotes TCP fallback back to WireGuard relay QUIC"
  ip netns exec "${node_a}" nft delete table inet laneway_wg_udp_block
  ip netns exec "${node_b}" nft delete table inet laneway_wg_udp_block
  wait_selected_path "${node_a}" "${case_dir}/a.toml" wireguard-relay-quic "${node_a_pid}" "${case_dir}/a.log"
  wait_selected_path "${node_b}" "${case_dir}/b.toml" wireguard-relay-quic "${node_b_pid}" "${case_dir}/b.log"

  echo "==> restoring peer UDP promotes the unchanged tunnel to direct WireGuard"
  ip netns exec "${node_a}" nft delete table inet laneway_wg_direct_block
  ip netns exec "${node_b}" nft delete table inet laneway_wg_direct_block
  wait_selected_path "${node_a}" "${case_dir}/a.toml" direct-wireguard "${node_a_pid}" "${case_dir}/a.log"
  wait_selected_path "${node_b}" "${case_dir}/b.toml" direct-wireguard "${node_b_pid}" "${case_dir}/b.log"
  start_process "${node_b}" "${case_dir}/direct4.log" "${work_dir}/netprobe" udp-server -listen "${overlay_b4%/*}:9605"
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/direct4.log" "ready=udp-server"
  local relay_before relay_after
  relay_before="$(ip netns exec "${relay}" "${work_dir}/netprobe" metric \
    -url http://127.0.0.1:6060/metrics -name laneway_forwarded_packets_total)"
  ip netns exec "${node_a}" "${work_dir}/netprobe" udp-client -target "${overlay_b4%/*}:9605" -message direct-wireguard4
  wait "${server_pid}"
  sleep 0.1
  relay_after="$(ip netns exec "${relay}" "${work_dir}/netprobe" metric \
    -url http://127.0.0.1:6060/metrics -name laneway_forwarded_packets_total)"
  if [[ "${relay_after}" != "${relay_before}" ]]; then
    echo "ERROR: direct WireGuard application packet traversed the relay" >&2
    return 1
  fi
  start_process "${node_a}" "${case_dir}/direct6.log" "${work_dir}/netprobe" udp-server -listen "[${overlay_a6%/*}]:9606"
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/direct6.log" "ready=udp-server"
  ip netns exec "${node_b}" "${work_dir}/netprobe" udp-client -target "[${overlay_a6%/*}]:9606" -message direct-wireguard6
  wait "${server_pid}"

  echo "==> direct failure demotes without recreating lane0 or changing overlay identity"
  for namespace in "${node_a}" "${node_b}"; do
    ip netns exec "${namespace}" nft add table inet laneway_wg_direct_reject
    ip netns exec "${namespace}" nft add chain inet laneway_wg_direct_reject output \
      '{ type filter hook output priority -20; policy accept; }'
  done
  ip netns exec "${node_a}" nft add rule inet laneway_wg_direct_reject output \
    ip daddr 10.254.0.4 udp dport 41002 drop
  ip netns exec "${node_b}" nft add rule inet laneway_wg_direct_reject output \
    ip daddr 10.254.0.3 udp dport 41001 drop
  wait_selected_path "${node_a}" "${case_dir}/a.toml" wireguard-relay-quic "${node_a_pid}" "${case_dir}/a.log"
  wait_selected_path "${node_b}" "${case_dir}/b.toml" wireguard-relay-quic "${node_b_pid}" "${case_dir}/b.log"
  if [[ "$(ip netns exec "${node_a}" cat /sys/class/net/lane0/ifindex)" != "${lane_a_ifindex}" || \
        "$(ip netns exec "${node_b}" cat /sys/class/net/lane0/ifindex)" != "${lane_b_ifindex}" ]]; then
    echo "ERROR: carrier switching recreated the stable WireGuard interface" >&2
    return 1
  fi
  ip -n "${node_a}" address show dev lane0 | grep -Fq "${overlay_a4}"
  ip -n "${node_a}" address show dev lane0 | grep -Fq "${overlay_a6}"
  start_process "${node_b}" "${case_dir}/demoted4.log" "${work_dir}/netprobe" udp-server -listen "${overlay_b4%/*}:9607"
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/demoted4.log" "ready=udp-server"
  ip netns exec "${node_a}" "${work_dir}/netprobe" udp-client -target "${overlay_b4%/*}:9607" -message demoted-relay-quic
  wait "${server_pid}"

  echo "==> controller-approved WireGuard exit carries Internet traffic over relay QUIC"
  local exit_json exit_route_id
  exit_json="$(ip netns exec "${node_b}" "${work_dir}/laneway" exit enable \
    --family ipv4 --config "${case_dir}/b.toml")"
  exit_route_id="$(printf '%s\n' "${exit_json}" | json_string_field route_id | head -n 1)"
  if [[ ! "${exit_route_id}" =~ ^[0-9a-f]{32}$ ]]; then
    echo "ERROR: failed to parse WireGuard exit advertisement" >&2
    printf '%s\n' "${exit_json}" >&2
    return 1
  fi
  ip netns exec "${controller}" "${work_dir}/laneway" controller route approve \
    --route-id "${exit_route_id}" "${admin_connection[@]}" >"${case_dir}/exit-route-approval.json"
  local gateway_ready=0
  for _ in $(seq 1 200); do
    if ip netns exec "${node_b}" nft list table inet laneway_exit >/dev/null 2>&1; then
      gateway_ready=1
      break
    fi
    sleep 0.05
  done
  if [[ "${gateway_ready}" != "1" ]]; then
    echo "ERROR: approved WireGuard exit did not activate gateway policy" >&2
    sed -n '1,260p' "${case_dir}/b.log" >&2
    return 1
  fi
  ip netns exec "${node_a}" "${work_dir}/laneway" exit use wireguard-b \
    --config "${case_dir}/a.toml" >"${case_dir}/exit-use.txt"
  local exit_selected=0
  for _ in $(seq 1 200); do
    if ip -n "${node_a}" -4 rule show priority 11000 | grep -q 'lookup 51820' && \
       ip -n "${node_a}" route show table 51820 exact 0.0.0.0/1 | grep -q 'dev lane0'; then
      exit_selected=1
      break
    fi
    sleep 0.05
  done
  if [[ "${exit_selected}" != "1" ]]; then
    echo "ERROR: WireGuard exit selection did not install native defaults" >&2
    sed -n '1,300p' "${case_dir}/a.log" >&2
    return 1
  fi
  ip -n "${node_a}" route show table 51820 exact 10.254.0.0/24 | grep -q 'dev eth0'
  start_process "${internet}" "${case_dir}/exit-relay-quic.log" "${work_dir}/netprobe" \
    udp-server -listen 198.51.100.2:9701
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/exit-relay-quic.log" "ready=udp-server"
  ip netns exec "${node_a}" "${work_dir}/netprobe" udp-client \
    -target 198.51.100.2:9701 -message wireguard-exit-relay-quic
  wait "${server_pid}"
  grep -q 'remote=198.51.100.1:' "${case_dir}/exit-relay-quic.log"

  stop_process "${node_a_pid}"
  stop_process "${node_b_pid}"
  stop_process "${relay_pid}"
  stop_process "${controller_pid}"
}

run_controller_connect_flow() {
  local case_dir="${work_dir}/controller-connect"
  local switch="${prefix}us" controller="${prefix}uc" relay="${prefix}ur"
  local user="${prefix}uu" node="${prefix}un"
  local network_id="30000000000000000000000000000001"
  local controller_service="30000000000000000000000000000002"
  local relay_service="30000000000000000000000000000003"
  local controller_endpoint="https://10.252.0.1:8443"
  local controller_quic_endpoint="10.252.0.1:8443"
  local bootstrap_authority="lane.example.test:9443"
  local admin_token="laneway-connect-fullstack-admin-token-000000000000000001"

  mkdir -p "${case_dir}"
  printf '%s\n' "${admin_token}" >"${case_dir}/admin.token"
  chmod 600 "${case_dir}/admin.token"
  "${work_dir}/laneway" pki init -out-dir "${case_dir}" >/dev/null
  "${work_dir}/laneway" pki controller -ca-cert "${case_dir}/ca.crt" -ca-key "${case_dir}/ca.key" \
    -network-id "${network_id}" -service-id "${controller_service}" \
    -dns lane.example.test -ip 10.252.0.1 \
    -out-cert "${case_dir}/controller.crt" -out-key "${case_dir}/controller.key"
  "${work_dir}/laneway" pki relay -ca-cert "${case_dir}/ca.crt" -ca-key "${case_dir}/ca.key" \
    -network-id "${network_id}" -service-id "${relay_service}" -ip 10.252.0.2 \
    -out-cert "${case_dir}/relay.crt" -out-key "${case_dir}/relay.key"

  add_switch "${switch}"
  add_namespace "${controller}"
  add_namespace "${relay}"
  add_namespace "${user}"
  add_namespace "${node}"
  attach_switch "${switch}" "${controller}" eth0 10.252.0.1/24
  attach_switch "${switch}" "${relay}" eth0 10.252.0.2/24
  attach_switch "${switch}" "${user}" eth0 10.252.0.3/24
  attach_switch "${switch}" "${node}" eth0 10.252.0.4/24
  set_namespace_host "${user}" 10.252.0.1 lane.example.test

  cat >"${case_dir}/controller.toml" <<EOF
mode = "controller"
state_dir = "${case_dir}/controller-state"
socket_path = "${case_dir}/controller.sock"
[tls]
certificate = "${case_dir}/controller.crt"
private_key = "${case_dir}/controller.key"
ca = "${case_dir}/ca.crt"
[controller]
listen = "10.252.0.1:8443"
quic_listen = "10.252.0.1:8443"
database = "${case_dir}/controller.db"
ca_private_key = "${case_dir}/ca.key"
admin_token_file = "${case_dir}/admin.token"
leaf_validity = "24h"
EOF
  start_process "${controller}" "${case_dir}/controller-initialize.log" \
    "${work_dir}/laneway-controller" -config "${case_dir}/controller.toml" -diagnostics 127.0.0.1:6063
  local controller_pid="${last_pid}"
  wait_log "${controller_pid}" "${case_dir}/controller-initialize.log" "laneway-controller HTTPS="

  local -a admin_connection=(
    --controller "${controller_endpoint}" --ca "${case_dir}/ca.crt"
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}"
    --admin-token-file "${case_dir}/admin.token"
  )
  ip netns exec "${controller}" "${work_dir}/laneway" controller network create \
    --network-id "${network_id}" --name connect-fullstack --ipv4-pool 100.101.0.0/24 \
    "${admin_connection[@]}" >"${case_dir}/network.json"
  ip netns exec "${controller}" "${work_dir}/laneway" controller relay register \
    --network-id "${network_id}" --service-id "${relay_service}" \
    --name connect-relay --endpoint 10.252.0.2:4433 \
    "${admin_connection[@]}" >"${case_dir}/relay-registration.json"
  stop_process "${controller_pid}"

  cat >>"${case_dir}/controller.toml" <<EOF
[bootstrap]
listen = "10.252.0.1:9443"
certificate = "${case_dir}/controller.crt"
private_key = "${case_dir}/controller.key"
network_id = "${network_id}"
controller_endpoint = "${controller_endpoint}"
controller_quic_endpoint = "${controller_quic_endpoint}"
controller_server_name = "lane.example.test"
[[bootstrap.artifacts]]
os = "linux"
arch = "amd64"
url = "https://lane.example.test:9443/artifacts/laneway-linux-amd64"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
size_bytes = 1
[[bootstrap.artifacts]]
os = "linux"
arch = "arm64"
url = "https://lane.example.test:9443/artifacts/laneway-linux-arm64"
sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
size_bytes = 1
EOF
  start_process "${controller}" "${case_dir}/controller.log" \
    "${work_dir}/laneway-controller" -config "${case_dir}/controller.toml" -diagnostics 127.0.0.1:6063
  controller_pid="${last_pid}"
  wait_log "${controller_pid}" "${case_dir}/controller.log" "bootstrap=10.252.0.1:9443"

  local node_join node_id node_overlays node_overlay
  (
    umask 077
    ip netns exec "${controller}" "${work_dir}/laneway" controller enrollment-token issue \
      --network-id "${network_id}" --label connect-node --expires-in 10m \
      "${admin_connection[@]}" | json_string_field enrollment_token >"${case_dir}/node.token"
  )
  node_join="$(ip netns exec "${node}" "${work_dir}/laneway" join \
    --token-file "${case_dir}/node.token" --controller "${controller_endpoint}" --ca "${case_dir}/ca.crt" \
    --server-name lane.example.test --controller-network-id "${network_id}" \
    --controller-service-id "${controller_service}" --name connect-node \
    --out-cert "${case_dir}/node.crt" --out-key "${case_dir}/node.key" \
    --out-wireguard-key "${case_dir}/node.wireguard.key")"
  rm -f -- "${case_dir}/node.token"
  node_id="$(printf '%s\n' "${node_join}" | sed -n 's/.* node=\([0-9a-f]\{32\}\) .*/\1/p')"
  node_overlays="$(printf '%s\n' "${node_join}" | sed -n 's/.* overlay=\([^ ]*\) certificate=.*/\1/p')"
  node_overlay="${node_overlays%%,*}"
  node_overlay="${node_overlay%/*}"
  if [[ ! "${node_id}" =~ ^[0-9a-f]{32}$ || -z "${node_overlay}" ]]; then
    echo "ERROR: failed to parse durable node enrollment" >&2
    printf '%s\n' "${node_join}" >&2
    return 1
  fi
  ip netns exec "${controller}" "${work_dir}/laneway" controller acl add \
    --network-id "${network_id}" --priority 100 --action accept \
    --selector '{"ip_protocol":"IP_PROTOCOL_ANY"}' --description connect-fullstack-allow \
    "${admin_connection[@]}" >"${case_dir}/acl.json"

  cat >"${case_dir}/relay.toml" <<EOF
mode = "relay"
state_dir = "${case_dir}/relay-state"
socket_path = "${case_dir}/relay.sock"
[tls]
certificate = "${case_dir}/relay.crt"
private_key = "${case_dir}/relay.key"
ca = "${case_dir}/ca.crt"
[relay]
listen = "10.252.0.2:4433"
[controller]
endpoint = "${controller_endpoint}"
quic_endpoint = "${controller_quic_endpoint}"
server_name = "lane.example.test"
network_id = "${network_id}"
service_id = "${controller_service}"
poll_interval = "100ms"
EOF
  cat >"${case_dir}/node.toml" <<EOF
mode = "node"
state_dir = "${case_dir}/node-state"
socket_path = "${case_dir}/node.sock"
[tls]
certificate = "${case_dir}/node.crt"
private_key = "${case_dir}/node.key"
ca = "${case_dir}/ca.crt"
[node]
name = "connect-node"
relay_address = "10.252.0.2:4433"
relay_network_id = "${network_id}"
relay_service_id = "${relay_service}"
reconnect_min = "50ms"
reconnect_max = "500ms"
[controller]
endpoint = "${controller_endpoint}"
quic_endpoint = "${controller_quic_endpoint}"
server_name = "lane.example.test"
network_id = "${network_id}"
service_id = "${controller_service}"
poll_interval = "100ms"
[direct]
enabled = true
listen = "10.252.0.4:41004"
candidate_ttl = "30s"
probe_interval = "100ms"
probe_timeout = "2s"
rendezvous_interval = "1s"
max_candidates = 8
EOF
  start_process "${relay}" "${case_dir}/relay.log" \
    "${work_dir}/laneway-relay" -config "${case_dir}/relay.toml" -diagnostics 127.0.0.1:6060
  local relay_pid="${last_pid}"
  wait_log "${relay_pid}" "${case_dir}/relay.log" "listening"
  start_process "${node}" "${case_dir}/node.log" \
    "${work_dir}/lanewayd" -config "${case_dir}/node.toml" -diagnostics 127.0.0.1:6061
  local node_pid="${last_pid}"
  wait_log "${node_pid}" "${case_dir}/node.log" "interface=lane0"

  local iteration invite_file connect_log connect_pid server_pid
  for iteration in 1 2; do
    if [[ "${iteration}" == "1" ]]; then
      # Block only direct peer UDP in this disposable namespace. Controller and
      # relay transports remain reachable, proving the authenticated relay path.
      ip netns exec "${user}" nft add table inet laneway_connect_direct_block
      ip netns exec "${user}" nft add chain inet laneway_connect_direct_block output \
        '{ type filter hook output priority -20; policy accept; }'
      ip netns exec "${user}" nft add chain inet laneway_connect_direct_block input \
        '{ type filter hook input priority -20; policy accept; }'
      ip netns exec "${user}" nft add rule inet laneway_connect_direct_block output \
        ip daddr 10.252.0.4 meta l4proto udp drop
      ip netns exec "${user}" nft add rule inet laneway_connect_direct_block input \
        ip saddr 10.252.0.4 meta l4proto udp drop
    fi

    invite_file="${case_dir}/user-${iteration}.token"
    connect_log="${case_dir}/connect-${iteration}.log"
    (
      umask 077
      ip netns exec "${controller}" "${work_dir}/laneway" invite \
        --config "${case_dir}/controller.toml" --name "temporary-user-${iteration}" \
        --ephemeral --session-lifetime 5m >"${invite_file}" 2>"${case_dir}/invite-${iteration}.log"
    )
    start_process "${user}" "${connect_log}" env SSL_CERT_FILE="${case_dir}/ca.crt" \
      "${work_dir}/laneway" connect "${bootstrap_authority}" --token-file "${invite_file}"
    connect_pid="${last_pid}"
    if [[ "${iteration}" == "1" ]]; then
      wait_log "${connect_pid}" "${connect_log}" "path=relay-quic"
    else
      wait_log "${connect_pid}" "${connect_log}" "path=direct"
    fi
    rm -f -- "${invite_file}"
    ip -n "${user}" link show lane0 >/dev/null
    if [[ "${iteration}" == "1" ]]; then
      start_process "${node}" "${case_dir}/relay-traffic.log" \
        "${work_dir}/netprobe" udp-server -listen "${node_overlay}:9801"
      server_pid="${last_pid}"
      wait_log "${server_pid}" "${case_dir}/relay-traffic.log" "ready=udp-server"
      ip netns exec "${user}" "${work_dir}/netprobe" udp-client \
        -target "${node_overlay}:9801" -message connect-relay -once -timeout 3s
      wait "${server_pid}"
      ip netns exec "${user}" nft delete table inet laneway_connect_direct_block
    else
      start_process "${node}" "${case_dir}/direct-traffic.log" \
        "${work_dir}/netprobe" udp-server -listen "${node_overlay}:9811"
      server_pid="${last_pid}"
      wait_log "${server_pid}" "${case_dir}/direct-traffic.log" "ready=udp-server"
      ip netns exec "${user}" "${work_dir}/netprobe" udp-client \
        -target "${node_overlay}:9811" -message connect-direct -once -timeout 3s
      wait "${server_pid}"
    fi

    stop_process "${connect_pid}"
    grep -q 'laneway disconnected; temporary networking restored' "${connect_log}"
    assert_foreground_network_clean "${user}" "${connect_log}" "${iteration}"
  done

  echo "==> foreground requester death cleans networking and the next run reconciles"
  local crash_token="${case_dir}/user-crash.token" crash_log="${case_dir}/connect-crash.log"
  (
    umask 077
    ip netns exec "${controller}" "${work_dir}/laneway" invite \
      --config "${case_dir}/controller.toml" --name temporary-user-crash \
      --ephemeral --session-lifetime 5m >"${crash_token}" 2>"${case_dir}/invite-crash.log"
  )
  start_process "${user}" "${crash_log}" env SSL_CERT_FILE="${case_dir}/ca.crt" \
    "${work_dir}/laneway" connect "${bootstrap_authority}" --token-file "${crash_token}"
  connect_pid="${last_pid}"
  wait_log "${connect_pid}" "${crash_log}" "path=relay-quic"
  rm -f -- "${crash_token}"
  kill -KILL "${connect_pid}"
  wait "${connect_pid}" >/dev/null 2>&1 || true
  assert_foreground_network_clean "${user}" "${crash_log}" "SIGKILL"

  local recovery_token="${case_dir}/user-recovery.token" recovery_log="${case_dir}/connect-recovery.log"
  (
    umask 077
    ip netns exec "${controller}" "${work_dir}/laneway" invite \
      --config "${case_dir}/controller.toml" --name temporary-user-recovery \
      --ephemeral --session-lifetime 5m >"${recovery_token}" 2>"${case_dir}/invite-recovery.log"
  )
  start_process "${user}" "${recovery_log}" env SSL_CERT_FILE="${case_dir}/ca.crt" \
    "${work_dir}/laneway" connect "${bootstrap_authority}" --token-file "${recovery_token}"
  connect_pid="${last_pid}"
  wait_log "${connect_pid}" "${recovery_log}" "path=relay-quic"
  rm -f -- "${recovery_token}"
  start_process "${node}" "${case_dir}/recovery-traffic.log" \
    "${work_dir}/netprobe" udp-server -listen "${node_overlay}:9821"
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/recovery-traffic.log" "ready=udp-server"
  ip netns exec "${user}" "${work_dir}/netprobe" udp-client \
    -target "${node_overlay}:9821" -message connect-recovery -once -timeout 3s
  wait "${server_pid}"
  stop_process "${connect_pid}"
  grep -q 'laneway disconnected; temporary networking restored' "${recovery_log}"
  assert_foreground_network_clean "${user}" "${recovery_log}" "post-SIGKILL recovery"

  stop_process "${node_pid}"
  stop_process "${relay_pid}"
  stop_process "${controller_pid}"
}

run_controller_subnet_flow() {
  local case_dir="${work_dir}/controller-subnet"
  local switch="${prefix}cs" controller="${prefix}cc" relay="${prefix}cr"
  local client="${prefix}ca" old_client="${prefix}co" gateway="${prefix}cg" lan_host="${prefix}ch"
  local network_id="10000000000000000000000000000001"
  local controller_service="10000000000000000000000000000002"
  local relay_service="10000000000000000000000000000003"
  local controller_endpoint="https://10.253.0.1:8443"
  local controller_quic_endpoint="10.253.0.1:8443"
  local admin_token="laneway-controller-fullstack-admin-token-0000000000000001"

  mkdir -p "${case_dir}"
  printf '%s\n' "${admin_token}" >"${case_dir}/admin.token"
  chmod 600 "${case_dir}/admin.token"
  "${work_dir}/laneway" pki init -out-dir "${case_dir}" >/dev/null
  "${work_dir}/laneway" pki controller -ca-cert "${case_dir}/ca.crt" -ca-key "${case_dir}/ca.key" \
    -network-id "${network_id}" -service-id "${controller_service}" -ip 10.253.0.1 \
    -out-cert "${case_dir}/controller.crt" -out-key "${case_dir}/controller.key"
  "${work_dir}/laneway" pki relay -ca-cert "${case_dir}/ca.crt" -ca-key "${case_dir}/ca.key" \
    -network-id "${network_id}" -service-id "${relay_service}" -ip 10.253.0.2 \
    -out-cert "${case_dir}/relay.crt" -out-key "${case_dir}/relay.key"

  add_switch "${switch}"
  add_namespace "${controller}"
  add_namespace "${relay}"
  add_namespace "${client}"
  add_namespace "${old_client}"
  add_namespace "${gateway}"
  add_namespace "${lan_host}"
  attach_switch "${switch}" "${controller}" eth0 10.253.0.1/24
  attach_switch "${switch}" "${relay}" eth0 10.253.0.2/24
  attach_switch "${switch}" "${client}" eth0 10.253.0.3/24
  attach_switch "${switch}" "${gateway}" eth0 10.253.0.4/24
  attach_switch "${switch}" "${old_client}" eth0 10.253.0.5/24
  connect_namespaces "${gateway}" lan1 192.168.60.1/24 "${lan_host}" eth0 192.168.60.2/24
  ip netns exec "${gateway}" sysctl -qw net.ipv4.ip_forward=0

  cat >"${case_dir}/controller.toml" <<EOF
mode = "controller"
state_dir = "${case_dir}/controller-state"
socket_path = "${case_dir}/controller.sock"
[tls]
certificate = "${case_dir}/controller.crt"
private_key = "${case_dir}/controller.key"
ca = "${case_dir}/ca.crt"
[controller]
listen = "10.253.0.1:8443"
quic_listen = "10.253.0.1:8443"
database = "${case_dir}/controller.db"
ca_private_key = "${case_dir}/ca.key"
admin_token_file = "${case_dir}/admin.token"
leaf_validity = "24h"
EOF

  start_process "${controller}" "${case_dir}/controller.log" \
    "${work_dir}/laneway-controller" -config "${case_dir}/controller.toml" -diagnostics 127.0.0.1:6063
  local controller_pid="${last_pid}"
  wait_log "${controller_pid}" "${case_dir}/controller.log" "laneway-controller HTTPS="

  local network_json created_network_id
  network_json="$(ip netns exec "${controller}" "${work_dir}/laneway" controller network create \
    --network-id "${network_id}" --name controller-fullstack --ipv4-pool 100.99.0.0/24 \
    --controller "${controller_endpoint}" --ca "${case_dir}/ca.crt" \
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
    --admin-token-file "${case_dir}/admin.token")"
  created_network_id="$(printf '%s\n' "${network_json}" | json_string_field network_id)"
  if [[ "${created_network_id}" != "${network_id}" ]]; then
    echo "ERROR: controller did not create the requested network ID" >&2
    printf '%s\n' "${network_json}" >&2
    return 1
  fi

  local -a admin_connection=(
    --controller "${controller_endpoint}" --ca "${case_dir}/ca.crt"
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}"
    --admin-token-file "${case_dir}/admin.token"
  )
  ip netns exec "${controller}" "${work_dir}/laneway" controller relay register \
    --network-id "${network_id}" --service-id "${relay_service}" \
    --name controller-relay --endpoint 10.253.0.2:4433 "${admin_connection[@]}" >"${case_dir}/relay-registration.json"

  local client_token_json gateway_token_json client_token gateway_token
  client_token_json="$(ip netns exec "${controller}" "${work_dir}/laneway" controller enrollment-token issue \
    --network-id "${network_id}" --label client --expires-in 10m "${admin_connection[@]}")"
  gateway_token_json="$(ip netns exec "${controller}" "${work_dir}/laneway" controller enrollment-token issue \
    --network-id "${network_id}" --label gateway --expires-in 10m "${admin_connection[@]}")"
  client_token="$(printf '%s\n' "${client_token_json}" | json_string_field enrollment_token)"
  gateway_token="$(printf '%s\n' "${gateway_token_json}" | json_string_field enrollment_token)"
  if [[ -z "${client_token}" || -z "${gateway_token}" ]]; then
    echo "ERROR: controller did not return enrollment tokens" >&2
    return 1
  fi

  local client_join gateway_join client_id gateway_id client_overlays gateway_overlays client_overlay gateway_overlay
  client_join="$(ip netns exec "${client}" "${work_dir}/laneway" join "${client_token}" \
    --controller "${controller_endpoint}" --ca "${case_dir}/ca.crt" \
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
    --name controller-client --out-cert "${case_dir}/client.crt" --out-key "${case_dir}/client.key" \
    --out-wireguard-key "${case_dir}/client.wireguard.key")"
  gateway_join="$(ip netns exec "${gateway}" "${work_dir}/laneway" join "${gateway_token}" \
    --controller "${controller_endpoint}" --ca "${case_dir}/ca.crt" \
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
    --name controller-gateway --out-cert "${case_dir}/gateway.crt" --out-key "${case_dir}/gateway.key" \
    --out-wireguard-key "${case_dir}/gateway.wireguard.key")"
  client_id="$(printf '%s\n' "${client_join}" | sed -n 's/.* node=\([0-9a-f]\{32\}\) .*/\1/p')"
  gateway_id="$(printf '%s\n' "${gateway_join}" | sed -n 's/.* node=\([0-9a-f]\{32\}\) .*/\1/p')"
  client_overlays="$(printf '%s\n' "${client_join}" | sed -n 's/.* overlay=\([^ ]*\) certificate=.*/\1/p')"
  gateway_overlays="$(printf '%s\n' "${gateway_join}" | sed -n 's/.* overlay=\([^ ]*\) certificate=.*/\1/p')"
  client_overlay="${client_overlays%%,*}"
  gateway_overlay="${gateway_overlays%%,*}"
  if [[ ! "${client_id}" =~ ^[0-9a-f]{32}$ || ! "${gateway_id}" =~ ^[0-9a-f]{32}$ || \
        -z "${client_overlay}" || -z "${gateway_overlay}" ]]; then
    echo "ERROR: failed to parse controller enrollment results" >&2
    printf '%s\n%s\n' "${client_join}" "${gateway_join}" >&2
    return 1
  fi

  ip netns exec "${controller}" "${work_dir}/laneway" controller node capabilities \
    --node-id "${gateway_id}" --subnet-router --exit-node "${admin_connection[@]}" >"${case_dir}/capabilities.json"
  local acl_json acl_id
  acl_json="$(ip netns exec "${controller}" "${work_dir}/laneway" controller acl add \
    --network-id "${network_id}" --priority 100 --action accept \
    --selector '{"ip_protocol":"IP_PROTOCOL_ANY"}' --description fullstack-allow \
    "${admin_connection[@]}")"
  acl_id="$(printf '%s\n' "${acl_json}" | json_string_field rule_id)"
  if [[ ! "${acl_id}" =~ ^[0-9a-f]{32}$ ]]; then
    echo "ERROR: failed to parse controller ACL ID" >&2
    printf '%s\n' "${acl_json}" >&2
    return 1
  fi

  cat >"${case_dir}/relay.toml" <<EOF
mode = "relay"
state_dir = "${case_dir}/relay-state"
socket_path = "${case_dir}/relay.sock"
[tls]
certificate = "${case_dir}/relay.crt"
private_key = "${case_dir}/relay.key"
ca = "${case_dir}/ca.crt"
[relay]
listen = "10.253.0.2:4433"
[controller]
endpoint = "${controller_endpoint}"
quic_endpoint = "${controller_quic_endpoint}"
network_id = "${network_id}"
service_id = "${controller_service}"
poll_interval = "100ms"
EOF
  cat >"${case_dir}/client.toml" <<EOF
mode = "node"
state_dir = "${case_dir}/client-state"
socket_path = "${case_dir}/client.sock"
[tls]
certificate = "${case_dir}/client.crt"
private_key = "${case_dir}/client.key"
ca = "${case_dir}/ca.crt"
[node]
name = "controller-client"
relay_address = "10.253.0.2:4433"
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
[exit]
failure_mode = "closed"
dns_servers = ["1.1.1.1"]
EOF
  cat >"${case_dir}/gateway.toml" <<EOF
mode = "node"
state_dir = "${case_dir}/gateway-state"
socket_path = "${case_dir}/gateway.sock"
[tls]
certificate = "${case_dir}/gateway.crt"
private_key = "${case_dir}/gateway.key"
ca = "${case_dir}/ca.crt"
[node]
name = "controller-gateway"
relay_address = "10.253.0.2:4433"
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
advertise = ["192.168.60.0/24"]
nat = true
output_interface = "lan1"
[exit]
serve = true
EOF

  # systemd-resolved does not run inside these disposable network namespaces.
  # This command-compatible shim supplies only per-link resolver state so the
  # product daemon still executes its real DNS manager and route/DNS transaction.
  # Unit tests exercise failure rollback and ownership conflicts in detail.
  mkdir -p "${case_dir}/resolver-state"
  cat >"${case_dir}/resolvectl" <<'EOF'
#!/bin/sh
set -eu
property="${1:-}"
interface="${2:-}"
if [ -z "${property}" ] || [ -z "${interface}" ] || [ -z "${LANEWAY_RESOLVE_STATE:-}" ]; then
  exit 2
fi
index="$(cat "/sys/class/net/${interface}/ifindex")"
state="${LANEWAY_RESOLVE_STATE}/${index}.${property}"
if [ "${property}" = "revert" ]; then
  rm -f "${LANEWAY_RESOLVE_STATE}/${index}.dns" "${LANEWAY_RESOLVE_STATE}/${index}.domain" \
    "${LANEWAY_RESOLVE_STATE}/${index}.default-route"
  exit 0
fi
shift 2
if [ "$#" -eq 0 ]; then
  value=""
  if [ -f "${state}" ]; then
    value="$(sed -n '1p' "${state}")"
  fi
  printf 'Link %s (%s): %s\n' "${index}" "${interface}" "${value}"
  exit 0
fi
printf '%s\n' "$*" >"${state}"
EOF
  chmod 700 "${case_dir}/resolvectl"

  start_process "${relay}" "${case_dir}/relay.log" "${work_dir}/laneway-relay" \
    -config "${case_dir}/relay.toml" -diagnostics 127.0.0.1:6060
  local relay_pid="${last_pid}"
  wait_log "${relay_pid}" "${case_dir}/relay.log" "listening"
  start_process "${client}" "${case_dir}/client.log" env \
    PATH="${case_dir}:${PATH}" LANEWAY_RESOLVE_STATE="${case_dir}/resolver-state" \
    "${work_dir}/lanewayd" -config "${case_dir}/client.toml" -diagnostics 127.0.0.1:6061
  local client_pid="${last_pid}"
  start_process "${gateway}" "${case_dir}/gateway.log" "${work_dir}/lanewayd" \
    -config "${case_dir}/gateway.toml" -diagnostics 127.0.0.1:6062
  local gateway_pid="${last_pid}"
  wait_log "${client_pid}" "${case_dir}/client.log" "interface=lane0"
  wait_log "${gateway_pid}" "${case_dir}/gateway.log" "interface=lane0"
  if ip -n "${client}" route show exact 192.168.60.0/24 | grep -q .; then
    echo "ERROR: unapproved subnet route was installed before controller approval" >&2
    return 1
  fi

  echo "==> controller CLI approval is polled into both daemons and the relay"
  local route_json route_id
  route_json="$(ip netns exec "${gateway}" "${work_dir}/laneway" route advertise 192.168.60.0/24 \
    --kind subnet --mode nat --controller "${controller_endpoint}" --ca "${case_dir}/ca.crt" \
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
    --cert "${case_dir}/gateway.crt" --key "${case_dir}/gateway.key")"
  route_id="$(printf '%s\n' "${route_json}" | json_string_field route_id)"
  if [[ ! "${route_id}" =~ ^[0-9a-f]{32}$ ]]; then
    echo "ERROR: failed to parse advertised route ID" >&2
    printf '%s\n' "${route_json}" >&2
    return 1
  fi
  ip netns exec "${controller}" "${work_dir}/laneway" controller route approve \
    --route-id "${route_id}" "${admin_connection[@]}" >"${case_dir}/route-approval.json"

  local applied=0
  for _ in $(seq 1 200); do
    if ip -n "${client}" route show exact 192.168.60.0/24 | grep -q 'dev lane0' && \
       ip netns exec "${gateway}" nft list table inet laneway 2>/dev/null | grep -q '192.168.60.0/24' && \
       [[ "$(ip netns exec "${gateway}" sysctl -n net.ipv4.ip_forward)" == "1" ]]; then
      applied=1
      break
    fi
    sleep 0.05
  done
  if [[ "${applied}" != "1" ]]; then
    echo "ERROR: approved controller route was not applied to the kernel dataplane" >&2
    sed -n '1,240p' "${case_dir}/client.log" >&2
    sed -n '1,240p' "${case_dir}/gateway.log" >&2
    ip netns exec "${gateway}" nft list ruleset >&2 || true
    return 1
  fi

  echo "==> controller-approved subnet route carries a real NATed application packet"
  start_process "${lan_host}" "${case_dir}/nat-server.log" "${work_dir}/netprobe" udp-server -listen 192.168.60.2:9401
  local server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/nat-server.log" "ready=udp-server"
  ip netns exec "${client}" "${work_dir}/netprobe" udp-client -target 192.168.60.2:9401 -message controller-subnet
  wait "${server_pid}"
  grep -q 'remote=192.168.60.1:' "${case_dir}/nat-server.log"

  echo "==> live node renews into a staged pair and promotes it while stopped"
  local old_certificate_info old_serial renew_output renewed_certificate_info
  old_certificate_info="$("${work_dir}/netprobe" certificate-info -cert "${case_dir}/client.crt")"
  old_serial="$(printf '%s\n' "${old_certificate_info}" | sed -n 's/.* serial=\([0-9a-f]*\)$/\1/p')"
  if [[ "${old_certificate_info}" != *"network=${network_id}"* || \
        "${old_certificate_info}" != *"node=${client_id}"* || ! "${old_serial}" =~ ^[0-9a-f]{2,64}$ ]]; then
    echo "ERROR: failed to inspect enrolled client certificate" >&2
    printf '%s\n' "${old_certificate_info}" >&2
    return 1
  fi
  renew_output="$(ip netns exec "${client}" "${work_dir}/laneway" renew \
    --controller "${controller_endpoint}" --controller-quic "${controller_quic_endpoint}" \
    --ca "${case_dir}/ca.crt" \
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
    --cert "${case_dir}/client.crt" --key "${case_dir}/client.key" \
    --out-cert "${case_dir}/client.next.crt" --out-key "${case_dir}/client.next.key" \
    --out-wireguard-key "${case_dir}/client.wireguard.next.key")"
  if [[ "${renew_output}" != *"network=${network_id}"* || "${renew_output}" != *"node=${client_id}"* ]]; then
    echo "ERROR: renewal changed the immutable node identity" >&2
    printf '%s\n' "${renew_output}" >&2
    return 1
  fi
  renewed_certificate_info="$("${work_dir}/netprobe" certificate-info -cert "${case_dir}/client.next.crt")"
  if [[ "${renewed_certificate_info}" != *"network=${network_id}"* || \
        "${renewed_certificate_info}" != *"node=${client_id}"* || \
        "${renewed_certificate_info}" == *"serial=${old_serial}" ]]; then
    echo "ERROR: staged renewal identity/serial is invalid" >&2
    printf '%s\n' "${renewed_certificate_info}" >&2
    return 1
  fi
  if cmp -s "${case_dir}/client.crt" "${case_dir}/client.next.crt" || \
     cmp -s "${case_dir}/client.key" "${case_dir}/client.next.key"; then
    echo "ERROR: renewal did not produce a distinct staged certificate and key" >&2
    return 1
  fi
  cp "${case_dir}/client.crt" "${case_dir}/client.old.crt"
  cp "${case_dir}/client.key" "${case_dir}/client.old.key"
  chmod 644 "${case_dir}/client.old.crt"
  chmod 600 "${case_dir}/client.old.key"
  stop_process "${client_pid}"
  mv "${case_dir}/client.next.crt" "${case_dir}/client.crt"
  mv "${case_dir}/client.next.key" "${case_dir}/client.key"
  chmod 644 "${case_dir}/client.crt"
  chmod 600 "${case_dir}/client.key"
  start_process "${client}" "${case_dir}/client-renewed.log" env \
    PATH="${case_dir}:${PATH}" LANEWAY_RESOLVE_STATE="${case_dir}/resolver-state" \
    "${work_dir}/lanewayd" -config "${case_dir}/client.toml" -diagnostics 127.0.0.1:6061
  client_pid="${last_pid}"
  wait_log "${client_pid}" "${case_dir}/client-renewed.log" "interface=lane0"
  local renewed_connected=0 relay_sessions
  for _ in $(seq 1 200); do
    relay_sessions="$(ip netns exec "${relay}" "${work_dir}/netprobe" metric \
      -url http://127.0.0.1:6060/metrics -name laneway_relay_sessions 2>/dev/null || true)"
    if [[ "${relay_sessions}" == "2" ]]; then
      renewed_connected=1
      break
    fi
    sleep 0.05
  done
  if [[ "${renewed_connected}" != "1" ]]; then
    echo "ERROR: renewed client did not establish an authenticated relay session" >&2
    sed -n '1,260p' "${case_dir}/client-renewed.log" >&2
    return 1
  fi
  start_process "${lan_host}" "${case_dir}/renewed-server.log" "${work_dir}/netprobe" \
    udp-server -listen 192.168.60.2:9403
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/renewed-server.log" "ready=udp-server"
  ip netns exec "${client}" "${work_dir}/netprobe" udp-client \
    -target 192.168.60.2:9403 -message renewed-subnet
  wait "${server_pid}"
  grep -q 'remote=192.168.60.1:' "${case_dir}/renewed-server.log"

  echo "==> revoking only the old serial preserves renewed traffic and rejects the old pair"
  ip netns exec "${controller}" "${work_dir}/laneway" controller certificate revoke \
    --network-id "${network_id}" --serial "${old_serial}" --reason superseded-by-renewal \
    "${admin_connection[@]}" >"${case_dir}/old-certificate-revocation.json"
  sleep 1
  relay_sessions="$(ip netns exec "${relay}" "${work_dir}/netprobe" metric \
    -url http://127.0.0.1:6060/metrics -name laneway_relay_sessions)"
  if [[ "${relay_sessions}" != "2" ]]; then
    echo "ERROR: revoking the old serial closed the renewed session (sessions=${relay_sessions})" >&2
    return 1
  fi
  cat >"${case_dir}/old-client.toml" <<EOF
mode = "node"
state_dir = "${case_dir}/old-client-state"
socket_path = "${case_dir}/old-client.sock"
[tls]
certificate = "${case_dir}/client.old.crt"
private_key = "${case_dir}/client.old.key"
ca = "${case_dir}/ca.crt"
[node]
name = "revoked-old-client"
relay_address = "10.253.0.2:4433"
relay_network_id = "${network_id}"
relay_service_id = "${relay_service}"
overlay_addresses = ["${client_overlay}"]
reconnect_min = "50ms"
reconnect_max = "500ms"
EOF
  local old_connections old_quic_failures old_client_pid old_rejected=0
  start_process "${old_client}" "${case_dir}/old-client.log" "${work_dir}/lanewayd" \
    -config "${case_dir}/old-client.toml" -diagnostics 127.0.0.1:6064
  old_client_pid="${last_pid}"
  wait_log "${old_client_pid}" "${case_dir}/old-client.log" "interface=lane0"
  for _ in $(seq 1 200); do
    old_connections="$(ip netns exec "${old_client}" "${work_dir}/netprobe" metric \
      -url http://127.0.0.1:6064/metrics -name laneway_node_connections_total 2>/dev/null || true)"
    old_quic_failures="$(ip netns exec "${old_client}" "${work_dir}/netprobe" metric \
      -url http://127.0.0.1:6064/metrics -name laneway_node_quic_failures_total 2>/dev/null || true)"
    relay_sessions="$(ip netns exec "${relay}" "${work_dir}/netprobe" metric \
      -url http://127.0.0.1:6060/metrics -name laneway_relay_sessions 2>/dev/null || true)"
    if [[ "${old_connections}" == "0" && "${old_quic_failures:-0}" =~ ^[0-9]+$ ]] && \
       (( old_quic_failures > 0 )) && [[ "${relay_sessions}" == "2" ]]; then
      old_rejected=1
      break
    fi
    sleep 0.05
  done
  stop_process "${old_client_pid}"
  if [[ "${old_rejected}" != "1" ]]; then
    echo "ERROR: revoked old credential was not rejected (connections=${old_connections:-unknown}, quic_failures=${old_quic_failures:-unknown}, sessions=${relay_sessions:-unknown})" >&2
    sed -n '1,260p' "${case_dir}/old-client.log" >&2
    return 1
  fi
  start_process "${lan_host}" "${case_dir}/renewed-after-revoke-server.log" "${work_dir}/netprobe" \
    udp-server -listen 192.168.60.2:9404
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/renewed-after-revoke-server.log" "ready=udp-server"
  ip netns exec "${client}" "${work_dir}/netprobe" udp-client \
    -target 192.168.60.2:9404 -message renewed-after-old-revoke
  wait "${server_pid}"
  grep -q 'remote=192.168.60.1:' "${case_dir}/renewed-after-revoke-server.log"

  echo "==> deleting the controller ACL fails closed while the kernel route remains installed"
  ip netns exec "${controller}" "${work_dir}/laneway" controller acl delete \
    --rule-id "${acl_id}" "${admin_connection[@]}" >"${case_dir}/acl-delete.json"
  sleep 1
  start_process "${lan_host}" "${case_dir}/denied-server.log" "${work_dir}/netprobe" udp-server -listen 192.168.60.2:9402
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/denied-server.log" "ready=udp-server"
  if ip netns exec "${client}" "${work_dir}/netprobe" udp-client \
      -target 192.168.60.2:9402 -message should-be-denied -timeout 2s; then
    echo "ERROR: controller default-deny ACL was not applied" >&2
    return 1
  fi
  kill -TERM "${server_pid}" >/dev/null 2>&1 || true
  wait "${server_pid}" >/dev/null 2>&1 || true
  ip -n "${client}" route show exact 192.168.60.0/24 | grep -q 'dev lane0'

  echo "==> node withdrawal is polled into transactional route, nftables, and sysctl cleanup"
  ip netns exec "${gateway}" "${work_dir}/laneway" controller route withdraw \
    --route-id "${route_id}" --controller "${controller_endpoint}" --ca "${case_dir}/ca.crt" \
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
    --cert "${case_dir}/gateway.crt" --key "${case_dir}/gateway.key" >"${case_dir}/route-withdrawal.json"
  local removed=0
  for _ in $(seq 1 200); do
    if ! ip -n "${client}" route show exact 192.168.60.0/24 | grep -q . && \
       ! ip netns exec "${gateway}" nft list table inet laneway >/dev/null 2>&1 && \
       [[ "$(ip netns exec "${gateway}" sysctl -n net.ipv4.ip_forward)" == "0" ]]; then
      removed=1
      break
    fi
    sleep 0.05
  done
  if [[ "${removed}" != "1" ]]; then
    echo "ERROR: withdrawn controller route left kernel dataplane state behind" >&2
    ip -n "${client}" route show exact 192.168.60.0/24 >&2 || true
    ip netns exec "${gateway}" nft list ruleset >&2 || true
    return 1
  fi

  echo "==> controller-approved exit is selected through the CLI and installed by lanewayd"
  local exit_acl_json exit_acl_id exit_json exit_route_id
  exit_acl_json="$(ip netns exec "${controller}" "${work_dir}/laneway" controller acl add \
    --network-id "${network_id}" --priority 110 --action accept \
    --selector '{"ip_protocol":"IP_PROTOCOL_ANY"}' --description fullstack-exit-allow \
    "${admin_connection[@]}")"
  exit_acl_id="$(printf '%s\n' "${exit_acl_json}" | json_string_field rule_id)"
  if [[ ! "${exit_acl_id}" =~ ^[0-9a-f]{32}$ ]]; then
    echo "ERROR: failed to parse replacement controller ACL ID" >&2
    printf '%s\n' "${exit_acl_json}" >&2
    return 1
  fi
  exit_json="$(ip netns exec "${gateway}" "${work_dir}/laneway" exit enable \
    --family ipv4 --config "${case_dir}/gateway.toml")"
  exit_route_id="$(printf '%s\n' "${exit_json}" | json_string_field route_id | head -n 1)"
  if [[ ! "${exit_route_id}" =~ ^[0-9a-f]{32}$ ]]; then
    echo "ERROR: failed to parse exit route advertisement" >&2
    printf '%s\n' "${exit_json}" >&2
    return 1
  fi
  ip netns exec "${controller}" "${work_dir}/laneway" controller route approve \
    --route-id "${exit_route_id}" "${admin_connection[@]}" >"${case_dir}/exit-route-approval.json"

  local gateway_exit_ready=0
  for _ in $(seq 1 200); do
    if ip netns exec "${gateway}" nft list table inet laneway_exit >/dev/null 2>&1; then
      gateway_exit_ready=1
      break
    fi
    sleep 0.05
  done
  if [[ "${gateway_exit_ready}" != "1" ]]; then
    echo "ERROR: approved exit route did not activate the gateway daemon" >&2
    sed -n '1,260p' "${case_dir}/gateway.log" >&2
    return 1
  fi
  ip netns exec "${client}" "${work_dir}/laneway" exit use controller-gateway \
    --config "${case_dir}/client.toml" >"${case_dir}/exit-use.txt"
  local exit_selected=0
  for _ in $(seq 1 200); do
    if ip -n "${client}" -4 rule show priority 11000 | grep -q 'lookup 51820' && \
       ip -n "${client}" route show table 51820 exact 0.0.0.0/1 | grep -q 'dev lane0' && \
       ip -n "${client}" route show table 51820 exact 128.0.0.0/1 | grep -q 'dev lane0'; then
      exit_selected=1
      break
    fi
    sleep 0.05
  done
  if [[ "${exit_selected}" != "1" ]]; then
    echo "ERROR: CLI-selected controller exit did not install policy routes" >&2
    sed -n '1,260p' "${case_dir}/client.log" >&2
    return 1
  fi
  ip -n "${client}" route show table 51820 exact 10.253.0.1/32 | grep -q 'dev eth0'
  ip -n "${client}" route show table 51820 exact 10.253.0.2/32 | grep -q 'dev eth0'
  if [[ "$(stat -c '%a' "${case_dir}/client-state/exit-intent-v1.json")" != "600" ]]; then
    echo "ERROR: persisted exit intent is not mode 0600" >&2
    return 1
  fi
  grep -q '"enabled":true' "${case_dir}/client-state/exit-intent-v1.json"
  grep -q '"failure_mode":"closed"' "${case_dir}/client-state/exit-intent-v1.json"

  echo "==> selected exit carries a real packet through daemon-installed gateway NAT"
  start_process "${lan_host}" "${case_dir}/exit-nat-server.log" "${work_dir}/netprobe" \
    udp-server -listen 192.168.60.2:9501
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/exit-nat-server.log" "ready=udp-server"
  ip netns exec "${client}" "${work_dir}/netprobe" udp-client \
    -target 192.168.60.2:9501 -message controller-exit
  wait "${server_pid}"
  grep -q 'remote=192.168.60.1:' "${case_dir}/exit-nat-server.log"
  run_kernel_udp_benchmark "${lan_host}" "${client}" 192.168.60.2:9590 192.168.60.2:9590 \
    controller-exit-nat-kernel "${case_dir}/controller-exit-benchmark-server.log"

  echo "==> SIGKILL restart reloads persisted closed intent and adopts partial kernel residue"
  kill -KILL "${client_pid}" >/dev/null 2>&1 || true
  wait "${client_pid}" >/dev/null 2>&1 || true
  local tun_removed=0
  for _ in $(seq 1 100); do
    if ! ip -n "${client}" link show dev lane0 >/dev/null 2>&1; then
      tun_removed=1
      break
    fi
    sleep 0.05
  done
  if [[ "${tun_removed}" != "1" ]]; then
    echo "ERROR: crashed client TUN did not disappear" >&2
    return 1
  fi
  ip -n "${client}" -4 rule show priority 11000 | grep -q 'lookup 51820'
  start_process "${client}" "${case_dir}/client-restart-closed.log" env \
    PATH="${case_dir}:${PATH}" LANEWAY_RESOLVE_STATE="${case_dir}/resolver-state" \
    "${work_dir}/lanewayd" -config "${case_dir}/client.toml" -diagnostics 127.0.0.1:6061
  client_pid="${last_pid}"
  wait_log "${client_pid}" "${case_dir}/client-restart-closed.log" "interface=lane0"
  exit_selected=0
  for _ in $(seq 1 200); do
    if ip -n "${client}" -4 rule show priority 11000 | grep -q 'lookup 51820' && \
       ip -n "${client}" route show table 51820 exact 0.0.0.0/1 | grep -q 'dev lane0'; then
      exit_selected=1
      break
    fi
    sleep 0.05
  done
  if [[ "${exit_selected}" != "1" ]]; then
    echo "ERROR: restarted daemon did not recover persisted exit policy" >&2
    sed -n '1,260p' "${case_dir}/client-restart-closed.log" >&2
    return 1
  fi

  echo "==> fail-closed retains policy routes after the selected path disappears"
  stop_process "${gateway_pid}"
  local relay_reduced=0 relay_sessions
  for _ in $(seq 1 200); do
    relay_sessions="$(ip netns exec "${relay}" "${work_dir}/netprobe" metric \
      -url http://127.0.0.1:6060/metrics -name laneway_relay_sessions 2>/dev/null || true)"
    if [[ "${relay_sessions}" == "1" ]]; then
      relay_reduced=1
      break
    fi
    sleep 0.05
  done
  if [[ "${relay_reduced}" != "1" ]]; then
    echo "ERROR: stopped exit gateway retained a relay session" >&2
    return 1
  fi
  sleep 2
  ip -n "${client}" -4 rule show priority 11000 | grep -q 'lookup 51820'
  ip -n "${client}" route show table 51820 exact 0.0.0.0/1 | grep -q 'dev lane0'
  start_process "${lan_host}" "${case_dir}/closed-denied-server.log" "${work_dir}/netprobe" \
    udp-server -listen 192.168.60.2:9502
  server_pid="${last_pid}"
  wait_log "${server_pid}" "${case_dir}/closed-denied-server.log" "ready=udp-server"
  if ip netns exec "${client}" "${work_dir}/netprobe" udp-client \
      -target 192.168.60.2:9502 -message closed-must-not-leak -timeout 2s; then
    echo "ERROR: fail-closed packet escaped after exit path loss" >&2
    return 1
  fi
  kill -TERM "${server_pid}" >/dev/null 2>&1 || true
  wait "${server_pid}" >/dev/null 2>&1 || true

  start_process "${gateway}" "${case_dir}/gateway-restart-closed.log" "${work_dir}/lanewayd" \
    -config "${case_dir}/gateway.toml" -diagnostics 127.0.0.1:6062
  gateway_pid="${last_pid}"
  wait_log "${gateway_pid}" "${case_dir}/gateway-restart-closed.log" "interface=lane0"
  for _ in $(seq 1 200); do
    relay_sessions="$(ip netns exec "${relay}" "${work_dir}/netprobe" metric \
      -url http://127.0.0.1:6060/metrics -name laneway_relay_sessions 2>/dev/null || true)"
    if [[ "${relay_sessions}" == "2" ]] && ip netns exec "${gateway}" nft list table inet laneway_exit >/dev/null 2>&1; then
      break
    fi
    sleep 0.05
  done

  echo "==> durable disable overrides static selection; a new open selection removes routes on path loss"
  ip netns exec "${client}" "${work_dir}/laneway" exit disable \
    --config "${case_dir}/client.toml" >"${case_dir}/exit-disable.txt"
  grep -qx '{"version":1,"enabled":false}' "${case_dir}/client-state/exit-intent-v1.json"
  stop_process "${client_pid}"
  sed -i 's/failure_mode = "closed"/failure_mode = "open"/' "${case_dir}/client.toml"
  start_process "${client}" "${case_dir}/client-open.log" env \
    PATH="${case_dir}:${PATH}" LANEWAY_RESOLVE_STATE="${case_dir}/resolver-state" \
    "${work_dir}/lanewayd" -config "${case_dir}/client.toml" -diagnostics 127.0.0.1:6061
  client_pid="${last_pid}"
  wait_log "${client_pid}" "${case_dir}/client-open.log" "interface=lane0"
  if ip -n "${client}" -4 rule show priority 11000 | grep -q .; then
    echo "ERROR: static configuration overrode durable CLI disable" >&2
    return 1
  fi
  ip netns exec "${client}" "${work_dir}/laneway" exit use controller-gateway \
    --config "${case_dir}/client.toml" >"${case_dir}/exit-use-open.txt"
  for _ in $(seq 1 200); do
    if ip -n "${client}" -4 rule show priority 11000 | grep -q 'lookup 51820'; then
      break
    fi
    sleep 0.05
  done
  grep -q '"failure_mode":"open"' "${case_dir}/client-state/exit-intent-v1.json"
  stop_process "${gateway_pid}"
  local open_removed=0
  for _ in $(seq 1 240); do
    if ! ip -n "${client}" -4 rule show priority 11000 | grep -q .; then
      open_removed=1
      break
    fi
    sleep 0.05
  done
  if [[ "${open_removed}" != "1" ]]; then
    echo "ERROR: fail-open did not remove exit policy after path loss" >&2
    sed -n '1,260p' "${case_dir}/client-open.log" >&2
    return 1
  fi
  start_process "${gateway}" "${case_dir}/gateway-restart-open.log" "${work_dir}/lanewayd" \
    -config "${case_dir}/gateway.toml" -diagnostics 127.0.0.1:6062
  gateway_pid="${last_pid}"
  wait_log "${gateway_pid}" "${case_dir}/gateway-restart-open.log" "interface=lane0"
  exit_selected=0
  for _ in $(seq 1 240); do
    if ip -n "${client}" -4 rule show priority 11000 | grep -q 'lookup 51820' && \
       ip netns exec "${gateway}" nft list table inet laneway_exit >/dev/null 2>&1; then
      exit_selected=1
      break
    fi
    sleep 0.05
  done
  if [[ "${exit_selected}" != "1" ]]; then
    echo "ERROR: fail-open selection did not recover when path returned" >&2
    return 1
  fi

  echo "==> withdrawing the approved exit removes client policy and gateway NAT while intent remains explicit"
  ip netns exec "${gateway}" "${work_dir}/laneway" controller route withdraw \
    --route-id "${exit_route_id}" --controller "${controller_endpoint}" --ca "${case_dir}/ca.crt" \
    --controller-network-id "${network_id}" --controller-service-id "${controller_service}" \
    --cert "${case_dir}/gateway.crt" --key "${case_dir}/gateway.key" >"${case_dir}/exit-route-withdrawal.json"
  local exit_removed=0
  for _ in $(seq 1 240); do
    if ! ip -n "${client}" -4 rule show priority 11000 | grep -q . && \
       ! ip netns exec "${gateway}" nft list table inet laneway_exit >/dev/null 2>&1; then
      exit_removed=1
      break
    fi
    sleep 0.05
  done
  if [[ "${exit_removed}" != "1" ]]; then
    echo "ERROR: withdrawn exit authorization left product kernel state" >&2
    return 1
  fi
  grep -q '"enabled":true' "${case_dir}/client-state/exit-intent-v1.json"

  echo "==> controller node revocation reaches the live relay and closes the authenticated session"
  ip netns exec "${controller}" "${work_dir}/laneway" controller node revoke \
    --node-id "${gateway_id}" --reason fullstack-decommission "${admin_connection[@]}" >"${case_dir}/node-revocation.json"
  local revoked=0 relay_sessions
  for _ in $(seq 1 200); do
    relay_sessions="$(ip netns exec "${relay}" "${work_dir}/netprobe" metric \
      -url http://127.0.0.1:6060/metrics -name laneway_relay_sessions 2>/dev/null || true)"
    if [[ "${relay_sessions}" == "1" ]]; then
      revoked=1
      break
    fi
    sleep 0.05
  done
  if [[ "${revoked}" != "1" ]]; then
    echo "ERROR: revoked node retained a live relay session (sessions=${relay_sessions:-unknown})" >&2
    sed -n '1,240p' "${case_dir}/relay.log" >&2
    return 1
  fi
  ip netns exec "${controller}" "${work_dir}/laneway" controller audit \
    --network-id "${network_id}" --limit 100 "${admin_connection[@]}" >"${case_dir}/audit.json"
  for action in network.create node.enroll certificate.issue certificate.revoke node.capabilities.set route.advertise route.approve acl_rule.create acl_rule.delete route.withdraw node.revoke; do
    grep -q "\"action\": \"${action}\"" "${case_dir}/audit.json"
  done

  echo "==> malformed persisted exit intent aborts startup before host reconciliation"
  stop_process "${client_pid}"
  printf '%s\n' '{"version":1,"enabled":false,"unexpected":true}' \
    >"${case_dir}/client-state/exit-intent-v1.json"
  chmod 600 "${case_dir}/client-state/exit-intent-v1.json"
  if ip netns exec "${client}" env PATH="${case_dir}:${PATH}" \
      LANEWAY_RESOLVE_STATE="${case_dir}/resolver-state" \
      "${work_dir}/lanewayd" -config "${case_dir}/client.toml" \
      >"${case_dir}/client-malformed-intent.log" 2>&1; then
    echo "ERROR: daemon accepted malformed persisted exit intent" >&2
    return 1
  fi
  grep -q 'load persisted exit intent' "${case_dir}/client-malformed-intent.log"
  grep -q 'unknown member "unexpected"' "${case_dir}/client-malformed-intent.log"

  stop_process "${client_pid}"
  stop_process "${gateway_pid}"
  stop_process "${relay_pid}"
  stop_process "${controller_pid}"
}

case "${LANEWAY_INTEGRATION_CASE:-all}" in
  all)
    run_overlay_and_subnet
    run_exit_flow
    run_direct_nat_flow
    run_controller_wireguard_carriers
    run_controller_connect_flow
    run_controller_subnet_flow
    ;;
  overlay-subnet) run_overlay_and_subnet ;;
  exit) run_exit_flow ;;
  direct-nat) run_direct_nat_flow ;;
  controller-wireguard) run_controller_wireguard_carriers ;;
  controller-connect) run_controller_connect_flow ;;
  controller-subnet) run_controller_subnet_flow ;;
  *)
    echo "ERROR: unknown LANEWAY_INTEGRATION_CASE=${LANEWAY_INTEGRATION_CASE}" >&2
    exit 1
    ;;
esac

if [[ -n "${LANEWAY_KERNEL_BENCHMARK_OUTPUT:-}" && "${LANEWAY_INTEGRATION_CASE:-all}" == "all" ]]; then
  command -v jq >/dev/null
  jq -e -s '
    length == 4 and
    ([.[].scenario] | sort == ["controller-exit-nat-kernel", "exit-nat-kernel", "subnet-nat-kernel", "subnet-routed-kernel"]) and
    all(.schema == "laneway-kernel-datapath-benchmark-v1" and
        .scope == "production-kernel-tun-routes-nat-nftables" and
        .generated > 0 and .sent > 0 and .received > 0 and .bytes > 0 and
        .generated == (.sent + .send_errors) and .sent == (.received + .drops) and
        .bytes == (.received * .packet_size) and .duration_ms > 0 and
        .resource_duration_ms >= .duration_ms and
        (.flows == 1 or .flows == 10 or .flows == 100) and
        .packet_size >= 16 and .packet_size <= 60000 and
        .pps > 0 and .gbps > 0 and
        .loss_percent >= 0 and .loss_percent <= 100 and
        .latency_samples > 0 and .latency_samples <= .received and
        .bad == 0 and .rss_bytes > 0 and .allocations >= 0 and
        .cpu_percent >= 0 and .p50_us >= 0 and .p95_us >= .p50_us and .p99_us >= .p95_us)
  ' "${LANEWAY_KERNEL_BENCHMARK_OUTPUT}" >/dev/null
fi

echo "PASS: requested full-stack namespace flows (${LANEWAY_INTEGRATION_CASE:-all})"
