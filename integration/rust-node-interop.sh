#!/usr/bin/env bash
set -euo pipefail

if [[ "${LANEWAY_RUN_PRIVILEGED:-0}" != "1" ]]; then
  echo "SKIP: set LANEWAY_RUN_PRIVILEGED=1 to run Rust node interoperability"
  exit 0
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "ERROR: Rust node interoperability requires root" >&2
  exit 1
fi
for command in cargo go ip nft grep ping; do
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
work_dir="$(mktemp -d -t laneway-rust-node.XXXXXX)"
prefix="lwri$$_"
switch="${prefix}s"
relay_ns="${prefix}r"
node_a_ns="${prefix}a"
node_b_ns="${prefix}b"
lan_ns="${prefix}l"
external_ns="${prefix}e"
declare -a processes=()
last_pid=""

cleanup() {
  for pid in "${processes[@]:-}"; do
    kill -INT "${pid}" >/dev/null 2>&1 || true
  done
  sleep 0.1
  for pid in "${processes[@]:-}"; do
    kill -KILL "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
  done
  for namespace in "${external_ns}" "${lan_ns}" "${node_a_ns}" "${node_b_ns}" "${relay_ns}" "${switch}"; do
    ip netns delete "${namespace}" >/dev/null 2>&1 || true
  done
  rm -rf -- "${work_dir}"
}
trap cleanup EXIT INT TERM

(
  cd "${repo_root}/go"
  go build -o "${work_dir}/laneway" ./cmd/laneway
  go build -o "${work_dir}/go-node" ./cmd/laneway
  go build -o "${work_dir}/go-relay" ./cmd/laneway-relay
  go build -o "${work_dir}/netprobe" ./integration/netprobe
)
cargo build --quiet --locked --manifest-path "${repo_root}/rust/Cargo.toml" -p lanewayd-rs -p laneway-relay
cp "${repo_root}/rust/target/debug/lanewayd-rs" "${work_dir}/rust-node"
cp "${repo_root}/rust/target/debug/laneway-relay" "${work_dir}/rust-relay"

network_id="00000000000000000000000000000001"
node_a_id="00000000000000000000000000000002"
node_b_id="00000000000000000000000000000003"
relay_id="00000000000000000000000000000004"
relay_ip="10.253.0.1"
node_a_v4="100.113.0.1"
node_b_v4="100.113.0.2"
node_a_v6="fd71:6e65:7761::1"
node_b_v6="fd71:6e65:7761::2"

"${work_dir}/laneway" pki init -out-dir "${work_dir}/pki" >/dev/null
"${work_dir}/laneway" pki relay \
  -ca-cert "${work_dir}/pki/ca.crt" -ca-key "${work_dir}/pki/ca.key" \
  -network-id "${network_id}" -service-id "${relay_id}" -ip "${relay_ip}" \
  -out-cert "${work_dir}/pki/relay.crt" -out-key "${work_dir}/pki/relay.key"
"${work_dir}/laneway" pki node \
  -ca-cert "${work_dir}/pki/ca.crt" -ca-key "${work_dir}/pki/ca.key" \
  -network-id "${network_id}" -node-id "${node_a_id}" \
  -out-cert "${work_dir}/pki/a.crt" -out-key "${work_dir}/pki/a.key"
"${work_dir}/laneway" pki node \
  -ca-cert "${work_dir}/pki/ca.crt" -ca-key "${work_dir}/pki/ca.key" \
  -network-id "${network_id}" -node-id "${node_b_id}" \
  -out-cert "${work_dir}/pki/b.crt" -out-key "${work_dir}/pki/b.key"

ip netns add "${switch}"
ip netns add "${relay_ns}"
ip netns add "${node_a_ns}"
ip netns add "${node_b_ns}"
ip netns add "${lan_ns}"
ip netns add "${external_ns}"
for namespace in "${switch}" "${relay_ns}" "${node_a_ns}" "${node_b_ns}" "${lan_ns}" "${external_ns}"; do
  ip -n "${namespace}" link set lo up
done
ip -n "${switch}" link add br0 type bridge
ip -n "${switch}" link set br0 up

attach() {
  local namespace="$1" interface_name="$2" address="$3" suffix="$4"
  local switch_end="s${suffix}x$$" target_end="t${suffix}x$$"
  ip link add "${switch_end}" type veth peer name "${target_end}"
  ip link set "${switch_end}" netns "${switch}"
  ip link set "${target_end}" netns "${namespace}"
  ip -n "${switch}" link set "${switch_end}" master br0
  ip -n "${switch}" link set "${switch_end}" up
  ip -n "${namespace}" link set "${target_end}" name "${interface_name}"
  ip -n "${namespace}" address add "${address}" dev "${interface_name}"
  ip -n "${namespace}" link set "${interface_name}" up
}
attach "${relay_ns}" eth0 10.253.0.1/24 1
attach "${node_a_ns}" eth0 10.253.0.2/24 2
attach "${node_b_ns}" eth0 10.253.0.3/24 3

ip link add "la$$" type veth peer name "lh$$"
ip link set "la$$" netns "${node_a_ns}"
ip link set "lh$$" netns "${lan_ns}"
ip -n "${node_a_ns}" link set "la$$" name lan0
ip -n "${lan_ns}" link set "lh$$" name eth0
ip -n "${node_a_ns}" address add 192.168.77.1/24 dev lan0
ip -n "${node_a_ns}" address add 192.168.78.1/24 dev lan0
ip -n "${lan_ns}" address add 192.168.77.2/24 dev eth0
ip -n "${lan_ns}" address add 192.168.78.2/24 dev eth0
ip -n "${node_a_ns}" link set lan0 up
ip -n "${lan_ns}" link set eth0 up
ip -n "${lan_ns}" route add "${node_b_v4}/32" via 192.168.78.1

ip link add "wa$$" type veth peer name "we$$"
ip link set "wa$$" netns "${node_a_ns}"
ip link set "we$$" netns "${external_ns}"
ip -n "${node_a_ns}" link set "wa$$" name wan0
ip -n "${external_ns}" link set "we$$" name eth0
ip -n "${node_a_ns}" address add 203.0.113.1/24 dev wan0
ip -n "${node_a_ns}" address add 2001:db8:253::1/64 dev wan0
ip -n "${external_ns}" address add 203.0.113.2/24 dev eth0
ip -n "${external_ns}" address add 2001:db8:253::2/64 dev eth0
ip -n "${node_a_ns}" link set wan0 up
ip -n "${external_ns}" link set eth0 up

cat >"${work_dir}/go-relay.toml" <<EOF
mode = "relay"
state_dir = "${work_dir}/go-relay-state"
socket_path = "${work_dir}/go-relay.sock"
[tls]
certificate = "${work_dir}/pki/relay.crt"
private_key = "${work_dir}/pki/relay.key"
ca = "${work_dir}/pki/ca.crt"
[relay]
listen = "${relay_ip}:4433"
[[peers]]
network_id = "${network_id}"
node_id = "${node_a_id}"
prefixes = ["100.113.0.1/32", "fd71:6e65:7761::1/128"]
[[peers]]
network_id = "${network_id}"
node_id = "${node_b_id}"
prefixes = ["100.113.0.2/32", "fd71:6e65:7761::2/128"]
EOF

cat >"${work_dir}/rust-relay.toml" <<EOF
mode = "relay"
state_dir = "${work_dir}/rust-relay-state"
socket_path = "${work_dir}/rust-relay.sock"
[tls]
certificate = "${work_dir}/pki/relay.crt"
private_key = "${work_dir}/pki/relay.key"
ca = "${work_dir}/pki/ca.crt"
[relay]
listen = "${relay_ip}:4433"
queue_depth = 16
max_sessions = 8
max_routes = 4096
handshake_timeout = "5s"
idle_timeout = "15s"
metrics_interval = "100ms"
[tcp_fallback]
listen = "${relay_ip}:4443"
handshake_timeout = "5s"
write_timeout = "5s"
idle_timeout = "15s"
keepalive_period = "5s"
queue_depth = 16
[[peers]]
network_id = "${network_id}"
node_id = "${node_a_id}"
prefixes = ["100.113.0.1/32", "fd71:6e65:7761::1/128"]
[[peers]]
network_id = "${network_id}"
node_id = "${node_b_id}"
prefixes = ["100.113.0.2/32", "fd71:6e65:7761::2/128"]
EOF

rust_node_config() {
  local path="$1" node_id="$2" certificate="$3" key="$4" address="$5" address6="$6"
  local peer_id="$7" peer_address="$8" peer_address6="$9"
  cat >"${path}" <<EOF
mode = "node"
socket_path = "${path}.sock"
exit_intent_path = "${path}.exit-intent.json"
[identity]
network_id = "${network_id}"
node_id = "${node_id}"
[tls]
certificate = "${certificate}"
private_key = "${key}"
ca = "${work_dir}/pki/ca.crt"
[tun]
name = "lane0"
mtu = 1280
addresses = ["${address}/32", "${address6}/128"]
configure = true
[relay]
address = "${relay_ip}:4433"
server_name = "${relay_ip}"
service_id = "${relay_id}"
queue_depth = 16
max_routes = 8
handshake_timeout = "5s"
idle_timeout = "15s"
keepalive = "5s"
reconnect_min = "50ms"
reconnect_max = "500ms"
[tcp_fallback]
address = "${relay_ip}:4443"
handshake_timeout = "5s"
write_timeout = "5s"
idle_timeout = "15s"
keepalive_period = "5s"
queue_depth = 16
[[routes]]
prefix = "${peer_address}/32"
via_node = "${peer_id}"
kind = "overlay"
[[routes]]
prefix = "${peer_address6}/128"
via_node = "${peer_id}"
kind = "overlay"
EOF
}
rust_node_config "${work_dir}/rust-a.toml" "${node_a_id}" "${work_dir}/pki/a.crt" "${work_dir}/pki/a.key" \
  "${node_a_v4}" "${node_a_v6}" "${node_b_id}" "${node_b_v4}" "${node_b_v6}"
rust_node_config "${work_dir}/rust-b.toml" "${node_b_id}" "${work_dir}/pki/b.crt" "${work_dir}/pki/b.key" \
  "${node_b_v4}" "${node_b_v6}" "${node_a_id}" "${node_a_v4}" "${node_a_v6}"

cat >"${work_dir}/go-b.toml" <<EOF
mode = "node"
state_dir = "${work_dir}/go-b-state"
socket_path = "${work_dir}/go-b.sock"
[tls]
certificate = "${work_dir}/pki/b.crt"
private_key = "${work_dir}/pki/b.key"
ca = "${work_dir}/pki/ca.crt"
[node]
name = "interop-go-b"
relay_address = "${relay_ip}:4433"
relay_network_id = "${network_id}"
relay_service_id = "${relay_id}"
overlay_addresses = ["100.113.0.2/32", "fd71:6e65:7761::2/128"]
reconnect_min = "50ms"
reconnect_max = "500ms"
[tcp_fallback]
address = "${relay_ip}:4443"
handshake_timeout = "5s"
write_timeout = "5s"
idle_timeout = "15s"
keepalive_period = "5s"
quic_probe_interval = "5m"
queue_depth = 16
[[peers]]
network_id = "${network_id}"
node_id = "${node_a_id}"
prefixes = ["100.113.0.1/32", "fd71:6e65:7761::1/128"]
EOF

cat >"${work_dir}/go-a.toml" <<EOF
mode = "node"
state_dir = "${work_dir}/go-a-state"
socket_path = "${work_dir}/go-a.sock"
[tls]
certificate = "${work_dir}/pki/a.crt"
private_key = "${work_dir}/pki/a.key"
ca = "${work_dir}/pki/ca.crt"
[node]
name = "interop-go-a"
relay_address = "${relay_ip}:4433"
relay_network_id = "${network_id}"
relay_service_id = "${relay_id}"
overlay_addresses = ["100.113.0.1/32", "fd71:6e65:7761::1/128"]
reconnect_min = "50ms"
reconnect_max = "500ms"
[tcp_fallback]
address = "${relay_ip}:4443"
handshake_timeout = "5s"
write_timeout = "5s"
idle_timeout = "15s"
keepalive_period = "5s"
quic_probe_interval = "5m"
queue_depth = 16
[[peers]]
network_id = "${network_id}"
node_id = "${node_b_id}"
prefixes = ["100.113.0.2/32", "fd71:6e65:7761::2/128"]
EOF

cp "${work_dir}/rust-a.toml" "${work_dir}/rust-a-direct.toml"
cat >>"${work_dir}/rust-a-direct.toml" <<EOF
[direct]
listen = "10.253.0.2:45001"
probe_interval = "50ms"
probe_timeout = "3s"
probe_attempts = 3
candidate_refresh_interval = "6s"
[[direct_peers]]
node_id = "${node_b_id}"
address = "10.253.0.3:45002"
EOF

cp "${work_dir}/go-b.toml" "${work_dir}/go-b-direct.toml"
cat >>"${work_dir}/go-b-direct.toml" <<EOF
[direct]
enabled = true
listen = "10.253.0.3:45002"
candidate_ttl = "30s"
probe_interval = "50ms"
probe_timeout = "3s"
rendezvous_interval = "6s"
max_candidates = 4
EOF

cp "${work_dir}/rust-a.toml" "${work_dir}/rust-a-subnet.toml"
cat >>"${work_dir}/rust-a-subnet.toml" <<EOF
[forwarding]
subnet_router = true
owned_prefixes = ["192.168.77.0/24", "192.168.78.0/24"]
[[forwarding.subnet_routes]]
prefix = "192.168.77.0/24"
mode = "nat"
output_interface = "lan0"
[[forwarding.subnet_routes]]
prefix = "192.168.78.0/24"
mode = "routed"
output_interface = "lan0"
EOF

sed 's#prefixes = \["100.113.0.1/32", "fd71:6e65:7761::1/128"\]#prefixes = ["100.113.0.1/32", "fd71:6e65:7761::1/128", "192.168.77.0/24", "192.168.78.0/24"]#' \
  "${work_dir}/go-b.toml" >"${work_dir}/go-b-subnet.toml"
sed 's#prefixes = \["100.113.0.1/32", "fd71:6e65:7761::1/128"\]#prefixes = ["100.113.0.1/32", "fd71:6e65:7761::1/128", "192.168.77.0/24", "192.168.78.0/24"]#' \
  "${work_dir}/rust-relay.toml" >"${work_dir}/rust-relay-subnet.toml"

cp "${work_dir}/rust-a.toml" "${work_dir}/rust-a-exit.toml"
cat >>"${work_dir}/rust-a-exit.toml" <<EOF
[forwarding]
exit_gateway = true
exit_gateway_sources = ["${node_b_v4}/32", "${node_b_v6}/128"]
exit_output_interface = "wan0"
EOF

sed 's#prefixes = \["100.113.0.1/32", "fd71:6e65:7761::1/128"\]#prefixes = ["100.113.0.1/32", "fd71:6e65:7761::1/128", "203.0.113.2/32", "2001:db8:253::2/128"]#' \
  "${work_dir}/go-b.toml" >"${work_dir}/go-b-exit-targets.toml"
sed 's#prefixes = \["100.113.0.1/32", "fd71:6e65:7761::1/128"\]#prefixes = ["100.113.0.1/32", "fd71:6e65:7761::1/128", "203.0.113.2/32", "2001:db8:253::2/128"]#' \
  "${work_dir}/rust-relay.toml" >"${work_dir}/rust-relay-exit.toml"

start_process() {
  local namespace="$1" log="$2"
  shift 2
  ip netns exec "${namespace}" "$@" >"${log}" 2>&1 &
  last_pid=$!
  processes+=("${last_pid}")
}

stop_process() {
  local pid="$1"
  kill -INT "${pid}" >/dev/null 2>&1 || true
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
      echo "ERROR: process stopped before ${pattern}" >&2
      sed -n '1,240p' "${log}" >&2 || true
      return 1
    fi
    sleep 0.05
  done
  echo "ERROR: timed out waiting for ${pattern}" >&2
  sed -n '1,240p' "${log}" >&2 || true
  return 1
}

exchange_one() {
  local label="$1" server_namespace="$2" listen_address="$3"
  local client_namespace="$4" target_address="$5" expected_remote="$6"
  start_process "${server_namespace}" "${work_dir}/${label}-server.log" \
    "${work_dir}/netprobe" udp-server -listen "${listen_address}"
  local server_pid="${last_pid}"
  wait_log "${server_pid}" "${work_dir}/${label}-server.log" "ready=udp-server"
  if ! ip netns exec "${client_namespace}" "${work_dir}/netprobe" udp-client \
    -target "${target_address}" -message "${label}"; then
    echo "ERROR: ${label} packet exchange failed; component logs follow" >&2
    for log in "${work_dir}"/*.log; do
      echo "==> ${log}" >&2
      sed -n '1,240p' "${log}" >&2 || true
    done
    return 1
  fi
  wait "${server_pid}"
  grep -Fq "remote=${expected_remote}" "${work_dir}/${label}-server.log"
}

exchange() {
  local label="$1"
  exchange_one "${label}" "${node_b_ns}" "${node_b_v4}:9401" \
    "${node_a_ns}" "${node_b_v4}:9401" "${node_a_v4}:"
}

exchange_bidirectional() {
  local label="$1"
  exchange_one "${label}-v4-a-to-b" "${node_b_ns}" "${node_b_v4}:9401" \
    "${node_a_ns}" "${node_b_v4}:9401" "${node_a_v4}:"
  exchange_one "${label}-v4-b-to-a" "${node_a_ns}" "${node_a_v4}:9401" \
    "${node_b_ns}" "${node_a_v4}:9401" "${node_b_v4}:"
  exchange_one "${label}-v6-a-to-b" "${node_b_ns}" "[${node_b_v6}]:9401" \
    "${node_a_ns}" "[${node_b_v6}]:9401" "[${node_a_v6}]:"
  exchange_one "${label}-v6-b-to-a" "${node_a_ns}" "[${node_a_v6}]:9401" \
    "${node_b_ns}" "[${node_a_v6}]:9401" "[${node_b_v6}]:"
}

exchange_tcp_one() {
  local label="$1" server_namespace="$2" listen_address="$3"
  local client_namespace="$4" target_address="$5" expected_remote="$6"
  start_process "${server_namespace}" "${work_dir}/${label}-server.log" \
    "${work_dir}/netprobe" tcp-server -listen "${listen_address}"
  local server_pid="${last_pid}"
  wait_log "${server_pid}" "${work_dir}/${label}-server.log" "ready=tcp-server"
  if ! ip netns exec "${client_namespace}" "${work_dir}/netprobe" tcp-client \
    -target "${target_address}" -message "${label}"; then
    echo "ERROR: ${label} TCP exchange failed" >&2
    sed -n '1,240p' "${work_dir}/${label}-server.log" >&2 || true
    return 1
  fi
  wait "${server_pid}"
  grep -Fq "remote=${expected_remote}" "${work_dir}/${label}-server.log"
}

exchange_tcp_bidirectional() {
  local label="$1"
  exchange_tcp_one "${label}-v4-a-to-b" "${node_b_ns}" "${node_b_v4}:9402" \
    "${node_a_ns}" "${node_b_v4}:9402" "${node_a_v4}:"
  exchange_tcp_one "${label}-v4-b-to-a" "${node_a_ns}" "${node_a_v4}:9402" \
    "${node_b_ns}" "${node_a_v4}:9402" "${node_b_v4}:"
  exchange_tcp_one "${label}-v6-a-to-b" "${node_b_ns}" "[${node_b_v6}]:9402" \
    "${node_a_ns}" "[${node_b_v6}]:9402" "[${node_a_v6}]:"
  exchange_tcp_one "${label}-v6-b-to-a" "${node_a_ns}" "[${node_a_v6}]:9402" \
    "${node_b_ns}" "[${node_a_v6}]:9402" "[${node_b_v6}]:"
}

wait_metric_value() {
  local namespace="$1" name="$2" expected="$3"
  for _ in $(seq 1 100); do
    local value
    value="$(ip netns exec "${namespace}" "${work_dir}/netprobe" metric -name "${name}" 2>/dev/null || true)"
    if [[ "${value}" == "${expected}" ]]; then
      return 0
    fi
    sleep 0.05
  done
  echo "ERROR: metric ${name} did not become ${expected}" >&2
  return 1
}

if [[ "${LANEWAY_INTEROP_DIRECT_ONLY:-0}" != "1" ]]; then
echo "==> Rust node -> Go relay -> Go node"
start_process "${relay_ns}" "${work_dir}/go-relay.log" "${work_dir}/go-relay" -config "${work_dir}/go-relay.toml"
go_relay_pid="${last_pid}"
wait_log "${go_relay_pid}" "${work_dir}/go-relay.log" "listening"
start_process "${node_a_ns}" "${work_dir}/rust-a-go-relay.log" "${work_dir}/rust-node" --config "${work_dir}/rust-a.toml"
rust_a_pid="${last_pid}"
start_process "${node_b_ns}" "${work_dir}/go-b.log" "${work_dir}/go-node" node run -config "${work_dir}/go-b.toml"
go_b_pid="${last_pid}"
wait_log "${rust_a_pid}" "${work_dir}/rust-a-go-relay.log" "relay connected"
wait_log "${go_b_pid}" "${work_dir}/go-b.log" "interface=lane0"
echo "==> bidirectional IPv4 and IPv6 over mixed Rust/Go nodes"
exchange_bidirectional rust-go-go
echo "==> ICMP and SSH-class TCP use ordinary overlay routes"
ip netns exec "${node_a_ns}" ping -c 2 -W 2 "${node_b_v4}"
ip netns exec "${node_a_ns}" ping -c 2 -W 2 "${node_b_v6}"
ip netns exec "${node_b_ns}" ping -c 2 -W 2 "${node_a_v4}"
ip netns exec "${node_b_ns}" ping -c 2 -W 2 "${node_a_v6}"
exchange_tcp_bidirectional rust-go-overlay-tcp
stop_process "${rust_a_pid}"
stop_process "${go_b_pid}"
stop_process "${go_relay_pid}"

echo "==> Rust node -> Rust relay -> Rust node"
start_process "${relay_ns}" "${work_dir}/rust-relay.log" "${work_dir}/rust-relay" --config "${work_dir}/rust-relay.toml"
rust_relay_pid="${last_pid}"
wait_log "${rust_relay_pid}" "${work_dir}/rust-relay.log" "listening"
start_process "${node_a_ns}" "${work_dir}/rust-a-rust-relay.log" "${work_dir}/rust-node" --config "${work_dir}/rust-a.toml"
rust_a_pid="${last_pid}"
start_process "${node_b_ns}" "${work_dir}/rust-b.log" "${work_dir}/rust-node" --config "${work_dir}/rust-b.toml"
rust_b_pid="${last_pid}"
wait_log "${rust_a_pid}" "${work_dir}/rust-a-rust-relay.log" "relay connected"
wait_log "${rust_b_pid}" "${work_dir}/rust-b.log" "relay connected"
wait_log "${rust_relay_pid}" "${work_dir}/rust-relay.log" "registrations: 2"
exchange rust-rust-rust
stop_process "${rust_a_pid}"
stop_process "${rust_b_pid}"
stop_process "${rust_relay_pid}"

echo "==> Rust node -> Rust relay -> Go node"
start_process "${relay_ns}" "${work_dir}/rust-relay-mixed.log" "${work_dir}/rust-relay" --config "${work_dir}/rust-relay.toml"
rust_relay_pid="${last_pid}"
wait_log "${rust_relay_pid}" "${work_dir}/rust-relay-mixed.log" "listening"
start_process "${node_a_ns}" "${work_dir}/rust-a-rust-relay-go.log" "${work_dir}/rust-node" --config "${work_dir}/rust-a.toml"
rust_a_pid="${last_pid}"
start_process "${node_b_ns}" "${work_dir}/go-b-rust-relay.log" "${work_dir}/go-node" node run -config "${work_dir}/go-b.toml"
go_b_pid="${last_pid}"
wait_log "${rust_a_pid}" "${work_dir}/rust-a-rust-relay-go.log" "relay connected"
wait_log "${go_b_pid}" "${work_dir}/go-b-rust-relay.log" "interface=lane0"
wait_log "${rust_relay_pid}" "${work_dir}/rust-relay-mixed.log" "registrations: 2"
exchange rust-rust-go
stop_process "${rust_a_pid}"
stop_process "${go_b_pid}"
stop_process "${rust_relay_pid}"

echo "==> Rust node -> Rust relay TLS/TCP fallback -> Go QUIC node"
ip netns exec "${node_a_ns}" nft add table inet laneway_quic_block
ip netns exec "${node_a_ns}" nft add chain inet laneway_quic_block output \
  '{ type filter hook output priority -10; policy accept; }'
ip netns exec "${node_a_ns}" nft add rule inet laneway_quic_block output \
  ip daddr "${relay_ip}" udp dport 4433 drop
start_process "${relay_ns}" "${work_dir}/rust-relay-tcp.log" "${work_dir}/rust-relay" --config "${work_dir}/rust-relay.toml"
rust_relay_pid="${last_pid}"
wait_log "${rust_relay_pid}" "${work_dir}/rust-relay-tcp.log" "listening"
start_process "${node_a_ns}" "${work_dir}/rust-a-rust-tcp.log" "${work_dir}/rust-node" --config "${work_dir}/rust-a.toml"
rust_a_pid="${last_pid}"
start_process "${node_b_ns}" "${work_dir}/go-b-rust-tcp.log" "${work_dir}/go-node" node run -config "${work_dir}/go-b.toml"
go_b_pid="${last_pid}"
wait_log "${rust_a_pid}" "${work_dir}/rust-a-rust-tcp.log" "Rust agent relay TCP fallback connected"
wait_log "${go_b_pid}" "${work_dir}/go-b-rust-tcp.log" "interface=lane0"
wait_log "${rust_relay_pid}" "${work_dir}/rust-relay-tcp.log" "registrations: 2"
exchange rust-rust-tcp-go
stop_process "${rust_a_pid}"
stop_process "${go_b_pid}"
stop_process "${rust_relay_pid}"
ip netns exec "${node_a_ns}" nft delete table inet laneway_quic_block

echo "==> Go node -> Rust subnet router -> NAT and routed LAN applications"
start_process "${relay_ns}" "${work_dir}/rust-relay-subnet.log" "${work_dir}/rust-relay" --config "${work_dir}/rust-relay-subnet.toml"
rust_relay_pid="${last_pid}"
wait_log "${rust_relay_pid}" "${work_dir}/rust-relay-subnet.log" "listening"
start_process "${node_a_ns}" "${work_dir}/rust-a-subnet.log" "${work_dir}/rust-node" --config "${work_dir}/rust-a-subnet.toml"
rust_a_pid="${last_pid}"
start_process "${node_b_ns}" "${work_dir}/go-b-subnet.log" "${work_dir}/go-node" node run -config "${work_dir}/go-b-subnet.toml"
go_b_pid="${last_pid}"
wait_log "${rust_a_pid}" "${work_dir}/rust-a-subnet.log" "relay connected"
wait_log "${go_b_pid}" "${work_dir}/go-b-subnet.log" "interface=lane0"
wait_log "${rust_relay_pid}" "${work_dir}/rust-relay-subnet.log" "registrations: 2"
ip netns exec "${node_b_ns}" ping -c 2 -W 2 192.168.77.2
ip netns exec "${node_b_ns}" ping -c 2 -W 2 192.168.78.2
exchange_one rust-subnet-nat-udp "${lan_ns}" 192.168.77.2:9501 \
  "${node_b_ns}" 192.168.77.2:9501 "192.168.77.1:"
exchange_tcp_one rust-subnet-nat-tcp "${lan_ns}" 192.168.77.2:9502 \
  "${node_b_ns}" 192.168.77.2:9502 "192.168.77.1:"
exchange_one rust-subnet-routed-udp "${lan_ns}" 192.168.78.2:9501 \
  "${node_b_ns}" 192.168.78.2:9501 "${node_b_v4}:"
exchange_tcp_one rust-subnet-routed-tcp "${lan_ns}" 192.168.78.2:9502 \
  "${node_b_ns}" 192.168.78.2:9502 "${node_b_v4}:"
stop_process "${rust_a_pid}"
stop_process "${go_b_pid}"
stop_process "${rust_relay_pid}"

echo "==> Go node -> Rust exit gateway -> NATed IPv4 and IPv6 applications"
start_process "${relay_ns}" "${work_dir}/rust-relay-exit.log" "${work_dir}/rust-relay" --config "${work_dir}/rust-relay-exit.toml"
rust_relay_pid="${last_pid}"
wait_log "${rust_relay_pid}" "${work_dir}/rust-relay-exit.log" "listening"
start_process "${node_a_ns}" "${work_dir}/rust-a-exit.log" "${work_dir}/rust-node" --config "${work_dir}/rust-a-exit.toml"
rust_a_pid="${last_pid}"
start_process "${node_b_ns}" "${work_dir}/go-b-exit.log" "${work_dir}/go-node" node run -config "${work_dir}/go-b-exit-targets.toml"
go_b_pid="${last_pid}"
wait_log "${rust_a_pid}" "${work_dir}/rust-a-exit.log" "relay connected"
wait_log "${go_b_pid}" "${work_dir}/go-b-exit.log" "interface=lane0"
wait_log "${rust_relay_pid}" "${work_dir}/rust-relay-exit.log" "registrations: 2"
ip netns exec "${node_b_ns}" ping -c 2 -W 2 203.0.113.2
ip netns exec "${node_b_ns}" ping -c 2 -W 2 2001:db8:253::2
exchange_one rust-exit-v4-udp "${external_ns}" 203.0.113.2:9601 \
  "${node_b_ns}" 203.0.113.2:9601 "203.0.113.1:"
exchange_tcp_one rust-exit-v4-tcp "${external_ns}" 203.0.113.2:9602 \
  "${node_b_ns}" 203.0.113.2:9602 "203.0.113.1:"
exchange_one rust-exit-v6-udp "${external_ns}" '[2001:db8:253::2]:9601' \
  "${node_b_ns}" '[2001:db8:253::2]:9601' '[2001:db8:253::1]:'
exchange_tcp_one rust-exit-v6-tcp "${external_ns}" '[2001:db8:253::2]:9602' \
  "${node_b_ns}" '[2001:db8:253::2]:9602' '[2001:db8:253::1]:'
stop_process "${rust_a_pid}"
stop_process "${go_b_pid}"
stop_process "${rust_relay_pid}"

fi

echo "==> Rust node -> authenticated direct QUIC -> Go node"
start_process "${relay_ns}" "${work_dir}/go-relay-direct.log" "${work_dir}/go-relay" \
  -config "${work_dir}/go-relay.toml" -diagnostics 127.0.0.1:6060
go_relay_pid="${last_pid}"
wait_log "${go_relay_pid}" "${work_dir}/go-relay-direct.log" "listening"
wait_metric_value "${relay_ns}" laneway_forwarded_packets_total 0
start_process "${node_b_ns}" "${work_dir}/go-b-direct.log" "${work_dir}/go-node" node run -config "${work_dir}/go-b-direct.toml"
go_b_pid="${last_pid}"
start_process "${node_a_ns}" "${work_dir}/rust-a-direct.log" "${work_dir}/rust-node" --config "${work_dir}/rust-a-direct.toml"
rust_a_pid="${last_pid}"
wait_log "${go_b_pid}" "${work_dir}/go-b-direct.log" "interface=lane0"
wait_log "${rust_a_pid}" "${work_dir}/rust-a-direct.log" "direct path attached"
exchange_bidirectional rust-go-direct
wait_metric_value "${relay_ns}" laneway_forwarded_packets_total 0
stop_process "${rust_a_pid}"
stop_process "${go_b_pid}"
stop_process "${go_relay_pid}"
grep -Eq 'relay_packets: 0.*direct_packets: [1-9][0-9]*' "${work_dir}/rust-a-direct.log"
grep -q 'stopped sessions=0 forwarded=0 dropped=0' "${work_dir}/go-relay-direct.log"

echo "PASS: Rust node executable interoperability"
