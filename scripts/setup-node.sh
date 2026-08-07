#!/bin/sh
set -eu

usage() {
  cat >&2 <<'EOF'
usage: laneway-setup-node \
  --token-file PATH --name NAME --ca CA_FILE \
  --controller https://HOST:PORT --controller-quic HOST:PORT \
  --controller-network-id ID --controller-service-id ID \
  --controller-server-name NAME \
  --relay HOST:PORT --relay-tcp HOST:PORT \
  --relay-service-id ID --relay-server-name NAME [--start]
EOF
  exit 2
}

token_file=''
name=''
ca_file=''
controller=''
controller_quic=''
controller_network_id=''
controller_service_id=''
controller_server_name=''
relay=''
relay_tcp=''
relay_service_id=''
relay_server_name=''
start=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --token-file) token_file=${2-}; shift 2 ;;
    --name) name=${2-}; shift 2 ;;
    --ca) ca_file=${2-}; shift 2 ;;
    --controller) controller=${2-}; shift 2 ;;
    --controller-quic) controller_quic=${2-}; shift 2 ;;
    --controller-network-id) controller_network_id=${2-}; shift 2 ;;
    --controller-service-id) controller_service_id=${2-}; shift 2 ;;
    --controller-server-name) controller_server_name=${2-}; shift 2 ;;
    --relay) relay=${2-}; shift 2 ;;
		--relay-tcp) relay_tcp=${2-}; shift 2 ;;
    --relay-service-id) relay_service_id=${2-}; shift 2 ;;
    --relay-server-name) relay_server_name=${2-}; shift 2 ;;
    --start) start=true; shift ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "laneway-setup-node must run as root" >&2
  exit 1
fi
for value in "$token_file" "$name" "$ca_file" "$controller" "$controller_quic" \
  "$controller_network_id" "$controller_service_id" "$controller_server_name" \
  "$relay" "$relay_tcp" "$relay_service_id" "$relay_server_name"; do
  [ -n "$value" ] || usage
done
[ -f "$ca_file" ] || { echo "CA file does not exist: $ca_file" >&2; exit 1; }
[ -f "$token_file" ] || { echo "token file does not exist: $token_file" >&2; exit 1; }
token_mode=$(stat -c '%a' "$token_file")
case "$token_mode" in *[!0-7]*) echo "cannot validate token file permissions" >&2; exit 1;; esac
if [ $((token_mode % 100)) -ne 0 ]; then
  echo "token file must be mode 0600 or stricter" >&2
  exit 1
fi
case "$name" in *[!A-Za-z0-9._-]*) echo "node name contains unsupported characters" >&2; exit 1;; esac
case "$controller_network_id:$controller_service_id:$relay_service_id" in
  *[!0-9a-fA-F:]*) echo "IDs must be hexadecimal" >&2; exit 1;;
esac
for value in "$controller_network_id" "$controller_service_id" "$relay_service_id"; do
  [ "${#value}" -eq 32 ] || { echo "IDs must contain exactly 32 hexadecimal characters" >&2; exit 1; }
done
for value in "$controller" "$controller_quic" "$controller_server_name" "$relay" "$relay_tcp" "$relay_server_name"; do
  case "$value" in *[\"\\[:space:]]*) echo "endpoint or server name contains unsafe characters" >&2; exit 1;; esac
done
case "$controller" in https://*) ;; *) echo "controller must use https://" >&2; exit 1;; esac

getent group laneway >/dev/null 2>&1 || { echo "laneway group is missing; run the package installer first" >&2; exit 1; }
id laneway >/dev/null 2>&1 || { echo "laneway user is missing; run the package installer first" >&2; exit 1; }
install -d -m 0750 -o root -g laneway /etc/laneway
for target in ca.crt node.crt node.key laneway.toml; do
  if [ -e "/etc/laneway/$target" ]; then
    echo "refusing to replace existing /etc/laneway/$target" >&2
    exit 1
  fi
done

work_dir=$(mktemp -d)
trap 'find "$work_dir" -depth -delete' EXIT HUP INT TERM
install -m 0600 "$ca_file" "$work_dir/ca.crt"
laneway join --token-file "$token_file" \
  --controller "$controller" \
  --controller-network-id "$controller_network_id" \
  --controller-service-id "$controller_service_id" \
  --server-name "$controller_server_name" \
  --ca "$work_dir/ca.crt" --name "$name" \
  --out-cert "$work_dir/node.crt" --out-key "$work_dir/node.key"

config_file="$work_dir/laneway.toml"
cat > "$config_file" <<EOF
mode = "node"
state_dir = "/var/lib/laneway"
socket_path = "/run/laneway/lanewayd.sock"

[tls]
certificate = "/etc/laneway/node.crt"
private_key = "/etc/laneway/node.key"
ca = "/etc/laneway/ca.crt"
server_name = "$relay_server_name"

[node]
name = "$name"
relay_address = "$relay"
relay_network_id = "$controller_network_id"
relay_service_id = "$relay_service_id"
reconnect_min = "1s"
reconnect_max = "30s"

[controller]
endpoint = "$controller"
quic_endpoint = "$controller_quic"
server_name = "$controller_server_name"
network_id = "$controller_network_id"
service_id = "$controller_service_id"
poll_interval = "30s"

[tcp_fallback]
address = "$relay_tcp"
quic_probe_interval = "30s"
EOF
laneway config validate -config "$config_file"
install -m 0640 -o root -g laneway "$work_dir/ca.crt" /etc/laneway/ca.crt
install -m 0640 -o root -g laneway "$work_dir/node.crt" /etc/laneway/node.crt
install -m 0640 -o root -g laneway "$work_dir/node.key" /etc/laneway/node.key
install -m 0640 -o root -g laneway "$config_file" /etc/laneway/laneway.toml

echo "Node enrollment and configuration are complete."
if [ "$start" = true ]; then
  systemctl enable --now lanewayd
  sudo_command=
  if [ -n "${SUDO_USER:-}" ]; then sudo_command=sudo; fi
  echo "Daemon started. Check it with: $sudo_command laneway up"
else
  echo "Start it with: systemctl enable --now lanewayd"
  echo "Then check it with: sudo laneway up"
fi
