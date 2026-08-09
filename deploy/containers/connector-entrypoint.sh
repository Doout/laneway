#!/bin/sh
set -eu

die() { echo "laneway connector: $*" >&2; exit 1; }
required() {
  [ -n "$2" ] || die "required environment variable is missing: $1"
}

state_dir=/var/lib/laneway/connector
config_file=$state_dir/connector.toml
ca_file=$state_dir/ca.crt
cert_file=$state_dir/node.crt
key_file=$state_dir/node.key
wireguard_key_file=$state_dir/wireguard.key

# Packaged Compose deployments already provide identity files and an explicit
# config argument. Preserve that mode while the public Connector image uses the
# environment-driven first-run path below.
if [ "$#" -gt 0 ]; then
  exec /bin/setpriv --inh-caps=+net_admin --ambient-caps=+net_admin --no-new-privs \
    /sbin/tini -- /usr/local/bin/laneway node run "$@"
fi

identity_count=0
for path in "$config_file" "$ca_file" "$cert_file" "$key_file" "$wireguard_key_file"; do
  [ ! -f "$path" ] || identity_count=$((identity_count + 1))
done

if [ "$identity_count" -ne 5 ]; then
  [ "$identity_count" -eq 0 ] || die "persistent volume contains an incomplete Connector identity"
  required LANEWAY_ENROLLMENT_TOKEN "${LANEWAY_ENROLLMENT_TOKEN:-}"
  required LANEWAY_NODE_NAME "${LANEWAY_NODE_NAME:-}"
  required LANEWAY_CONTROLLER_SERVER_NAME "${LANEWAY_CONTROLLER_SERVER_NAME:-}"
  required LANEWAY_CONTROLLER_PORT "${LANEWAY_CONTROLLER_PORT:-}"
  required LANEWAY_NETWORK_ID "${LANEWAY_NETWORK_ID:-}"
  required LANEWAY_CONTROLLER_SERVICE_ID "${LANEWAY_CONTROLLER_SERVICE_ID:-}"
  required LANEWAY_RELAY_ENDPOINT "${LANEWAY_RELAY_ENDPOINT:-}"
  required LANEWAY_RELAY_SERVICE_ID "${LANEWAY_RELAY_SERVICE_ID:-}"
  required LANEWAY_CA_B64 "${LANEWAY_CA_B64:-}"
  case "$LANEWAY_NODE_NAME" in *[!A-Za-z0-9._-]*) die "invalid LANEWAY_NODE_NAME" ;; esac
  case "$LANEWAY_CONTROLLER_SERVER_NAME" in *[!A-Za-z0-9.-]*) die "invalid LANEWAY_CONTROLLER_SERVER_NAME" ;; esac
  case "$LANEWAY_CONTROLLER_PORT" in *[!0-9]*|'') die "invalid LANEWAY_CONTROLLER_PORT" ;; esac
  if [ "${#LANEWAY_CONTROLLER_PORT}" -gt 5 ] || \
    [ "$LANEWAY_CONTROLLER_PORT" -lt 1 ] || [ "$LANEWAY_CONTROLLER_PORT" -gt 65535 ]; then
    die "invalid LANEWAY_CONTROLLER_PORT"
  fi
  case "$LANEWAY_NETWORK_ID$LANEWAY_CONTROLLER_SERVICE_ID$LANEWAY_RELAY_SERVICE_ID" in
    *[!0-9a-f]*) die "invalid Laneway identity" ;;
  esac
  if [ "${#LANEWAY_NETWORK_ID}" -ne 32 ] || \
    [ "${#LANEWAY_CONTROLLER_SERVICE_ID}" -ne 32 ] || \
    [ "${#LANEWAY_RELAY_SERVICE_ID}" -ne 32 ]; then
    die "invalid Laneway identity length"
  fi
  case "$LANEWAY_RELAY_ENDPOINT" in *'"'*|*\\*|*'
'*) die "invalid LANEWAY_RELAY_ENDPOINT" ;; esac

  umask 077
  mkdir -p "$state_dir"
  token_file=$state_dir/enrollment.token
  cleanup_token() { rm -f -- "$token_file"; }
  trap cleanup_token EXIT HUP INT TERM
  printf '%s\n' "$LANEWAY_ENROLLMENT_TOKEN" > "$token_file"
  printf '%s' "$LANEWAY_CA_B64" | base64 -d > "$ca_file.tmp" || die "invalid LANEWAY_CA_B64"
  grep -F -- '-----BEGIN CERTIFICATE-----' "$ca_file.tmp" >/dev/null || die "decoded CA is not a certificate"
  mv "$ca_file.tmp" "$ca_file"

  /usr/local/bin/laneway join --token-file "$token_file" \
    --controller "https://$LANEWAY_CONTROLLER_SERVER_NAME:$LANEWAY_CONTROLLER_PORT" \
    --ca "$ca_file" --server-name "$LANEWAY_CONTROLLER_SERVER_NAME" \
    --controller-network-id "$LANEWAY_NETWORK_ID" \
    --controller-service-id "$LANEWAY_CONTROLLER_SERVICE_ID" \
    --name "$LANEWAY_NODE_NAME" --out-cert "$cert_file" --out-key "$key_file" \
    --out-wireguard-key "$wireguard_key_file"
  cleanup_token

  cat > "$config_file.tmp" <<EOF
mode = "node"
state_dir = "/var/lib/laneway"
socket_path = "/run/laneway/lanewayd.sock"

[tls]
certificate = "$cert_file"
private_key = "$key_file"
ca = "$ca_file"
server_name = "$LANEWAY_CONTROLLER_SERVER_NAME"

[node]
name = "$LANEWAY_NODE_NAME"
relay_address = "$LANEWAY_RELAY_ENDPOINT"
relay_network_id = "$LANEWAY_NETWORK_ID"
relay_service_id = "$LANEWAY_RELAY_SERVICE_ID"
reconnect_min = "1s"
reconnect_max = "30s"

[controller]
endpoint = "https://$LANEWAY_CONTROLLER_SERVER_NAME:$LANEWAY_CONTROLLER_PORT"
quic_endpoint = "$LANEWAY_CONTROLLER_SERVER_NAME:$LANEWAY_CONTROLLER_PORT"
server_name = "$LANEWAY_CONTROLLER_SERVER_NAME"
network_id = "$LANEWAY_NETWORK_ID"
service_id = "$LANEWAY_CONTROLLER_SERVICE_ID"
poll_interval = "30s"

[tcp_fallback]
address = "$LANEWAY_CONTROLLER_SERVER_NAME:443"
quic_probe_interval = "30s"

[direct]
enabled = true
listen = "0.0.0.0:4434"

[routing]
output_interface = "eth0"
nat = true

[exit]
enabled = false
serve = true
failure_mode = "closed"
EOF
  mv "$config_file.tmp" "$config_file"
  chmod 0444 "$ca_file" "$cert_file" "$config_file"
  chmod 0400 "$key_file" "$wireguard_key_file"
  trap - EXIT HUP INT TERM
fi

unset LANEWAY_ENROLLMENT_TOKEN LANEWAY_CA_B64
exec /bin/setpriv --inh-caps=+net_admin --ambient-caps=+net_admin --no-new-privs \
  /sbin/tini -- /usr/local/bin/laneway node run -config "$config_file"
