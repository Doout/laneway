#!/bin/sh
set -eu

base_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
env_file=$base_dir/.env
published=
staging=

cleanup() {
  if [ -n "$published" ]; then
    for path in $published; do
      [ ! -e "$path" ] || find "$path" -maxdepth 0 -delete
    done
  fi
  [ -z "$staging" ] || [ ! -e "$staging" ] || find "$staging" -depth -delete
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

die() { echo "lane prepare: $*" >&2; exit 1; }

read_setting() {
  key=$1
  value=$(sed -n "s/^${key}=//p" "$env_file")
  if [ -z "$value" ] || [ "$(printf '%s\n' "$value" | wc -l)" -ne 1 ]; then
    die "missing or duplicate $key in .env"
  fi
  case "$value" in *[!A-Za-z0-9._:/-]*) die "$key contains an unsafe character" ;; esac
  printf '%s' "$value"
}

require_regular() {
  if [ ! -f "$1" ] || [ -L "$1" ]; then
    die "required issuer file is missing or unsafe: $1"
  fi
}

[ "$#" -eq 1 ] || die "usage: prepare.sh ISSUER_DIRECTORY"
[ "$(id -u)" -eq 0 ] || die "run as root so fixed container ownership can be installed safely"
command -v laneway >/dev/null 2>&1 || die "the signed laneway binary must be installed"
if [ ! -f "$env_file" ] || [ -L "$env_file" ]; then
  die ".env must be a regular, non-symlink file"
fi

issuer_dir=$(CDPATH='' cd -- "$1" && pwd)
case "$issuer_dir" in "$base_dir"|"$base_dir"/*) die "issuer material must be staged outside the deployment directory" ;; esac
if [ -e "$issuer_dir/ca.key" ] || [ -L "$issuer_dir/ca.key" ]; then
  die "offline root private key ca.key must never be copied to the control host"
fi
for name in ca.crt intermediate-chain.crt intermediate.key; do require_regular "$issuer_dir/$name"; done
for path in "$issuer_dir"/*.key; do
  [ -e "$path" ] || continue
  [ "$(basename "$path")" = intermediate.key ] || die "issuer directory contains an unexpected private key: $path"
done
laneway pki verify-authority --root "$issuer_dir/ca.crt" \
  --issuer "$issuer_dir/intermediate-chain.crt" --key "$issuer_dir/intermediate.key"

targets="
$base_dir/generated/config/controller.toml
$base_dir/generated/config/relay.toml
$base_dir/generated/pki/ca.crt
$base_dir/generated/pki/intermediate-chain.crt
$base_dir/generated/pki/intermediate.key
$base_dir/generated/pki/controller.crt
$base_dir/generated/pki/controller.key
$base_dir/generated/pki/relay.crt
$base_dir/generated/pki/relay.key
$base_dir/generated/secrets/admin.token"
present=0
missing=0
for path in $targets; do
  if [ -e "$path" ] || [ -L "$path" ]; then
    if [ ! -f "$path" ] || [ -L "$path" ]; then
      die "refusing unsafe existing state: $path"
    fi
    present=$((present + 1))
  else
    missing=$((missing + 1))
  fi
done
if [ "$present" -gt 0 ] && [ "$missing" -gt 0 ]; then
  die "generated control-plane state is partial; refusing to overwrite or guess ownership"
fi
if [ "$missing" -eq 0 ]; then
  cmp -s "$issuer_dir/ca.crt" "$base_dir/generated/pki/ca.crt" || die "existing root certificate differs from issuer bundle"
  cmp -s "$issuer_dir/intermediate-chain.crt" "$base_dir/generated/pki/intermediate-chain.crt" || die "existing intermediate chain differs from issuer bundle"
  cmp -s "$issuer_dir/intermediate.key" "$base_dir/generated/pki/intermediate.key" || die "existing intermediate key differs from issuer bundle"
  echo "Laneway control-plane material is already prepared"
  published=
  exit 0
fi

network_id=$(read_setting LANEWAY_NETWORK_ID)
controller_id=$(read_setting LANEWAY_CONTROLLER_SERVICE_ID)
relay_id=$(read_setting LANEWAY_RELAY_SERVICE_ID)
server_name=$(read_setting LANEWAY_CONTROLLER_SERVER_NAME)
relay_endpoint=$(read_setting LANEWAY_RELAY_PUBLIC_ENDPOINT)
relay_name=${relay_endpoint%:*}
case "$relay_name" in ''|*:*|*[!A-Za-z0-9.-]*) die "relay endpoint must use a DNS hostname and port" ;; esac

for directory in "$base_dir/generated" "$base_dir/generated/config" "$base_dir/generated/pki" "$base_dir/generated/secrets"; do
  if [ -e "$directory" ] || [ -L "$directory" ]; then
    if [ ! -d "$directory" ] || [ -L "$directory" ]; then
      die "generated path must be a real directory: $directory"
    fi
  fi
done
install -d -m 0700 -o 0 -g 0 "$base_dir/generated" "$base_dir/generated/config" \
  "$base_dir/generated/pki" "$base_dir/generated/secrets"
staging=$(mktemp -d "$base_dir/generated/.prepare.XXXXXX")
install -m 0444 "$issuer_dir/ca.crt" "$staging/ca.crt"
install -m 0444 "$issuer_dir/intermediate-chain.crt" "$staging/intermediate-chain.crt"
install -m 0400 "$issuer_dir/intermediate.key" "$staging/intermediate.key"

laneway pki controller --ca-cert "$staging/intermediate-chain.crt" --ca-key "$staging/intermediate.key" \
  --network-id "$network_id" --service-id "$controller_id" --dns "$server_name" \
  --out-cert "$staging/controller.crt" --out-key "$staging/controller.key"
laneway pki relay --ca-cert "$staging/intermediate-chain.crt" --ca-key "$staging/intermediate.key" \
  --network-id "$network_id" --service-id "$relay_id" --dns "$relay_name" \
  --out-cert "$staging/relay.crt" --out-key "$staging/relay.key"

token=$(laneway id)$(laneway id)
printf '%s\n' "$token" > "$staging/admin.token"

cat > "$staging/controller.toml" <<'EOF'
mode = "controller"
state_dir = "/var/lib/laneway-controller"
socket_path = "/tmp/controller.sock"

[tls]
certificate = "/run/laneway-secrets/controller.crt"
private_key = "/run/laneway-secrets/controller.key"
ca = "/run/laneway-secrets/ca.crt"

[controller]
listen = ":8443"
quic_listen = ":8443"
database = "/var/lib/laneway-controller/controller.db"
ca_private_key = "/run/laneway-secrets/intermediate.key"
issuer_certificate = "/run/laneway-secrets/intermediate-chain.crt"
admin_token_file = "/run/laneway-secrets/admin.token"
leaf_validity = "720h"
EOF
cat > "$staging/relay.toml" <<EOF
mode = "relay"
state_dir = "/var/lib/laneway-relay"
socket_path = "/tmp/relay.sock"

[tls]
certificate = "/run/laneway-secrets/relay.crt"
private_key = "/run/laneway-secrets/relay.key"
ca = "/run/laneway-secrets/ca.crt"

[relay]
listen = ":4433"
queue_depth = 256
packet_rate_bits_per_second = 2000000
packet_burst_bytes = 65536
handshake_timeout = "10s"
idle_timeout = "45s"

[controller]
endpoint = "https://controller:8443"
quic_endpoint = "controller:8443"
network_id = "$network_id"
service_id = "$controller_id"
server_name = "$server_name"
poll_interval = "30s"

[tcp_fallback]
listen = ":8443"
EOF

for name in intermediate.key controller.key relay.key admin.token; do chmod 0400 "$staging/$name"; chown 65532:65532 "$staging/$name"; done
for name in ca.crt intermediate-chain.crt controller.crt relay.crt controller.toml relay.toml; do chmod 0444 "$staging/$name"; chown 0:0 "$staging/$name"; done

publish() {
  source=$1; destination=$2
  ln "$source" "$destination"
  published="$published $destination"
}
publish "$staging/controller.toml" "$base_dir/generated/config/controller.toml"
publish "$staging/relay.toml" "$base_dir/generated/config/relay.toml"
for name in ca.crt intermediate-chain.crt intermediate.key controller.crt controller.key relay.crt relay.key; do
  publish "$staging/$name" "$base_dir/generated/pki/$name"
done
publish "$staging/admin.token" "$base_dir/generated/secrets/admin.token"

published=
find "$staging" -depth -delete
staging=
echo "Prepared controller and relay material without installing the offline root private key"
