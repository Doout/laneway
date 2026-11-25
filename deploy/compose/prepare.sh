#!/bin/sh -p
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset ENV BASH_ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH
IFS=$(printf ' \t\n_'); IFS=${IFS%_}
set -eu

for trusted_command_dir in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin; do
  [ -d "$trusted_command_dir" ] && [ ! -L "$trusted_command_dir" ] && \
    [ "$(/usr/bin/stat -c '%u:%g' "$trusted_command_dir")" = 0:0 ] || {
      echo "Laneway preparation: trusted command directory is unsafe: $trusted_command_dir" >&2
      exit 1
    }
  trusted_command_mode=$((0$(/usr/bin/stat -c %a "$trusted_command_dir")))
  [ $((trusted_command_mode & 0022)) -eq 0 ] || {
    echo "Laneway preparation: trusted command directory is writable by group or other: $trusted_command_dir" >&2
    exit 1
  }
done

base_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
env_file=$base_dir/.env
published=
staging=
issuer_snapshot=

case "$base_dir" in *[!A-Za-z0-9_./-]*) echo "Laneway preparation: deployment directory contains an unsafe character" >&2; exit 1 ;; esac

cleanup() {
  if [ -n "$published" ]; then
    for path in $published; do
      [ ! -e "$path" ] || find "$path" -maxdepth 0 -delete
    done
  fi
  [ -z "$staging" ] || [ ! -e "$staging" ] || find "$staging" -depth -delete
  [ -z "$issuer_snapshot" ] || [ ! -e "$issuer_snapshot" ] || \
    find "$issuer_snapshot" -depth -delete
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

die() { echo "lane prepare: $*" >&2; exit 1; }

if env | grep -E '^COMPOSE_[A-Za-z0-9_]*=' >/dev/null; then
  die "ambient COMPOSE_* overrides are not allowed"
fi
if [ "${DOCKER_HOST+x}" = x ] || [ "${DOCKER_CONTEXT+x}" = x ] || \
  [ "${DOCKER_TLS+x}" = x ] || \
  [ "${DOCKER_TLS_VERIFY+x}" = x ] || [ "${DOCKER_CERT_PATH+x}" = x ]; then
  die "Docker target overrides are not allowed"
fi

validate_env_schema() {
  awk '
    /^[[:space:]]*($|#)/ { next }
    {
      key = $0
      if (key !~ /^[A-Z][A-Z0-9_]*=/) exit 1
      sub(/=.*/, "", key)
      if (key != "LANEWAY_VERSION" && key != "LANEWAY_INSTALL_PROFILE" &&
          key != "LANEWAY_CONTROLLER_IMAGE_DIGEST" && key != "LANEWAY_RELAY_IMAGE_DIGEST" &&
          key != "LANEWAY_ADMIN_IMAGE_DIGEST" && key != "LANEWAY_CONNECTOR_IMAGE_DIGEST" &&
          key != "LANEWAY_EXIT_NODE_IMAGE_DIGEST" && key != "LANEWAY_BIND_ADDRESS" &&
          key != "LANEWAY_CONTROLLER_PORT" && key != "LANEWAY_RELAY_QUIC_PORT" &&
          key != "LANEWAY_RELAY_TCP_PORT" && key != "LANEWAY_EXIT_DIRECT_PORT" &&
          key != "LANEWAY_CONTROLLER_SERVER_NAME" && key != "LANEWAY_NETWORK_ID" &&
          key != "LANEWAY_CONTROLLER_SERVICE_ID" && key != "LANEWAY_RELAY_SERVICE_ID" &&
          key != "LANEWAY_NETWORK_NAME" && key != "LANEWAY_IPV4_POOL" &&
          key != "LANEWAY_RELAY_PUBLIC_ENDPOINT" && key != "LANEWAY_BACKUP_RECIPIENT") exit 1
    }
  ' "$env_file" || die ".env must contain only canonical, managed KEY=value assignments, comments, or blank lines"
}

read_setting() {
  setting_key=$1
  canonical_count=$(grep -c "^${setting_key}=" "$env_file" || true)
  mention_count=$(grep -Ec "^[[:space:]]*(export[[:space:]]+)?${setting_key}[[:space:]]*=" "$env_file" || true)
  [ "$mention_count" -eq "$canonical_count" ] || die "malformed $setting_key in .env"
  [ "$canonical_count" -eq 1 ] || die "$setting_key must appear exactly once in .env"
  setting_value=$(sed -n "s/^${setting_key}=//p" "$env_file")
  [ -n "$setting_value" ] || die "$setting_key must not be empty in .env"
  case "$setting_value" in *[!A-Za-z0-9._:/-]*) die "$setting_key contains an unsafe character" ;; esac
  printf '%s' "$setting_value"
}

optional_setting() {
  setting_key=$1
  canonical_count=$(grep -c "^${setting_key}=" "$env_file" || true)
  mention_count=$(grep -Ec "^[[:space:]]*(export[[:space:]]+)?${setting_key}[[:space:]]*=" "$env_file" || true)
  [ "$mention_count" -eq "$canonical_count" ] || die "malformed $setting_key in .env"
  case "$canonical_count" in
    0) printf '%s' ''; return ;;
    1) ;;
    *) die "$setting_key must appear at most once in .env" ;;
  esac
  setting_value=$(sed -n "s/^${setting_key}=//p" "$env_file")
  [ -n "$setting_value" ] || die "$setting_key must not be empty in .env"
  case "$setting_value" in *[!A-Za-z0-9._:/-]*) die "$setting_key contains an unsafe character" ;; esac
  printf '%s' "$setting_value"
}

port_setting() {
  port_key=$1
  port_value=$(read_setting "$port_key")
  case "$port_value" in *[!0-9]*) die "$port_key must be a port from 1 through 65535" ;; esac
  [ "$port_value" -ge 1 ] && [ "$port_value" -le 65535 ] || die "$port_key must be a port from 1 through 65535"
  printf '%s' "$port_value"
}

controller_port_setting() {
  port_value=$(optional_setting LANEWAY_CONTROLLER_PORT)
  [ -n "$port_value" ] || port_value=8443
  case "$port_value" in *[!0-9]*) die "LANEWAY_CONTROLLER_PORT must be a port from 1 through 65535" ;; esac
  [ "$port_value" -ge 1 ] && [ "$port_value" -le 65535 ] || die "LANEWAY_CONTROLLER_PORT must be a port from 1 through 65535"
  printf '%s' "$port_value"
}

require_no_symlink_components() {
  checked_path=$1
  case "$checked_path" in
    /*) ;;
    *) checked_path=$(pwd -P)/$checked_path ;;
  esac
  old_ifs=$IFS
  IFS=/
  set -f
  # Splitting only on '/' keeps whitespace inside a path component intact.
  # shellcheck disable=SC2086
  set -- $checked_path
  set +f
  IFS=$old_ifs
  checked_prefix=
  for checked_component do
    case "$checked_component" in
      ''|.) continue ;;
      ..)
        case "$checked_prefix" in
          ''|/) checked_prefix=/ ;;
          *) checked_prefix=${checked_prefix%/*}; [ -n "$checked_prefix" ] || checked_prefix=/ ;;
        esac
        continue
        ;;
    esac
    if [ "$checked_prefix" = / ]; then
      checked_prefix=/$checked_component
    else
      checked_prefix=$checked_prefix/$checked_component
    fi
    [ ! -L "$checked_prefix" ] || die "issuer path must not contain symlinks: $checked_prefix"
  done
}

mode_allows_entry_replacement() {
  checked_mode=$1
  case "$checked_mode" in
    *[2367]?|*[2367])
      # A root-owned sticky ancestor such as /tmp cannot have a root-owned
      # child renamed by an unprivileged writer.
      case "$checked_mode" in
        [1357][0-7][0-7][0-7]) return 1 ;;
        *) return 0 ;;
      esac
      ;;
    *) return 1 ;;
  esac
}

require_protected_issuer_ancestry() {
  checked_ancestor=$1
  while [ "$checked_ancestor" != / ]; do
    checked_ancestor=${checked_ancestor%/*}
    [ -n "$checked_ancestor" ] || checked_ancestor=/
    if [ ! -d "$checked_ancestor" ] || [ -L "$checked_ancestor" ]; then
      die "issuer parent must be a real directory: $checked_ancestor"
    fi
    checked_ancestor_mode=$(stat -c '%a' "$checked_ancestor") || \
      die "could not inspect issuer parent: $checked_ancestor"
    checked_ancestor_owner=$(stat -c '%u:%g' "$checked_ancestor") || \
      die "could not inspect issuer parent ownership: $checked_ancestor"
    [ "$checked_ancestor_owner" = 0:0 ] || \
      die "issuer parent must be owned by root: $checked_ancestor"
    if mode_allows_entry_replacement "$checked_ancestor_mode"; then
      die "issuer parent permissions allow replacement: $checked_ancestor"
    fi
  done
}

source_attributes() {
  stat -c '%d:%i:%f:%s:%Y:%Z:%a:%u:%g:%h' "$1"
}

source_sha256() {
  sha256sum < "$1" | awk 'NR == 1 { print $1 }'
}

snapshot_issuer_file() {
  snapshot_source=$1
  snapshot_destination=$2
  snapshot_mode=$3
  if [ ! -f "$snapshot_source" ] || [ -L "$snapshot_source" ] || \
    [ "$(stat -c '%a:%u:%g:%h' "$snapshot_source")" != "$snapshot_mode:0:0:1" ]; then
    die "issuer file has unsafe type, ownership, mode, or link count: $snapshot_source"
  fi
  snapshot_before_attributes=$(source_attributes "$snapshot_source") || \
    die "could not inspect issuer file: $snapshot_source"
  snapshot_before_hash=$(source_sha256 "$snapshot_source") || \
    die "could not hash issuer file: $snapshot_source"
  snapshot_hash_attributes=$(source_attributes "$snapshot_source") || \
    die "could not re-inspect issuer file: $snapshot_source"
  [ "$snapshot_before_attributes" = "$snapshot_hash_attributes" ] || \
    die "issuer file changed while it was being inspected: $snapshot_source"

  install -m "$snapshot_mode" -o 0 -g 0 "$snapshot_source" "$snapshot_destination" || \
    die "could not snapshot issuer file: $snapshot_source"

  if [ ! -f "$snapshot_destination" ] || [ -L "$snapshot_destination" ] || \
    [ "$(stat -c '%a:%u:%g:%h' "$snapshot_destination")" != "$snapshot_mode:0:0:1" ]; then
    die "issuer snapshot has unsafe type, ownership, mode, or link count"
  fi
  snapshot_copy_hash=$(source_sha256 "$snapshot_destination") || \
    die "could not hash issuer snapshot"
  snapshot_after_attributes=$(source_attributes "$snapshot_source") || \
    die "could not inspect issuer source after snapshot"
  snapshot_after_hash=$(source_sha256 "$snapshot_source") || \
    die "could not hash issuer source after snapshot"
  snapshot_final_attributes=$(source_attributes "$snapshot_source") || \
    die "could not re-inspect issuer source after snapshot"
  if [ "$snapshot_before_attributes" != "$snapshot_after_attributes" ] || \
    [ "$snapshot_before_attributes" != "$snapshot_final_attributes" ] || \
    [ "$snapshot_before_hash" != "$snapshot_after_hash" ] || \
    [ "$snapshot_before_hash" != "$snapshot_copy_hash" ]; then
    die "issuer file changed while it was being snapshotted: $snapshot_source"
  fi
}

[ "$#" -eq 1 ] || die "usage: prepare.sh ISSUER_DIRECTORY"
[ "$(id -u)" -eq 0 ] || die "run as root so fixed container ownership can be installed safely"
command -v laneway >/dev/null 2>&1 || die "the signed laneway binary must be installed"
command -v jq >/dev/null 2>&1 || die "jq is required"
for command in install mktemp sha256sum stat; do
  command -v "$command" >/dev/null 2>&1 || die "required command is missing: $command"
done
if [ ! -f "$env_file" ] || [ -L "$env_file" ]; then
  die ".env must be a regular, non-symlink file"
fi
validate_env_schema

version=$(read_setting LANEWAY_VERSION)
printf '%s\n' "$version" | grep -Eq '^(dev|[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?)$' || \
  die "LANEWAY_VERSION must be dev or a pinned semantic release"
install_profile=$(read_setting LANEWAY_INSTALL_PROFILE)
case "$install_profile" in quick|production) ;; *) die "LANEWAY_INSTALL_PROFILE must be quick or production" ;; esac
for digest_key in LANEWAY_CONTROLLER_IMAGE_DIGEST LANEWAY_RELAY_IMAGE_DIGEST \
  LANEWAY_ADMIN_IMAGE_DIGEST LANEWAY_EXIT_NODE_IMAGE_DIGEST; do
  digest=$(read_setting "$digest_key")
  printf '%s\n' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || \
    die "$digest_key must be an immutable sha256 image manifest digest"
  if [ "$version" != dev ] && [ "$digest" = sha256:0000000000000000000000000000000000000000000000000000000000000000 ]; then
    die "$digest_key must use the release digest, not the development placeholder"
  fi
done
connector_digest=$(optional_setting LANEWAY_CONNECTOR_IMAGE_DIGEST)
if [ -n "$connector_digest" ]; then
  printf '%s\n' "$connector_digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || \
    die "LANEWAY_CONNECTOR_IMAGE_DIGEST must be an immutable sha256 image manifest digest"
  if [ "$version" != dev ] && [ "$connector_digest" = sha256:0000000000000000000000000000000000000000000000000000000000000000 ]; then
    die "LANEWAY_CONNECTOR_IMAGE_DIGEST must use the release digest, not the development placeholder"
  fi
fi
read_setting LANEWAY_BIND_ADDRESS >/dev/null
controller_port=$(controller_port_setting)
port_setting LANEWAY_RELAY_QUIC_PORT >/dev/null
port_setting LANEWAY_RELAY_TCP_PORT >/dev/null
port_setting LANEWAY_EXIT_DIRECT_PORT >/dev/null
network_id=$(read_setting LANEWAY_NETWORK_ID)
controller_id=$(read_setting LANEWAY_CONTROLLER_SERVICE_ID)
relay_id=$(read_setting LANEWAY_RELAY_SERVICE_ID)
network_name=$(read_setting LANEWAY_NETWORK_NAME)
ipv4_pool=$(read_setting LANEWAY_IPV4_POOL)
server_name=$(read_setting LANEWAY_CONTROLLER_SERVER_NAME)
relay_endpoint=$(read_setting LANEWAY_RELAY_PUBLIC_ENDPOINT)
backup_recipient=$(read_setting LANEWAY_BACKUP_RECIPIENT)
case "$network_id:$controller_id:$relay_id" in
  *:*:*:*|*[!0-9a-f:]*) die "network, controller, and relay IDs must be distinct 32-character lowercase hex values" ;;
esac
if [ "${#network_id}" -ne 32 ] || [ "${#controller_id}" -ne 32 ] || \
  [ "${#relay_id}" -ne 32 ] || [ "$network_id" = "$controller_id" ] || \
  [ "$network_id" = "$relay_id" ] || [ "$controller_id" = "$relay_id" ]; then
  die "network, controller, and relay IDs must be distinct 32-character lowercase hex values"
fi
printf '%s\n' "$backup_recipient" | grep -Eq '^age1[0-9a-z]{58}$' || \
  die "LANEWAY_BACKUP_RECIPIENT must be an age X25519 recipient"
relay_name=${relay_endpoint%:*}
case "$relay_name" in ''|*:*|*[!A-Za-z0-9.-]*) die "relay endpoint must use a DNS hostname and port" ;; esac

artifacts_file=${LANEWAY_BOOTSTRAP_ARTIFACTS_FILE:-}
if [ -z "$artifacts_file" ] || [ ! -f "$artifacts_file" ] || [ -L "$artifacts_file" ]; then
  die "signed bootstrap artifact manifest is missing or unsafe"
fi
if [ "$(grep -c '^\[\[bootstrap\.artifacts\]\]$' "$artifacts_file")" -ne 4 ]; then
  die "signed bootstrap artifact manifest must contain four platform artifacts"
fi
require_no_symlink_components "$1"
issuer_dir=$(CDPATH='' cd -- "$1" && pwd -P) || die "issuer directory does not exist"
case "$issuer_dir" in "$base_dir"|"$base_dir"/*) die "issuer material must be staged outside the deployment directory" ;; esac
require_protected_issuer_ancestry "$issuer_dir"
if [ ! -d "$issuer_dir" ] || [ -L "$issuer_dir" ] || \
  [ "$(stat -c '%a:%u:%g' "$issuer_dir")" != 700:0:0 ]; then
  die "issuer directory must be a real root-owned directory with mode 0700"
fi
issuer_source_attributes=$(source_attributes "$issuer_dir") || die "could not inspect issuer directory"
if [ -e "$issuer_dir/ca.key" ] || [ -L "$issuer_dir/ca.key" ]; then
  die "offline root private key ca.key must never be copied to the control host"
fi
for path in "$issuer_dir"/*.key; do
  [ -e "$path" ] || [ -L "$path" ] || continue
  [ "$(basename "$path")" = intermediate.key ] || die "issuer directory contains an unexpected private key: $path"
done
if [ ! -d /run ] || [ -L /run ] || [ "$(stat -c '%u:%g' /run)" != 0:0 ] || \
  mode_allows_entry_replacement "$(stat -c '%a' /run)"; then
  die "/run must be a protected root-owned directory for issuer staging"
fi
issuer_snapshot=$(mktemp -d /run/laneway-issuer.XXXXXX) || die "could not create protected issuer staging"
chmod 0700 "$issuer_snapshot"
chown 0:0 "$issuer_snapshot"
if [ -L "$issuer_snapshot" ] || [ "$(stat -c '%a:%u:%g' "$issuer_snapshot")" != 700:0:0 ]; then
  die "issuer staging directory is unsafe"
fi
snapshot_issuer_file "$issuer_dir/ca.crt" "$issuer_snapshot/ca.crt" 444
snapshot_issuer_file "$issuer_dir/intermediate-chain.crt" "$issuer_snapshot/intermediate-chain.crt" 444
snapshot_issuer_file "$issuer_dir/intermediate.key" "$issuer_snapshot/intermediate.key" 400
issuer_source_after=$(source_attributes "$issuer_dir") || die "could not re-inspect issuer directory"
[ "$issuer_source_attributes" = "$issuer_source_after" ] || \
  die "issuer directory changed while it was being snapshotted"

# From this point onward, certificate validation, idempotency checks, and leaf
# issuance consume only the protected point-in-time snapshot.
issuer_dir=$issuer_snapshot
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

cat > "$staging/controller.toml" <<EOF
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

[controller.initial_network]
network_id = "$network_id"
name = "$network_name"
ipv4_pool = "$ipv4_pool"

[bootstrap]
network_id = "$network_id"
controller_endpoint = "https://$server_name:$controller_port"
controller_quic_endpoint = "$server_name:$controller_port"
controller_server_name = "$server_name"
EOF
cat "$artifacts_file" >> "$staging/controller.toml"
initial_network=$(laneway config inspect-controller-initial-network -config "$staging/controller.toml") || \
  die "generated controller configuration is invalid"
printf '%s\n' "$initial_network" | jq -e \
  --arg network_id "$network_id" --arg name "$network_name" --arg ipv4_pool "$ipv4_pool" '
    type == "object" and .configured == true and
    .network_id == $network_id and .name == $name and .ipv4_pool == $ipv4_pool and
    .bootstrap_network_id == $network_id and
    (has("ipv6_pool") | not) and
    ((keys - ["configured", "network_id", "name", "ipv4_pool", "bootstrap_network_id"]) | length == 0)
  ' >/dev/null || die "generated controller initial-network configuration is invalid"
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

[public_https]
server_name = "$server_name"
cache_dir = "/var/lib/laneway-public"
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
