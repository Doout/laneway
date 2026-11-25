#!/bin/sh
set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$(printf ' \t\n_'); IFS=${IFS%_}
export PATH
unset ENV BASH_ENV CDPATH

base_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
env_file=$base_dir/.env
dev=false
[ "${1:-}" != --dev ] || { dev=true; shift; }
[ "$#" -eq 0 ] || { echo "usage: preflight.sh [--dev]" >&2; exit 1; }

die() { echo "Laneway preflight: $*" >&2; exit 1; }
case "$base_dir" in *[!A-Za-z0-9_./-]*) die "deployment directory contains an unsafe character" ;; esac
configure_trusted_docker_client() {
  if [ -e /root ] || [ -L /root ]; then
    [ -d /root ] && [ ! -L /root ] && [ "$(stat -c '%u:%g' /root)" = 0:0 ] && \
      [ $((0$(stat -c '%a' /root) & 0022)) -eq 0 ] || \
      die "/root must be a root-owned real directory not writable by group or others"
  else
    [ "$(stat -c '%u:%g' /)" = 0:0 ] && [ $((0$(stat -c '%a' /) & 0022)) -eq 0 ] || \
      die "the filesystem root must protect the absent /root Docker configuration parent"
  fi
  docker_config=/root/.docker
  if [ -e "$docker_config" ] || [ -L "$docker_config" ]; then
    [ -d "$docker_config" ] && [ ! -L "$docker_config" ] && \
      [ "$(stat -c '%u:%g' "$docker_config")" = 0:0 ] && \
      [ $((0$(stat -c '%a' "$docker_config") & 0022)) -eq 0 ] || \
      die "/root/.docker must be a root-owned real directory not writable by group or others"
  fi
  DOCKER_CONFIG=$docker_config
  HOME=/root
  export DOCKER_CONFIG HOME
}
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

read_setting_from() {
  setting_file=$1
  setting_key=$2
  canonical_count=$(grep -c "^${setting_key}=" "$setting_file" || true)
  mention_count=$(grep -Ec "^[[:space:]]*(export[[:space:]]+)?${setting_key}[[:space:]]*=" "$setting_file" || true)
  [ "$mention_count" -eq "$canonical_count" ] || die "malformed $setting_key in .env"
  [ "$canonical_count" -eq 1 ] || die "$setting_key must appear exactly once in .env"
  setting_value=$(sed -n "s/^${setting_key}=//p" "$setting_file")
  [ -n "$setting_value" ] || die "$setting_key must not be empty in .env"
  case "$setting_value" in *[!A-Za-z0-9._:/-]*) die "$setting_key contains an unsafe character" ;; esac
  printf '%s' "$setting_value"
}

optional_setting_from() {
  setting_file=$1
  setting_key=$2
  canonical_count=$(grep -c "^${setting_key}=" "$setting_file" || true)
  mention_count=$(grep -Ec "^[[:space:]]*(export[[:space:]]+)?${setting_key}[[:space:]]*=" "$setting_file" || true)
  [ "$mention_count" -eq "$canonical_count" ] || die "malformed $setting_key in .env"
  case "$canonical_count" in
    0) printf '%s' ''; return ;;
    1) ;;
    *) die "$setting_key must appear at most once in .env" ;;
  esac
  setting_value=$(sed -n "s/^${setting_key}=//p" "$setting_file")
  [ -n "$setting_value" ] || die "$setting_key must not be empty in .env"
  case "$setting_value" in *[!A-Za-z0-9._:/-]*) die "$setting_key contains an unsafe character" ;; esac
  printf '%s' "$setting_value"
}

read_setting() { read_setting_from "$env_file" "$1"; }
optional_setting() { optional_setting_from "$env_file" "$1"; }

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

compose_environment() {
  env \
    -u LANEWAY_VERSION \
    -u LANEWAY_CONTROLLER_IMAGE_DIGEST \
    -u LANEWAY_RELAY_IMAGE_DIGEST \
    -u LANEWAY_ADMIN_IMAGE_DIGEST \
    -u LANEWAY_CONNECTOR_IMAGE_DIGEST \
    -u LANEWAY_EXIT_NODE_IMAGE_DIGEST \
    -u LANEWAY_BIND_ADDRESS \
    -u LANEWAY_CONTROLLER_PORT \
    -u LANEWAY_RELAY_QUIC_PORT \
    -u LANEWAY_RELAY_TCP_PORT \
    -u LANEWAY_EXIT_DIRECT_PORT \
    -u LANEWAY_CONTROLLER_SERVER_NAME \
    -u COMPOSE_PROJECT_NAME \
    -u COMPOSE_PROFILES \
    -u COMPOSE_FILE \
    -u COMPOSE_PATH_SEPARATOR \
    -u COMPOSE_ENV_FILES \
    -u COMPOSE_DISABLE_ENV_FILE \
    -u COMPOSE_CONVERT_WINDOWS_PATHS \
    -u COMPOSE_IGNORE_ORPHANS \
    -u COMPOSE_REMOVE_ORPHANS \
    -u COMPOSE_PARALLEL_LIMIT \
    -u COMPOSE_ANSI \
    -u COMPOSE_PROGRESS \
    -u COMPOSE_STATUS_STDOUT \
    -u COMPOSE_MENU \
    -u COMPOSE_EXPERIMENTAL \
    -u COMPOSE_BAKE \
    -u COMPOSE_HTTP_TIMEOUT \
    -u DOCKER_DEFAULT_PLATFORM \
    "$@"
}

compose() {
  compose_environment docker --context default compose --project-name laneway --project-directory "$base_dir" --env-file "$env_file" -f "$base_dir/compose.yaml" "$@"
}

if env | grep -E '^COMPOSE_[A-Za-z0-9_]*=' >/dev/null; then
  die "ambient COMPOSE_* overrides are not allowed"
fi
if [ "${DOCKER_HOST+x}" = x ] || [ "${DOCKER_CONTEXT+x}" = x ] || \
  [ "${DOCKER_TLS+x}" = x ] || \
  [ "${DOCKER_TLS_VERIFY+x}" = x ] || [ "${DOCKER_CERT_PATH+x}" = x ] || \
  [ "${DOCKER_CONFIG+x}" = x ]; then
  die "Docker target overrides are not allowed"
fi
unset DOCKER_DEFAULT_PLATFORM
for command in awk docker env jq sed grep stat; do command -v "$command" >/dev/null 2>&1 || die "required command is missing: $command"; done
configure_trusted_docker_client
if [ ! -f "$env_file" ] || [ -L "$env_file" ]; then die ".env must be a regular, non-symlink file"; fi
validate_env_schema

version=$(read_setting LANEWAY_VERSION)
printf '%s\n' "$version" | grep -Eq '^(dev|[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?)$' || \
  die "LANEWAY_VERSION must be dev or a pinned semantic release"
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
install_profile=$(read_setting LANEWAY_INSTALL_PROFILE)
case "$install_profile" in quick|production) ;; *) die "LANEWAY_INSTALL_PROFILE must be quick or production" ;; esac
read_setting LANEWAY_BIND_ADDRESS >/dev/null
controller_port_setting >/dev/null
port_setting LANEWAY_RELAY_QUIC_PORT >/dev/null
port_setting LANEWAY_RELAY_TCP_PORT >/dev/null
port_setting LANEWAY_EXIT_DIRECT_PORT >/dev/null
read_setting LANEWAY_CONTROLLER_SERVER_NAME >/dev/null
network_id=$(read_setting LANEWAY_NETWORK_ID)
controller_id=$(read_setting LANEWAY_CONTROLLER_SERVICE_ID)
relay_id=$(read_setting LANEWAY_RELAY_SERVICE_ID)
case "$network_id:$controller_id:$relay_id" in
  *:*:*:*|*[!0-9a-f:]*) die "network, controller, and relay IDs must be distinct 32-character lowercase hex values" ;;
esac
if [ "${#network_id}" -ne 32 ] || [ "${#controller_id}" -ne 32 ] || \
  [ "${#relay_id}" -ne 32 ] || [ "$network_id" = "$controller_id" ] || \
  [ "$network_id" = "$relay_id" ] || [ "$controller_id" = "$relay_id" ]; then
  die "network, controller, and relay IDs must be distinct 32-character lowercase hex values"
fi
read_setting LANEWAY_NETWORK_NAME >/dev/null
read_setting LANEWAY_IPV4_POOL >/dev/null
read_setting LANEWAY_RELAY_PUBLIC_ENDPOINT >/dev/null
backup_recipient=$(read_setting LANEWAY_BACKUP_RECIPIENT)
printf '%s\n' "$backup_recipient" | grep -Eq '^age1[0-9a-z]{58}$' || \
  die "LANEWAY_BACKUP_RECIPIENT must be an age X25519 recipient"

compose_environment docker --context default compose version >/dev/null 2>&1 || die "Docker Compose v2 is unavailable"
server_version=$(docker --context default version --format '{{.Server.Version}}' 2>/dev/null) || die "Docker Engine is unavailable"
server_major=${server_version%%.*}
case "$server_major" in ''|*[!0-9]*) die "cannot parse Docker Engine version: $server_version" ;; esac
[ "$server_major" -ge 26 ] || die "Docker Engine 26 or newer is required (found $server_version)"

if [ "$dev" = false ]; then
  command -v age >/dev/null 2>&1 || die "age is required for encrypted recovery bundles"
  command -v getent >/dev/null 2>&1 || die "getent is required for DNS validation"
  for hostname in "$(read_setting LANEWAY_CONTROLLER_SERVER_NAME)" "$(read_setting LANEWAY_RELAY_PUBLIC_ENDPOINT)"; do
    hostname=${hostname%:*}
    getent ahosts "$hostname" >/dev/null 2>&1 || die "public DNS does not resolve: $hostname"
  done
fi

owned=$(compose ps --all --quiet 2>/dev/null || true)
if [ -z "$owned" ]; then
  command -v ss >/dev/null 2>&1 || die "ss is required for non-mutating port availability checks"
  check_port() {
    protocol=$1; port=$2
    case "$port" in ''|*[!0-9]*) die "invalid $protocol port: $port" ;; esac
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
      die "invalid $protocol port: $port"
    fi
    case "$protocol" in tcp) flag=-ltn ;; udp) flag=-lun ;; esac
    listeners=$(ss -H "$flag" "sport = :$port") || die "cannot inspect $protocol port $port"
    if [ -n "$listeners" ]; then
      die "$protocol port $port is already occupied by foreign state"
    fi
  }
  controller_port=$(controller_port_setting)
  check_port tcp "$controller_port"
  check_port udp "$controller_port"
  check_port udp "$(read_setting LANEWAY_RELAY_QUIC_PORT)"
  check_port tcp "$(read_setting LANEWAY_RELAY_TCP_PORT)"
  if [ -e "$base_dir/generated/config/exit-node.toml" ]; then
    check_port udp "$(read_setting LANEWAY_EXIT_DIRECT_PORT)"
  fi
fi

if [ -e "$base_dir/generated/config/exit-node.toml" ]; then
  [ -c /dev/net/tun ] || die "the optional Exit Node requires character device /dev/net/tun"
fi

echo "Laneway host prerequisites are valid (read-only checks only)"
