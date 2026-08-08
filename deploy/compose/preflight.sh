#!/bin/sh
set -eu

base_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
env_file=$base_dir/.env
dev=false
[ "${1:-}" != --dev ] || { dev=true; shift; }
[ "$#" -eq 0 ] || { echo "usage: preflight.sh [--dev]" >&2; exit 1; }

die() { echo "Laneway preflight: $*" >&2; exit 1; }
read_setting() {
  key=$1
  value=$(sed -n "s/^${key}=//p" "$env_file")
  [ -n "$value" ] && [ "$(printf '%s\n' "$value" | wc -l)" -eq 1 ] || die "missing or duplicate $key in .env"
  case "$value" in *[!A-Za-z0-9._:/-]*) die "$key contains an unsafe character" ;; esac
  printf '%s' "$value"
}
compose() {
  docker compose --project-directory "$base_dir" --env-file "$env_file" -f "$base_dir/compose.yaml" "$@"
}

for command in docker sed grep stat; do command -v "$command" >/dev/null 2>&1 || die "required command is missing: $command"; done
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is unavailable"
server_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null) || die "Docker Engine is unavailable"
server_major=${server_version%%.*}
case "$server_major" in ''|*[!0-9]*) die "cannot parse Docker Engine version: $server_version" ;; esac
[ "$server_major" -ge 26 ] || die "Docker Engine 26 or newer is required (found $server_version)"

if [ "$dev" = false ]; then
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
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "invalid $protocol port: $port"
    case "$protocol" in tcp) flag=-ltn ;; udp) flag=-lun ;; esac
    listeners=$(ss -H "$flag" "sport = :$port") || die "cannot inspect $protocol port $port"
    if [ -n "$listeners" ]; then
      die "$protocol port $port is already occupied by foreign state"
    fi
  }
  controller_port=$(read_setting LANEWAY_CONTROLLER_PORT)
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
