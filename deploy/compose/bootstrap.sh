#!/bin/sh
set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$(printf ' \t\n_'); IFS=${IFS%_}
export PATH
unset ENV BASH_ENV CDPATH

base_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
die() { echo "Laneway bootstrap: $*" >&2; exit 1; }
case "$base_dir" in *[!A-Za-z0-9_./-]*) die "deployment directory contains an unsafe character" ;; esac
configure_trusted_docker_client() {
  command -v stat >/dev/null 2>&1 || die "stat is required for trusted Docker configuration"
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
compose_files="-f $base_dir/compose.yaml"
case "${1:-}" in
  '') ;;
  --dev) compose_files="$compose_files -f $base_dir/compose.dev.yaml" ;;
  *) echo "usage: bootstrap.sh [--dev]" >&2; exit 1 ;;
esac
if [ "$#" -gt 1 ]; then
  echo "usage: bootstrap.sh [--dev]" >&2
  exit 1
fi

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
configure_trusted_docker_client

read_setting() {
  setting_key=$1
  canonical_count=$(grep -c "^${setting_key}=" "$base_dir/.env" || true)
  mention_count=$(grep -Ec "^[[:space:]]*(export[[:space:]]+)?${setting_key}[[:space:]]*=" "$base_dir/.env" || true)
  if [ "$mention_count" -ne "$canonical_count" ]; then
    echo "malformed $setting_key in .env" >&2
    exit 1
  fi
  if [ "$canonical_count" -ne 1 ]; then
    echo "$setting_key must appear exactly once in .env" >&2
    exit 1
  fi
  setting_value=$(sed -n "s/^${setting_key}=//p" "$base_dir/.env")
  if [ -z "$setting_value" ]; then
    echo "$setting_key must not be empty in .env" >&2
    exit 1
  fi
  case "$setting_value" in
    *[!A-Za-z0-9._:/-]*) echo "$setting_key contains an unsafe character" >&2; exit 1 ;;
  esac
  printf '%s' "$setting_value"
}

env -u DOCKER_CONFIG -u ENV -u BASH_ENV -u CDPATH -u IFS HOME=/root "$base_dir/validate.sh"

network_id=$(read_setting LANEWAY_NETWORK_ID)
controller_id=$(read_setting LANEWAY_CONTROLLER_SERVICE_ID)
relay_id=$(read_setting LANEWAY_RELAY_SERVICE_ID)
network_name=$(read_setting LANEWAY_NETWORK_NAME)
ipv4_pool=$(read_setting LANEWAY_IPV4_POOL)
relay_endpoint=$(read_setting LANEWAY_RELAY_PUBLIC_ENDPOINT)
server_name=$(read_setting LANEWAY_CONTROLLER_SERVER_NAME)

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
  # Paths are derived from this script's directory and contain no whitespace in
  # the supported packaged layout.
  # shellcheck disable=SC2086
  compose_environment docker --context default compose --project-name laneway --project-directory "$base_dir" --env-file "$base_dir/.env" \
    $compose_files "$@"
}

admin() {
  compose --profile tools run --rm admin "$@"
}

compose up -d controller --wait

common="--controller https://controller:8443 --ca /run/laneway-secrets/ca.crt --server-name $server_name --controller-network-id $network_id --controller-service-id $controller_id --admin-token-file /run/laneway-secrets/admin.token"

# Values are validated as delimiter-free atoms by validate.sh. Intentional word
# splitting turns the fixed option string into argv without evaluating it.
# shellcheck disable=SC2086
if ! network=$(admin controller network get $common --network-id "$network_id"); then
  echo "controller did not expose configured initial network $network_id; refusing relay bootstrap" >&2
  exit 1
fi
if ! printf '%s\n' "$network" | jq -e -s --arg id "$network_id" \
  --arg name "$network_name" --arg pool "$ipv4_pool" \
  'length == 1 and .[0].network_id == $id and .[0].name == $name and .[0].ipv4_pool == $pool' >/dev/null; then
  echo "existing network $network_id does not match .env; refusing to overwrite it" >&2
  exit 1
fi

# shellcheck disable=SC2086
relays=$(admin controller relay list $common --network-id "$network_id" --limit 1000)
relay_count=$(printf '%s\n' "$relays" | jq --arg id "$relay_id" '[.relays[] | select(.service_id == $id)] | length')
case "$relay_count" in
  0)
    # shellcheck disable=SC2086
    admin controller relay register $common --network-id "$network_id" \
      --service-id "$relay_id" --name relay --endpoint "$relay_endpoint" >/dev/null
    ;;
  1)
    if ! printf '%s\n' "$relays" | jq -e --arg id "$relay_id" \
      --arg endpoint "$relay_endpoint" \
      '.relays[] | select(.service_id == $id) | .enabled == true and .endpoint == $endpoint' >/dev/null; then
      echo "existing relay $relay_id does not match .env; refusing to overwrite it" >&2
      exit 1
    fi
    ;;
  *)
    echo "controller returned duplicate relay service IDs" >&2
    exit 1
    ;;
esac

compose up -d relay --wait
compose ps
