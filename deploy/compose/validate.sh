#!/bin/sh
set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$(printf ' \t\n_'); IFS=${IFS%_}
export PATH
unset ENV BASH_ENV CDPATH

base_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
env_file=$base_dir/.env

die() { echo "Laneway validation: $*" >&2; exit 1; }
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

validate_env_schema() {
  awk '
    /^[[:space:]]*($|#)/ { next }
    {
      key = $0
      if (key !~ /^[A-Z][A-Z0-9_]*=/) exit 1
      sub(/=.*/, "", key)
      if (key != "LANEWAY_VERSION" &&
          key != "LANEWAY_INSTALL_PROFILE" &&
          key != "LANEWAY_CONTROLLER_IMAGE_DIGEST" &&
          key != "LANEWAY_RELAY_IMAGE_DIGEST" &&
          key != "LANEWAY_ADMIN_IMAGE_DIGEST" &&
          key != "LANEWAY_CONNECTOR_IMAGE_DIGEST" &&
          key != "LANEWAY_EXIT_NODE_IMAGE_DIGEST" &&
          key != "LANEWAY_BIND_ADDRESS" &&
          key != "LANEWAY_CONTROLLER_PORT" &&
          key != "LANEWAY_RELAY_QUIC_PORT" &&
          key != "LANEWAY_RELAY_TCP_PORT" &&
          key != "LANEWAY_EXIT_DIRECT_PORT" &&
          key != "LANEWAY_CONTROLLER_SERVER_NAME" &&
          key != "LANEWAY_NETWORK_ID" &&
          key != "LANEWAY_CONTROLLER_SERVICE_ID" &&
          key != "LANEWAY_RELAY_SERVICE_ID" &&
          key != "LANEWAY_NETWORK_NAME" &&
          key != "LANEWAY_IPV4_POOL" &&
          key != "LANEWAY_RELAY_PUBLIC_ENDPOINT" &&
          key != "LANEWAY_BACKUP_RECIPIENT") exit 1
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
  case "$setting_value" in
    *[!A-Za-z0-9._:/-]*) die "$setting_key contains an unsafe character" ;;
  esac
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
  case "$setting_value" in
    *[!A-Za-z0-9._:/-]*) die "$setting_key contains an unsafe character" ;;
  esac
  printf '%s' "$setting_value"
}

read_setting() { read_setting_from "$env_file" "$1"; }
optional_setting() { optional_setting_from "$env_file" "$1"; }

port_setting() {
  port_key=$1
  port_value=$(read_setting "$port_key")
  case "$port_value" in
    *[!0-9]*) die "$port_key must be a port from 1 through 65535" ;;
  esac
  [ "$port_value" -ge 1 ] && [ "$port_value" -le 65535 ] || \
    die "$port_key must be a port from 1 through 65535"
  printf '%s' "$port_value"
}

controller_port_setting() {
  port_value=$(optional_setting LANEWAY_CONTROLLER_PORT)
  [ -n "$port_value" ] || port_value=8443
  case "$port_value" in
    *[!0-9]*) die "LANEWAY_CONTROLLER_PORT must be a port from 1 through 65535" ;;
  esac
  [ "$port_value" -ge 1 ] && [ "$port_value" -le 65535 ] || \
    die "LANEWAY_CONTROLLER_PORT must be a port from 1 through 65535"
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
if [ ! -f "$env_file" ] || [ -L "$env_file" ]; then
  die ".env must be a regular, non-symlink file"
fi
validate_env_schema

version=$(read_setting LANEWAY_VERSION)
if ! printf '%s\n' "$version" | grep -E '^(dev|[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?)$' >/dev/null; then
  die "LANEWAY_VERSION must be dev or a pinned semantic release such as 0.1.0"
fi

install_profile=$(read_setting LANEWAY_INSTALL_PROFILE)
case "$install_profile" in
  quick|production) ;;
  *) die "LANEWAY_INSTALL_PROFILE must be quick or production" ;;
esac

digest_keys="LANEWAY_CONTROLLER_IMAGE_DIGEST LANEWAY_RELAY_IMAGE_DIGEST LANEWAY_ADMIN_IMAGE_DIGEST LANEWAY_EXIT_NODE_IMAGE_DIGEST"
for key in $digest_keys
do
  digest=$(read_setting "$key")
  if ! printf '%s\n' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$'; then
    die "$key must be an immutable sha256 image manifest digest"
  fi
  if [ "$version" != dev ] && [ "$digest" = sha256:0000000000000000000000000000000000000000000000000000000000000000 ]; then
    die "$key must use the release digest, not the development placeholder"
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
controller_port_setting >/dev/null
port_setting LANEWAY_RELAY_QUIC_PORT >/dev/null
port_setting LANEWAY_RELAY_TCP_PORT >/dev/null
port_setting LANEWAY_EXIT_DIRECT_PORT >/dev/null

network_id=$(read_setting LANEWAY_NETWORK_ID)
controller_id=$(read_setting LANEWAY_CONTROLLER_SERVICE_ID)
relay_id=$(read_setting LANEWAY_RELAY_SERVICE_ID)
case "$network_id:$controller_id:$relay_id" in
  REPLACE_*|*:*:*:*|*[!0-9a-f:]* )
    echo "network, controller, and relay IDs must be distinct 32-character lowercase hex values" >&2
    exit 1
    ;;
esac
if [ "${#network_id}" -ne 32 ] || [ "${#controller_id}" -ne 32 ] || \
   [ "${#relay_id}" -ne 32 ] || [ "$network_id" = "$controller_id" ] || \
   [ "$network_id" = "$relay_id" ] || [ "$controller_id" = "$relay_id" ]; then
  echo "network, controller, and relay IDs must be distinct 32-character lowercase hex values" >&2
  exit 1
fi
read_setting LANEWAY_CONTROLLER_SERVER_NAME >/dev/null
network_name=$(read_setting LANEWAY_NETWORK_NAME)
ipv4_pool=$(read_setting LANEWAY_IPV4_POOL)
read_setting LANEWAY_RELAY_PUBLIC_ENDPOINT >/dev/null
backup_recipient=$(read_setting LANEWAY_BACKUP_RECIPIENT)
if ! printf '%s\n' "$backup_recipient" | grep -Eq '^age1[0-9a-z]{58}$'; then
  echo "LANEWAY_BACKUP_RECIPIENT must be an age X25519 recipient" >&2
  exit 1
fi

for path in \
  generated/config/controller.toml \
  generated/config/relay.toml \
  generated/pki/ca.crt \
  generated/pki/intermediate-chain.crt \
  generated/pki/intermediate.key \
  generated/pki/controller.crt \
  generated/pki/controller.key \
  generated/pki/relay.crt \
  generated/pki/relay.key \
  generated/secrets/admin.token
do
  target=$base_dir/$path
  if [ ! -f "$target" ] || [ -L "$target" ]; then
    echo "missing regular, non-symlink file: $path" >&2
    exit 1
  fi
  mode=$(stat -c '%a' "$target")
  case "$path" in
    *.key|*.token)
      if [ "$mode" != 400 ]; then
        echo "$path must have mode 0400 (found $mode)" >&2
        exit 1
      fi
      owner=$(stat -c '%u' "$target")
      if [ "$owner" != 65532 ]; then
        echo "$path must be owned by container UID 65532 (found $owner)" >&2
        exit 1
      fi
      ;;
    *)
      if [ "$mode" != 444 ]; then
        echo "$path must have mode 0444 (found $mode)" >&2
        exit 1
      fi
      ;;
  esac
done

controller_config=$base_dir/generated/config/controller.toml
command -v laneway >/dev/null 2>&1 || die "the signed laneway binary is required"
command -v jq >/dev/null 2>&1 || die "jq is required"
initial_network=$(laneway config inspect-controller-initial-network -config "$controller_config") || \
  die "controller configuration is invalid"
printf '%s\n' "$initial_network" | jq -e \
  --arg network_id "$network_id" --arg name "$network_name" --arg ipv4_pool "$ipv4_pool" '
    type == "object" and
    ((.configured == false and
      ((has("bootstrap_network_id") | not) or .bootstrap_network_id == $network_id) and
      ((keys - ["configured", "bootstrap_network_id"]) | length == 0)) or
     (.configured == true and .network_id == $network_id and .name == $name and
      .ipv4_pool == $ipv4_pool and
      ((has("bootstrap_network_id") | not) or .bootstrap_network_id == $network_id) and
      ((has("ipv6_pool") | not) or (.ipv6_pool | type == "string" and length > 0)) and
      ((keys - ["configured", "network_id", "name", "ipv4_pool", "ipv6_pool", "bootstrap_network_id"]) | length == 0)))
  ' >/dev/null || die "controller initial-network configuration does not match .env"

exit_artifacts="generated/config/exit-node.toml generated/pki/exit-node.crt generated/pki/exit-node.key"
exit_configured=false
for path in $exit_artifacts; do
  if [ -e "$base_dir/$path" ]; then
    exit_configured=true
  fi
done
if [ "$exit_configured" = true ]; then
  for path in $exit_artifacts; do
    target=$base_dir/$path
    if [ ! -f "$target" ] || [ -L "$target" ]; then
      echo "missing regular, non-symlink Exit Node file: $path" >&2
      exit 1
    fi
    mode=$(stat -c '%a' "$target")
    case "$path" in
      *.key)
        [ "$mode" = 400 ] || { echo "$path must have mode 0400 (found $mode)" >&2; exit 1; }
        owner=$(stat -c '%u' "$target")
        [ "$owner" = 65532 ] || { echo "$path must be owned by container UID 65532 (found $owner)" >&2; exit 1; }
        ;;
      *)
        [ "$mode" = 444 ] || { echo "$path must have mode 0444 (found $mode)" >&2; exit 1; }
        ;;
    esac
  done
  if grep -E 'REPLACE_|CHANGE_ME|latest([:@]|$)' "$base_dir/generated/config/exit-node.toml" >/dev/null 2>&1; then
    echo "generated Exit Node configuration still contains a placeholder or mutable tag" >&2
    exit 1
  fi
fi

if grep -E 'REPLACE_|CHANGE_ME|latest([:@]|$)' \
  "$base_dir/generated/config/controller.toml" \
  "$base_dir/generated/config/relay.toml" \
  "$base_dir/.env" >/dev/null 2>&1; then
  echo "generated configuration still contains a placeholder or mutable tag" >&2
  exit 1
fi

backup_dir=$base_dir/generated/backups
if [ -e "$backup_dir" ] && { [ ! -d "$backup_dir" ] || [ -L "$backup_dir" ]; }; then
  echo "generated/backups must be a real directory" >&2
  exit 1
fi
install -d -m 0700 "$backup_dir"
chown 65532:65532 "$backup_dir"
for path in "$backup_dir"/*; do
  [ -e "$path" ] || continue
  if [ ! -f "$path" ] || [ -L "$path" ]; then
    echo "backup entries must be regular, non-symlink files: $path" >&2
    exit 1
  fi
  mode=$(stat -c '%a' "$path")
  owner=$(stat -c '%u' "$path")
  if [ "$mode" != 600 ] || [ "$owner" != 65532 ]; then
    echo "backup files must be owned by UID 65532 with mode 0600: $path" >&2
    exit 1
  fi
done

recovery_dir=$base_dir/generated/recovery
if [ -e "$recovery_dir" ] || [ -L "$recovery_dir" ]; then
  if [ ! -d "$recovery_dir" ] || [ -L "$recovery_dir" ]; then
    echo "generated/recovery must be a real directory" >&2
    exit 1
  fi
  if [ "$(stat -c '%a:%u:%g' "$recovery_dir")" != 700:0:0 ]; then
    echo "generated/recovery must be root-owned with mode 0700" >&2
    exit 1
  fi
  for path in "$recovery_dir"/*; do
    [ -e "$path" ] || continue
    if [ ! -f "$path" ] || [ -L "$path" ] || [ "$(stat -c '%a:%u:%g' "$path")" != 600:0:0 ]; then
      echo "recovery bundles must be root-owned regular files with mode 0600: $path" >&2
      exit 1
    fi
  done
fi

compose_environment docker --context default compose --project-name laneway --project-directory "$base_dir" \
  --env-file "$base_dir/.env" \
  -f "$base_dir/compose.yaml" config --quiet
if [ "$exit_configured" = true ]; then
  compose_environment docker --context default compose --project-name laneway --project-directory "$base_dir" --profile exit-node \
    --env-file "$base_dir/.env" -f "$base_dir/compose.yaml" config --quiet
fi
echo "Laneway Compose inputs are valid"
