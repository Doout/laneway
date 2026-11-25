#!/bin/sh
set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$(printf ' \t\n_'); IFS=${IFS%_}
export PATH
unset ENV BASH_ENV CDPATH

die() { echo "Laneway control-plane upgrade: $*" >&2; exit 1; }

work_dir=
lock_dir=
lock_marker=
lock_owner=false

# Invoked by the EXIT trap installed immediately below.
# shellcheck disable=SC2329
cleanup() {
  [ -z "$work_dir" ] || [ ! -e "$work_dir" ] || find "$work_dir" -depth -delete 2>/dev/null || true
  if [ "$lock_owner" = true ]; then
    [ -z "$lock_marker" ] || [ ! -e "$lock_marker" ] || find "$lock_marker" -maxdepth 0 -delete 2>/dev/null || true
    [ -z "$lock_dir" ] || [ ! -d "$lock_dir" ] || find "$lock_dir" -maxdepth 0 -delete 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

validate_env_schema() {
  schema_file=$1
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
  ' "$schema_file" || die "${schema_file##*/} must contain only canonical, managed KEY=value assignments, comments, or blank lines"
}

read_setting() {
  setting_file=$1
  setting_key=$2
  setting_count=$(grep -c "^${setting_key}=" "$setting_file" || true)
  setting_mentions=$(grep -Ec "^[[:space:]]*(export[[:space:]]+)?${setting_key}[[:space:]]*=" "$setting_file" || true)
  [ "$setting_mentions" -eq "$setting_count" ] || \
    die "malformed $setting_key in ${setting_file##*/}"
  setting_value=$(sed -n "s/^${setting_key}=//p" "$setting_file")
  if [ "$setting_count" -ne 1 ] || [ -z "$setting_value" ]; then
    die "missing or duplicate $setting_key in ${setting_file##*/}"
  fi
  case "$setting_value" in *[!A-Za-z0-9._:/+-]*) die "$setting_key contains an unsafe character" ;; esac
  printf '%s' "$setting_value"
}

optional_setting() {
  setting_file=$1
  setting_key=$2
  setting_count=$(grep -c "^${setting_key}=" "$setting_file" || true)
  setting_mentions=$(grep -Ec "^[[:space:]]*(export[[:space:]]+)?${setting_key}[[:space:]]*=" "$setting_file" || true)
  [ "$setting_mentions" -eq "$setting_count" ] || \
    die "malformed $setting_key in ${setting_file##*/}"
  case "$setting_count" in
    0) return 1 ;;
    1) ;;
    *) die "duplicate $setting_key in ${setting_file##*/}" ;;
  esac
  setting_value=$(sed -n "s/^${setting_key}=//p" "$setting_file")
  [ -n "$setting_value" ] || die "$setting_key must not be empty in ${setting_file##*/}"
  case "$setting_value" in *[!A-Za-z0-9._:/+-]*) die "$setting_key contains an unsafe character" ;; esac
  printf '%s' "$setting_value"
}

controller_port_setting() {
  setting_file=$1
  setting_count=$(grep -c '^LANEWAY_CONTROLLER_PORT=' "$setting_file" || true)
  setting_mentions=$(grep -Ec '^[[:space:]]*(export[[:space:]]+)?LANEWAY_CONTROLLER_PORT[[:space:]]*=' "$setting_file" || true)
  [ "$setting_mentions" -eq "$setting_count" ] || \
    die "malformed LANEWAY_CONTROLLER_PORT in ${setting_file##*/}"
  case "$setting_count" in
    0) setting_value=8443 ;;
    1) setting_value=$(sed -n 's/^LANEWAY_CONTROLLER_PORT=//p' "$setting_file") ;;
    *) die "duplicate LANEWAY_CONTROLLER_PORT in ${setting_file##*/}" ;;
  esac
  case "$setting_value" in
    ''|*[!0-9]*) die "LANEWAY_CONTROLLER_PORT must be a port from 1 through 65535" ;;
  esac
  [ "$setting_value" -ge 1 ] && [ "$setting_value" -le 65535 ] || \
    die "LANEWAY_CONTROLLER_PORT must be a port from 1 through 65535"
  printf '%s' "$setting_value"
}

port_setting() {
  setting_file=$1
  setting_key=$2
  setting_value=$(read_setting "$setting_file" "$setting_key")
  case "$setting_value" in
    ''|*[!0-9]*) die "$setting_key must be a port from 1 through 65535" ;;
  esac
  [ "$setting_value" -ge 1 ] && [ "$setting_value" -le 65535 ] || \
    die "$setting_key must be a port from 1 through 65535"
  printf '%s' "$setting_value"
}

validate_ipv4() {
  printf '%s\n' "$1" | awk -F. '
    NF != 4 { exit 1 }
    {
      for (octet_index = 1; octet_index <= 4; octet_index++) {
        if ($octet_index !~ /^[0-9]+$/ || sprintf("%d", $octet_index + 0) != $octet_index ||
            $octet_index < 0 || $octet_index > 255) exit 1
      }
    }
  '
}

validate_ipv4_pool() {
  printf '%s\n' "$1" | awk -F/ '
    function overlaps(first, last, reserved_first, reserved_last) {
      return first <= reserved_last && reserved_first <= last
    }
    NF != 2 { exit 1 }
    $2 !~ /^[0-9]+$/ || sprintf("%d", $2 + 0) != $2 || $2 < 8 || $2 > 30 { exit 1 }
    {
      count = split($1, octets, ".")
      if (count != 4) exit 1
      for (octet_index = 1; octet_index <= 4; octet_index++) {
        if (octets[octet_index] !~ /^[0-9]+$/ ||
            sprintf("%d", octets[octet_index] + 0) != octets[octet_index] ||
            octets[octet_index] < 0 || octets[octet_index] > 255) exit 1
      }
      address = ((octets[1] * 256 + octets[2]) * 256 + octets[3]) * 256 + octets[4]
      block = 2 ^ (32 - $2)
      if (address % block != 0) exit 1
      last = address + block - 1
      if (overlaps(address, last, 0, 0) ||
          overlaps(address, last, 127 * 16777216, 127 * 16777216 + 16777215) ||
          overlaps(address, last, 169 * 16777216 + 254 * 65536, 169 * 16777216 + 254 * 65536 + 65535) ||
          overlaps(address, last, 224 * 16777216, 239 * 16777216 + 16777215)) exit 1
    }
  '
}

validate_release_env() {
  release_env=$1
  validate_env_schema "$release_env"
  release_version=$(read_setting "$release_env" LANEWAY_VERSION)
  printf '%s\n' "$release_version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || \
    die "installed release version is invalid"
  release_profile=$(read_setting "$release_env" LANEWAY_INSTALL_PROFILE)
  case "$release_profile" in quick|production) ;; *) die "LANEWAY_INSTALL_PROFILE must be quick or production" ;; esac
  for release_digest_key in LANEWAY_CONTROLLER_IMAGE_DIGEST LANEWAY_RELAY_IMAGE_DIGEST \
    LANEWAY_ADMIN_IMAGE_DIGEST LANEWAY_EXIT_NODE_IMAGE_DIGEST; do
    release_digest=$(read_setting "$release_env" "$release_digest_key")
    printf '%s\n' "$release_digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || \
      die "$release_digest_key is not an immutable digest"
    [ "$release_digest" != sha256:0000000000000000000000000000000000000000000000000000000000000000 ] || \
      die "$release_digest_key is a placeholder"
  done
  if release_connector_digest=$(optional_setting "$release_env" LANEWAY_CONNECTOR_IMAGE_DIGEST); then
    printf '%s\n' "$release_connector_digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || \
      die "LANEWAY_CONNECTOR_IMAGE_DIGEST is not an immutable digest"
    [ "$release_connector_digest" != sha256:0000000000000000000000000000000000000000000000000000000000000000 ] || \
      die "LANEWAY_CONNECTOR_IMAGE_DIGEST is a placeholder"
  fi
  release_bind=$(read_setting "$release_env" LANEWAY_BIND_ADDRESS)
  validate_ipv4 "$release_bind" || die "LANEWAY_BIND_ADDRESS must be a canonical IPv4 address"
  controller_port_setting "$release_env" >/dev/null
  port_setting "$release_env" LANEWAY_RELAY_QUIC_PORT >/dev/null
  port_setting "$release_env" LANEWAY_RELAY_TCP_PORT >/dev/null
  port_setting "$release_env" LANEWAY_EXIT_DIRECT_PORT >/dev/null
  release_network_id=$(read_setting "$release_env" LANEWAY_NETWORK_ID)
  release_controller_id=$(read_setting "$release_env" LANEWAY_CONTROLLER_SERVICE_ID)
  release_relay_id=$(read_setting "$release_env" LANEWAY_RELAY_SERVICE_ID)
  case "$release_network_id:$release_controller_id:$release_relay_id" in
    *:*:*:*|*[!0-9a-f:]*) die "network, controller, and relay IDs must be distinct 32-character lowercase hex values" ;;
  esac
  if [ "${#release_network_id}" -ne 32 ] || [ "${#release_controller_id}" -ne 32 ] || \
    [ "${#release_relay_id}" -ne 32 ] || [ "$release_network_id" = "$release_controller_id" ] || \
    [ "$release_network_id" = "$release_relay_id" ] || [ "$release_controller_id" = "$release_relay_id" ] || \
    [ "$release_network_id" = 00000000000000000000000000000000 ] || \
    [ "$release_controller_id" = 00000000000000000000000000000000 ] || \
    [ "$release_relay_id" = 00000000000000000000000000000000 ]; then
    die "network, controller, and relay IDs must be distinct nonzero 32-character lowercase hex values"
  fi
  read_setting "$release_env" LANEWAY_CONTROLLER_SERVER_NAME >/dev/null
  release_network_name=$(read_setting "$release_env" LANEWAY_NETWORK_NAME)
  if ! LC_ALL=C printf '%s\n' "$release_network_name" | LC_ALL=C awk \
    'length($0) < 1 || length($0) > 253 || $0 !~ /^[A-Za-z0-9._-]+$/ { exit 1 }'; then
    die "LANEWAY_NETWORK_NAME must be 1 through 253 bytes of letters, numbers, dot, underscore, or dash"
  fi
  release_pool=$(read_setting "$release_env" LANEWAY_IPV4_POOL)
  validate_ipv4_pool "$release_pool" || die "LANEWAY_IPV4_POOL must be a canonical routable IPv4 /8 through /30"
  read_setting "$release_env" LANEWAY_RELAY_PUBLIC_ENDPOINT >/dev/null
  release_recipient=$(read_setting "$release_env" LANEWAY_BACKUP_RECIPIENT)
  printf '%s\n' "$release_recipient" | grep -Eq '^age1[0-9a-z]{58}$' || \
    die "LANEWAY_BACKUP_RECIPIENT must be an age X25519 recipient"
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

reject_ambient_controls() {
  compose_override=$(env | sed -n 's/^\(COMPOSE_[A-Za-z0-9_]*\)=.*/\1/p' | sed -n '1p')
  [ -z "$compose_override" ] || \
    die "$compose_override is not allowed for control-plane lifecycle commands"
}

canonical_absolute_path() {
  candidate_path=$1
  case "$candidate_path" in /*) ;; *) return 1 ;; esac
  case "$candidate_path" in
    /|*/|*//*|*/./*|*/../*|*/.|*/..|*[!A-Za-z0-9_./-]*) return 1 ;;
  esac
}

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

validate_protected_executable() {
  protected_executable=$1
  [ -f "$protected_executable" ] && [ ! -L "$protected_executable" ] && \
    [ -x "$protected_executable" ] && \
    [ "$(stat -c '%u:%g:%h' "$protected_executable")" = 0:0:1 ] || return 1
  protected_directory=$(dirname "$protected_executable")
  protected_leaf=true
  while :; do
    [ -d "$protected_directory" ] && [ ! -L "$protected_directory" ] || return 1
    protected_attributes=$(stat -c '%a:%u:%g' "$protected_directory") || return 1
    protected_mode=${protected_attributes%%:*}
    protected_owner=${protected_attributes#*:}
    [ "$protected_owner" = 0:0 ] || return 1
    if [ $((0$protected_mode & 0022)) -ne 0 ]; then
      [ "$protected_leaf" = false ] && [ $((0$protected_mode & 01000)) -ne 0 ] || return 1
    fi
    [ "$protected_directory" != / ] || return 0
    protected_directory=$(dirname "$protected_directory") || return 1
    protected_leaf=false
  done
}

inspect_initial_network() {
  inspect_path=$1
  inspect_expected_network=$2
  inspect_expected_name=$3
  inspect_expected_pool=$4
  inspect_json=$("$laneway_command" config inspect-controller-initial-network -config "$inspect_path") || \
    die "controller configuration is invalid"
  printf '%s\n' "$inspect_json" | jq -e \
    --arg network_id "$inspect_expected_network" --arg name "$inspect_expected_name" --arg ipv4_pool "$inspect_expected_pool" '
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
  printf '%s' "$inspect_json"
}

validate_lock_marker() {
  marker_token=$1
  case "$marker_token" in
    .handoff.*)
      marker_suffix=${marker_token#.handoff.}
      case "$marker_suffix" in ''|*[!A-Za-z0-9]*) return 1 ;; esac
      ;;
    *) return 1 ;;
  esac
  marker_path=$lock_dir/$marker_token
  [ -d "$destination/generated/lifecycle" ] && [ ! -L "$destination/generated/lifecycle" ] && \
    [ "$(stat -c '%a:%u:%g' "$destination/generated/lifecycle")" = 700:0:0 ] && \
    [ -d "$lock_dir" ] && [ ! -L "$lock_dir" ] && \
    [ "$(stat -c '%a:%u:%g' "$lock_dir")" = 700:0:0 ] && \
    [ -f "$marker_path" ] && [ ! -L "$marker_path" ] && \
    [ "$(stat -c '%a:%u:%g:%h' "$marker_path")" = 600:0:0:1 ] && \
    [ "$(wc -l < "$marker_path")" -eq 3 ] && \
    [ "$(sed -n '1p' "$marker_path")" = version=1 ] && \
    [ "$(sed -n '2p' "$marker_path")" = "deployment=$destination" ] && \
    [ "$(sed -n '3p' "$marker_path")" = "token=$marker_token" ] || return 1
  lock_marker=$marker_path
}

adopt_or_acquire_lock() {
  lock_dir=$destination/generated/lifecycle/operator.lock
  token_present=false
  role_present=false
  [ "${LANEWAY_LIFECYCLE_LOCK_TOKEN+x}" != x ] || token_present=true
  [ "${LANEWAY_LIFECYCLE_LOCK_ROLE+x}" != x ] || role_present=true
  if [ "$token_present" = true ] || [ "$role_present" = true ]; then
    if [ "$token_present" != true ] || [ "$role_present" != true ] || \
      { [ "${LANEWAY_LIFECYCLE_LOCK_ROLE:-}" != owner ] && \
        [ "${LANEWAY_LIFECYCLE_LOCK_ROLE:-}" != observer ]; } || \
      ! validate_lock_marker "${LANEWAY_LIFECYCLE_LOCK_TOKEN:-}"; then
      die "lifecycle lock handoff is missing, malformed, or unauthorized"
    fi
    lock_token=$LANEWAY_LIFECYCLE_LOCK_TOKEN
    [ "$LANEWAY_LIFECYCLE_LOCK_ROLE" != owner ] || lock_owner=true
    return
  fi
  generated_dir=$destination/generated
  lifecycle_dir=$generated_dir/lifecycle
  [ -d "$generated_dir" ] && [ ! -L "$generated_dir" ] || \
    die "generated must be a real directory"
  if [ -e "$lifecycle_dir" ] || [ -L "$lifecycle_dir" ]; then
    [ -d "$lifecycle_dir" ] && [ ! -L "$lifecycle_dir" ] || \
      die "generated/lifecycle must be a real directory"
  else
    mkdir "$lifecycle_dir" 2>/dev/null || die "could not create lifecycle state directory"
    chmod 0700 "$lifecycle_dir" || die "could not protect lifecycle state directory"
    chown 0:0 "$lifecycle_dir" || die "could not own lifecycle state directory"
  fi
  [ -d "$generated_dir" ] && [ ! -L "$generated_dir" ] && \
    [ -d "$lifecycle_dir" ] && [ ! -L "$lifecycle_dir" ] || \
    die "generated lifecycle state changed during lock acquisition"
  mkdir "$lock_dir" 2>/dev/null || \
    die "another lifecycle operation is active (inspect generated/lifecycle/operator.lock if it is stale)"
  lock_owner=true
  chmod 0700 "$lock_dir" || die "could not protect lifecycle operation lock"
  lock_marker=$(mktemp "$lock_dir/.handoff.XXXXXX") || die "could not create lifecycle lock handoff marker"
  lock_token=${lock_marker##*/}
  chmod 0600 "$lock_marker"
  printf '%s\n' version=1 "deployment=$destination" "token=$lock_token" > "$lock_marker"
}

[ "$(id -u)" -eq 0 ] || die "run this command as root"
[ "${TAR_OPTIONS+x}" != x ] || die "TAR_OPTIONS is not allowed"
if [ "${LANEWAY_REPOSITORY+x}" = x ] || [ "${LANEWAY_RELEASE_BASE_URL+x}" = x ]; then
  die "public release source overrides are not allowed"
fi
if [ "${LANEWAY_COSIGN_BIN+x}" = x ] || [ "${LANEWAY_COMMAND+x}" = x ] || \
  [ "${LANEWAY_CONTROL_COMMAND+x}" = x ]; then
  die "public executable path overrides are not allowed"
fi
source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
destination=${LANEWAY_DEPLOY_DIR:-/opt/laneway}
canonical_absolute_path "$destination" || \
  die "LANEWAY_DEPLOY_DIR must be a canonical safe absolute path"
preflight_only=${LANEWAY_UPGRADE_PREFLIGHT_ONLY:-false}
case "$preflight_only" in true|false) ;; *) die "LANEWAY_UPGRADE_PREFLIGHT_ONLY must be true or false" ;; esac
if [ "$preflight_only" = true ] && [ "${LANEWAY_LIFECYCLE_LOCK_ROLE:-}" != observer ]; then
  die "verified-package preflight requires an observer lifecycle lock handoff"
fi
if [ "${LANEWAY_LIFECYCLE_LOCK_ROLE:-}" = observer ] && [ "$preflight_only" != true ]; then
  die "observer lifecycle lock handoff is valid only for verified-package preflight"
fi
if [ "$preflight_only" != true ] && [ "${LANEWAY_LIFECYCLE_LOCK_TOKEN+x}" = x ] && \
  [ "${LANEWAY_LIFECYCLE_LOCK_ROLE:-}" != owner ]; then
  die "mutating upgrade lock handoff requires the owner role"
fi
destination_physical=$(CDPATH='' cd -- "$destination" 2>/dev/null && pwd -P) || \
  die "deployment directory is missing or unsafe"
if [ "$destination_physical" != "$destination" ] || [ ! -d "$destination" ] || [ -L "$destination" ]; then
  die "LANEWAY_DEPLOY_DIR must identify its exact physical real directory"
fi
packaged_laneway=$source_dir/../../bin/laneway
if [ -f "$packaged_laneway" ] && [ ! -L "$packaged_laneway" ] && [ -x "$packaged_laneway" ]; then
  laneway_command=$packaged_laneway
else
  laneway_command=/usr/local/bin/laneway
fi
[ -f "$laneway_command" ] && [ ! -L "$laneway_command" ] && [ -x "$laneway_command" ] || \
  die "the protected Laneway command is missing or unsafe"

for command in awk chmod cp curl dirname docker env find grep install jq ln mkdir mktemp mv readlink sed sha256sum sleep stat wc; do
  command -v "$command" >/dev/null 2>&1 || die "required command is missing: $command"
done
if [ "${DOCKER_HOST+x}" = x ] || [ "${DOCKER_CONTEXT+x}" = x ] || [ "${DOCKER_TLS+x}" = x ] || \
  [ "${DOCKER_TLS_VERIFY+x}" = x ] || [ "${DOCKER_CERT_PATH+x}" = x ] || \
  [ "${DOCKER_CONFIG+x}" = x ]; then
  die "Docker target overrides are not allowed"
fi
trust_override=$(env | sed -n \
  -e 's/^\(COSIGN_[A-Za-z0-9_]*\)=.*/\1/p' \
  -e 's/^\(SIGSTORE_[A-Za-z0-9_]*\)=.*/\1/p' \
  -e 's/^\(TUF_[A-Za-z0-9_]*\)=.*/\1/p' | sed -n '1p')
[ -z "$trust_override" ] || die "$trust_override is not allowed for release verification"
if [ "${CURL_CA_BUNDLE+x}" = x ] || [ "${SSL_CERT_FILE+x}" = x ] || \
  [ "${SSL_CERT_DIR+x}" = x ]; then
  die "TLS trust path overrides are not allowed for release verification"
fi
unset DOCKER_DEFAULT_PLATFORM
configure_trusted_docker_client
reject_ambient_controls
if [ "${LANEWAY_LIFECYCLE_LOCK_TOKEN+x}" = x ] || [ "${LANEWAY_LIFECYCLE_LOCK_ROLE+x}" = x ]; then
  adopt_or_acquire_lock
fi

for path in "$destination/.env" "$destination/compose.yaml" \
  "$destination/generated/config/controller.toml" "$destination/generated/config/relay.toml" \
  "$source_dir/compose.yaml" "$source_dir/laneway-control"; do
  if [ ! -f "$path" ] || [ -L "$path" ]; then
    die "upgrade input is missing or unsafe: $path"
  fi
done
[ -d "$destination" ] && [ ! -L "$destination" ] || die "deployment directory is missing or unsafe"
[ -d "$destination/generated" ] && [ ! -L "$destination/generated" ] || \
  die "generated must be a real directory"
[ -d "$destination/generated/config" ] && [ ! -L "$destination/generated/config" ] || \
  die "generated/config must be a real directory"
if [ -e "$destination/generated/lifecycle" ] || [ -L "$destination/generated/lifecycle" ]; then
  [ -d "$destination/generated/lifecycle" ] && [ ! -L "$destination/generated/lifecycle" ] || \
    die "generated/lifecycle must be a real directory"
fi

validate_release_env "$destination/.env"
current_version=$(read_setting "$destination/.env" LANEWAY_VERSION)
network_id=$(read_setting "$destination/.env" LANEWAY_NETWORK_ID)
network_name=$(read_setting "$destination/.env" LANEWAY_NETWORK_NAME)
ipv4_pool=$(read_setting "$destination/.env" LANEWAY_IPV4_POOL)
controller_port=$(controller_port_setting "$destination/.env")
server_name=$(read_setting "$destination/.env" LANEWAY_CONTROLLER_SERVER_NAME)

existing_controller_config=$destination/generated/config/controller.toml
initial_network_json=$(inspect_initial_network "$existing_controller_config" "$network_id" "$network_name" "$ipv4_pool")
initial_network_configured=$(printf '%s\n' "$initial_network_json" | jq -r '.configured')
case "$initial_network_configured" in true|false) ;; *) die "controller initial-network inspection returned an invalid state" ;; esac
"$laneway_command" config validate -config "$destination/generated/config/relay.toml" >/dev/null || \
  die "existing relay configuration is invalid"

package_version=
[ -f "$source_dir/../../VERSION" ] && [ ! -L "$source_dir/../../VERSION" ] && \
  package_version=$(sed -n '1p' "$source_dir/../../VERSION")
printf '%s\n' "$package_version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || \
  die "control-plane upgrades require a packaged stable release"
if [ "$current_version" != "$package_version" ]; then
  awk -v candidate="$package_version" -v current="$current_version" 'BEGIN {
    split(candidate, c, "."); split(current, p, ".")
    for (i = 1; i <= 3; i++) {
      if ((c[i] + 0) > (p[i] + 0)) exit 0
      if ((c[i] + 0) < (p[i] + 0)) exit 1
    }
    exit 1
  }' || die "packaged release v$package_version would not upgrade installed v$current_version"
fi
tag=v$package_version
repository=Doout/laneway
authenticated_base_url=${LANEWAY_AUTHENTICATED_RELEASE_BASE_URL:-}
authenticated_cosign=${LANEWAY_AUTHENTICATED_COSIGN_BIN:-}
authenticated_digests=${LANEWAY_AUTHENTICATED_IMAGE_DIGESTS_FILE:-}
if [ -n "$authenticated_cosign" ]; then
  [ "${LANEWAY_LIFECYCLE_LOCK_TOKEN+x}" = x ] || \
    die "authenticated verifier requires a lifecycle lock handoff"
  case "${LANEWAY_LIFECYCLE_LOCK_ROLE:-}" in
    owner|observer) ;;
    *) die "authenticated verifier requires a lifecycle lock handoff" ;;
  esac
  case "$authenticated_cosign" in /*) ;; *) die "authenticated verifier path must be absolute" ;; esac
fi
if [ -n "$authenticated_base_url" ]; then
  [ "${LANEWAY_LIFECYCLE_LOCK_TOKEN+x}" = x ] || \
    die "authenticated release source requires a lifecycle lock handoff"
  case "${LANEWAY_LIFECYCLE_LOCK_ROLE:-}" in
    owner|observer) ;;
    *) die "authenticated release source requires a lifecycle lock handoff" ;;
  esac
  case "$authenticated_base_url" in
    https://*) ;;
    *) die "authenticated release source must use HTTPS" ;;
  esac
  base_url=${authenticated_base_url%/}
else
  base_url=https://github.com/$repository/releases/download/$tag
fi
if [ -n "$authenticated_digests" ]; then
  [ "${LANEWAY_LIFECYCLE_LOCK_TOKEN+x}" = x ] || \
    die "authenticated image digest manifest requires a lifecycle lock handoff"
  case "${LANEWAY_LIFECYCLE_LOCK_ROLE:-}" in
    owner|observer) ;;
    *) die "authenticated image digest manifest requires a lifecycle lock handoff" ;;
  esac
  case "$authenticated_digests" in /*) ;; *) die "authenticated image digest manifest path must be absolute" ;; esac
  [ -f "$authenticated_digests" ] && [ ! -L "$authenticated_digests" ] && \
    [ "$(stat -c '%a:%u:%g:%h' "$authenticated_digests")" = 600:0:0:1 ] || \
    die "authenticated image digest manifest must be a protected root-owned regular file"
fi
if { [ -n "$authenticated_base_url" ] || [ -n "$authenticated_cosign" ] || \
  [ -n "$authenticated_digests" ]; } && \
  ! validate_lock_marker "${LANEWAY_LIFECYCLE_LOCK_TOKEN:-}"; then
  die "authenticated release inputs require a validated lifecycle lock handoff"
fi

legacy=$destination/generated/lifecycle/lane-before-$package_version
if [ -e "$destination/lane" ] || [ -L "$destination/lane" ]; then
  if [ -L "$destination/lane" ]; then
    [ "$(readlink "$destination/lane")" = laneway-control ] || die "unexpected compatibility link: $destination/lane"
  elif [ -f "$destination/lane" ]; then
    [ ! -e "$legacy" ] && [ ! -L "$legacy" ] || die "legacy wrapper backup already exists: $legacy"
  else
    die "refusing to replace unsafe compatibility path: $destination/lane"
  fi
fi
system_command=/usr/local/sbin/laneway-control
if [ -e "$system_command" ] || [ -L "$system_command" ]; then
  [ -L "$system_command" ] || die "refusing to replace non-symlink command: $system_command"
  target=$(readlink "$system_command")
  case "$target" in "$destination/laneway-control"|"$destination/lane") ;; *) die "unexpected command link target: $target" ;; esac
else
  system_parent=$(dirname "$system_command")
  [ -d "$system_parent" ] && [ ! -L "$system_parent" ] || die "system command directory is missing or unsafe: $system_parent"
fi

artifacts_file=${LANEWAY_BOOTSTRAP_ARTIFACTS_FILE:-}
if [ -n "$artifacts_file" ]; then
  [ -f "$artifacts_file" ] && [ ! -L "$artifacts_file" ] || die "signed bootstrap artifact manifest is missing or unsafe"
  [ "$(grep -c '^\[\[bootstrap\.artifacts\]\]$' "$artifacts_file")" -eq 4 ] || \
    die "signed bootstrap artifact manifest must contain four platform artifacts"
fi

[ "$lock_owner" = true ] || adopt_or_acquire_lock
compose_environment docker --context default compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"
compose_environment docker --context default compose --project-name laneway --project-directory "$destination" \
  --env-file "$destination/.env" -f "$destination/compose.yaml" config --quiet || \
  die "existing Docker Compose configuration is invalid"
compose_environment docker --context default compose --project-name laneway --project-directory "$destination" \
  --env-file "$destination/.env" -f "$source_dir/compose.yaml" config --quiet || \
  die "packaged Docker Compose configuration is invalid"

if [ "$current_version" = "$package_version" ]; then
  echo "Laneway control plane is already on $tag."
  exit 0
fi

temporary_parent=/var/tmp
if [ ! -d "$temporary_parent" ] || [ -L "$temporary_parent" ] || \
  [ "$(stat -c '%a:%u:%g' "$temporary_parent")" != 1777:0:0 ]; then
  die "/var/tmp must be a root-owned real directory with mode 1777"
fi
work_dir=$(mktemp -d "$temporary_parent/laneway-control-upgrade.XXXXXX")
artifacts_file=${LANEWAY_BOOTSTRAP_ARTIFACTS_FILE:-}
if [ -z "$artifacts_file" ] || [ ! -f "$artifacts_file" ] || [ -L "$artifacts_file" ]; then
  # Compatibility path for an older laneway-control updater. It has already
  # installed this verified package, but cannot pass the manifest introduced
  # with it, so independently authenticate the release metadata here.
  artifacts_file=$work_dir/bootstrap-artifacts.toml
  curl --disable --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
    "$base_url/bootstrap-artifacts.toml" -o "$artifacts_file" || \
    die "could not download the bootstrap artifact manifest"
  curl --disable --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
    "$base_url/checksums.txt" -o "$work_dir/checksums.txt" || \
    die "could not download release checksums"
  curl --disable --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
    "$base_url/checksums.sigstore.json" -o "$work_dir/checksums.sigstore.json" || \
    die "could not download the release signature bundle"
  cosign_command=${LANEWAY_AUTHENTICATED_COSIGN_BIN:-/usr/local/libexec/laneway/cosign-v3.1.3}
  validate_protected_executable "$cosign_command" || die "the protected Cosign verifier is missing or unsafe"
  cosign_version=$("$cosign_command" version --json 2>/dev/null | \
    sed -n 's/.*"gitVersion":[[:space:]]*"\([^"]*\)".*/\1/p' | sed -n '1p')
  [ "$cosign_version" = v3.1.3 ] || die "the protected Cosign verifier has an unexpected version"
  "$cosign_command" verify-blob --bundle "$work_dir/checksums.sigstore.json" \
    --certificate-identity "https://github.com/$repository/.github/workflows/release.yml@refs/tags/$tag" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$work_dir/checksums.txt" >/dev/null 2>&1 || die "release checksum signature verification failed"
  (
    cd "$work_dir"
    grep '  bootstrap-artifacts.toml$' checksums.txt > bootstrap-artifacts-checksum.txt
    [ "$(wc -l < bootstrap-artifacts-checksum.txt)" -eq 1 ]
    sha256sum -c bootstrap-artifacts-checksum.txt >/dev/null
  ) || die "bootstrap artifact manifest checksum verification failed"
fi
if [ "$(grep -c '^\[\[bootstrap\.artifacts\]\]$' "$artifacts_file")" -ne 4 ]; then
  die "signed bootstrap artifact manifest must contain four platform artifacts"
fi
curl --disable --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
  "$base_url/checksums.txt" -o "$work_dir/checksums.txt" || die "could not download release checksums"
curl --disable --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
  "$base_url/checksums.sigstore.json" -o "$work_dir/checksums.sigstore.json" || \
  die "could not download the release signature bundle"
cosign_command=${LANEWAY_AUTHENTICATED_COSIGN_BIN:-/usr/local/libexec/laneway/cosign-v3.1.3}
validate_protected_executable "$cosign_command" || die "the protected Cosign verifier is missing or unsafe"
cosign_version=$("$cosign_command" version --json 2>/dev/null | \
  sed -n 's/.*"gitVersion":[[:space:]]*"\([^"]*\)".*/\1/p' | sed -n '1p')
[ "$cosign_version" = v3.1.3 ] || die "the protected Cosign verifier has an unexpected version"
"$cosign_command" verify-blob --bundle "$work_dir/checksums.sigstore.json" \
  --certificate-identity "https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$work_dir/checksums.txt" >/dev/null 2>&1 || die "release checksum signature verification failed"
if [ -n "$authenticated_digests" ]; then
  install -m 0600 "$authenticated_digests" "$work_dir/image-digests.txt" || \
    die "could not snapshot authenticated image digest metadata"
else
  curl --disable --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
    "$base_url/image-digests.txt" -o "$work_dir/image-digests.txt" || \
    die "could not download image digest metadata"
fi
(
  cd "$work_dir"
  grep '  image-digests\.txt$' checksums.txt > image-digests-checksum.txt
  [ "$(wc -l < image-digests-checksum.txt)" -eq 1 ]
  sha256sum -c image-digests-checksum.txt >/dev/null
) || die "image digest manifest checksum verification failed"

image_digest() {
  image=$1
  matches=$(sed -n "s|^${image}@\(sha256:[0-9a-f]\{64\}\)$|\1|p" "$work_dir/image-digests.txt")
  [ "$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l)" -eq 1 ] || \
    die "release metadata has no unique digest for $image"
  printf '%s' "$matches"
}

controller_digest=$(image_digest ghcr.io/doout/laneway-controller)
relay_digest=$(image_digest ghcr.io/doout/laneway-relay)
admin_digest=$(image_digest ghcr.io/doout/laneway-admin)
connector_digest=$(image_digest ghcr.io/doout/lane-edge)
exit_digest=$(image_digest ghcr.io/doout/laneway-exit-node)

awk -v version="$package_version" -v controller="$controller_digest" -v relay="$relay_digest" \
  -v admin="$admin_digest" -v connector="$connector_digest" -v exit_node="$exit_digest" '
  BEGIN {
    replacement["LANEWAY_VERSION"] = version
    replacement["LANEWAY_CONTROLLER_IMAGE_DIGEST"] = controller
    replacement["LANEWAY_RELAY_IMAGE_DIGEST"] = relay
    replacement["LANEWAY_ADMIN_IMAGE_DIGEST"] = admin
    replacement["LANEWAY_CONNECTOR_IMAGE_DIGEST"] = connector
    replacement["LANEWAY_EXIT_NODE_IMAGE_DIGEST"] = exit_node
  }
  {
    key = $0
    sub(/=.*/, "", key)
    if (key in replacement) {
      print key "=" replacement[key]
      seen[key]++
    } else {
      print
    }
  }
  END {
    for (key in replacement) {
      if (key == "LANEWAY_CONNECTOR_IMAGE_DIGEST" && seen[key] == 0) {
        print key "=" replacement[key]
        seen[key] = 1
      }
      if (seen[key] != 1) exit 1
    }
  }
' "$destination/.env" > "$work_dir/candidate.env" || die "existing release environment is incomplete"
validate_release_env "$work_dir/candidate.env"
compose_environment docker --context default compose --project-name laneway --project-directory "$destination" \
  --env-file "$work_dir/candidate.env" -f "$source_dir/compose.yaml" config --quiet || \
  die "candidate Docker Compose configuration is invalid"

cp "$destination/generated/config/controller.toml" "$work_dir/controller.toml.previous"
cp "$destination/generated/config/relay.toml" "$work_dir/relay.toml.previous"
cp "$work_dir/controller.toml.previous" "$work_dir/controller.toml"
# Release artifacts are versioned update metadata. Remove the old array blocks
# before installing the signed manifest for this release.
awk '
  /^\[\[bootstrap\.artifacts\]\]$/ { dropping=1; next }
  /^\[/ && dropping { dropping=0 }
  !dropping { print }
' "$work_dir/controller.toml" > "$work_dir/controller.without-artifacts.toml"
mv "$work_dir/controller.without-artifacts.toml" "$work_dir/controller.toml"
if ! grep -Eq '^[[:space:]]*\[bootstrap\][[:space:]]*(#.*)?$' "$work_dir/controller.toml"; then
  printf '\n[bootstrap]\nnetwork_id = "%s"\ncontroller_endpoint = "https://%s:%s"\ncontroller_quic_endpoint = "%s:%s"\ncontroller_server_name = "%s"\n' \
    "$network_id" "$server_name" "$controller_port" "$server_name" "$controller_port" "$server_name" >> "$work_dir/controller.toml"
fi
if [ "$initial_network_configured" = false ]; then
  printf '\n[controller.initial_network]\nnetwork_id = "%s"\nname = "%s"\nipv4_pool = "%s"\n' \
    "$network_id" "$network_name" "$ipv4_pool" >> "$work_dir/controller.toml"
fi
cat "$artifacts_file" >> "$work_dir/controller.toml"
candidate_initial_network=$(inspect_initial_network "$work_dir/controller.toml" "$network_id" "$network_name" "$ipv4_pool")
[ "$(printf '%s\n' "$candidate_initial_network" | jq -r '.configured')" = true ] || \
  die "candidate controller configuration omitted the initial network"
cp "$work_dir/relay.toml.previous" "$work_dir/relay.toml"
if ! grep -Eq '^\[public_https\][[:space:]]*$' "$work_dir/relay.toml"; then
  printf '\n[public_https]\nserver_name = "%s"\ncache_dir = "/var/lib/laneway-public"\n' "$server_name" >> "$work_dir/relay.toml"
fi
"$laneway_command" config validate -config "$work_dir/relay.toml" >/dev/null || \
  die "candidate relay configuration is invalid"
migration_dir=$work_dir/migration
install -d -m 0700 "$migration_dir"
install -m 0644 "$source_dir/compose.yaml" "$migration_dir/compose.yaml"
install -m 0444 "$work_dir/controller.toml" "$migration_dir/controller.toml"
install -m 0444 "$work_dir/relay.toml" "$migration_dir/relay.toml"

if [ "$preflight_only" = true ]; then
  echo "Verified control-plane update package passed local and rendered configuration preflight."
  exit 0
fi

# All local, semantic, link, and rendered-Compose invariants have passed. Only
# now publish candidate/tooling state into the installed deployment.
install -d -m 0700 -o 0 -g 0 "$destination/generated/lifecycle"
candidate=$destination/generated/lifecycle/upgrade-$package_version.env
install -m 0600 -o 0 -g 0 "$work_dir/candidate.env" "$candidate"
install -m 0755 -o 0 -g 0 "$source_dir/laneway-control" "$destination/.laneway-control.new"
mv "$destination/.laneway-control.new" "$destination/laneway-control"

if [ -e "$destination/lane" ] || [ -L "$destination/lane" ]; then
  if [ -L "$destination/lane" ]; then
    : # Its exact target was verified before remote work.
  else
    mv "$destination/lane" "$legacy"
    ln -s laneway-control "$destination/lane"
  fi
else
  ln -s laneway-control "$destination/lane"
fi
if [ ! -e "$system_command" ] && [ ! -L "$system_command" ]; then
  ln -s "$destination/laneway-control" "$system_command"
fi

printf '\nApplying Laneway control-plane release\n'
printf '  Version: v%s -> %s\n' "$current_version" "$tag"
printf '  Network identity, PKI, state, ports, firewall, and host networking remain unchanged.\n\n'
if ! (cd "$destination" && env -u DOCKER_CONFIG -u ENV -u BASH_ENV -u CDPATH -u IFS \
  -u LANEWAY_AUTHENTICATED_RELEASE_BASE_URL \
  -u LANEWAY_AUTHENTICATED_IMAGE_DIGESTS_FILE \
  -u LANEWAY_AUTHENTICATED_COSIGN_BIN \
  HOME=/root LANEWAY_LIFECYCLE_LOCK_TOKEN="$lock_token" \
  LANEWAY_LIFECYCLE_LOCK_ROLE=borrower ./laneway-control upgrade "$candidate" "$migration_dir"); then
  die "upgrade failed; restoring the previous deployment files and containers"
fi
public_ready=false
attempt=0
while [ "$attempt" -lt 30 ]; do
  if curl --disable --fail --silent --show-error --proto '=https' --proto-redir '=https' \
    --max-time 10 --tlsv1.3 \
    "https://$server_name/.well-known/laneway/bootstrap.json" > "$work_dir/bootstrap.json" 2>/dev/null &&
    grep -F "\"network_id\":\"$network_id\"" "$work_dir/bootstrap.json" >/dev/null &&
    grep -F "releases/download/$tag/laneway_" "$work_dir/bootstrap.json" >/dev/null; then
    public_ready=true
    break
  fi
  attempt=$((attempt + 1))
  sleep 2
done
if [ "$public_ready" != true ]; then
  (cd "$destination" && env -u DOCKER_CONFIG -u ENV -u BASH_ENV -u CDPATH -u IFS \
    -u LANEWAY_AUTHENTICATED_RELEASE_BASE_URL \
    -u LANEWAY_AUTHENTICATED_IMAGE_DIGESTS_FILE \
    -u LANEWAY_AUTHENTICATED_COSIGN_BIN \
    HOME=/root LANEWAY_LIFECYCLE_LOCK_TOKEN="$lock_token" \
    LANEWAY_LIFECYCLE_LOCK_ROLE=borrower ./laneway-control rollback) || \
    die "public HTTPS bootstrap failed and automatic rollback also failed"
  die "public HTTPS bootstrap did not become ready; the previous deployment was restored"
fi
for name in compose.yaml validate.sh preflight.sh recovery.sh bootstrap.sh README.md; do
  [ ! -f "$source_dir/$name" ] || case "$name" in
    *.sh) install -m 0755 -o 0 -g 0 "$source_dir/$name" "$destination/$name" ;;
    *) install -m 0644 -o 0 -g 0 "$source_dir/$name" "$destination/$name" ;;
  esac
done
printf '\nLaneway control plane is now on %s\n' "$tag"
printf '  Public HTTPS: automatic certificate management on TCP 443\n'
printf '  Verify:       sudo laneway-control status\n'
