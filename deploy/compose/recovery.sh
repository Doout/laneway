#!/bin/sh
set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$(printf ' \t\n_'); IFS=${IFS%_}
export PATH
unset ENV BASH_ENV CDPATH

base_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
env_file=$base_dir/.env
backup_dir=$base_dir/generated/backups
recovery_dir=$base_dir/generated/recovery
work=
published=
database_snapshot=
umask 077

case "$base_dir" in *[!A-Za-z0-9_./-]*) echo "Laneway recovery: deployment directory contains an unsafe character" >&2; exit 1 ;; esac

cleanup_database_snapshot() {
  if [ -n "$database_snapshot" ]; then
    # SQLite can create these beside both online backup and restore databases.
    # The controller-writable staging directory must not retain plaintext state
    # after the encrypted bundle is published or an operation fails.
    for suffix in '' -wal -shm -journal; do
      path=$database_snapshot$suffix
      if [ -e "$path" ] || [ -L "$path" ]; then
        find "$path" -maxdepth 0 -delete
      fi
    done
    database_snapshot=
  fi
  # Controllers predating the owner-level cleanup used an independent random
  # temporary name. Remove only that reserved internal namespace so upgrading
  # from an affected release cannot strand its plaintext SQLite sidecars.
  if [ -d "$backup_dir" ] && [ ! -L "$backup_dir" ]; then
    find "$backup_dir" -mindepth 1 -maxdepth 1 \
      \( -type f -o -type l \) -name '.laneway-database-*' -delete
  fi
}

cleanup() {
  if [ -n "$published" ]; then
    for path in $published; do
      [ ! -e "$path" ] || find "$path" -maxdepth 0 -delete
    done
  fi
  cleanup_database_snapshot
  [ -z "$work" ] || [ ! -e "$work" ] || find "$work" -depth -delete
  return 0
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

die() { echo "lane recovery: $*" >&2; exit 1; }

[ "${TAR_OPTIONS+x}" != x ] || die "TAR_OPTIONS is not allowed"
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

compose_with_env() {
  compose_env_file=$1
  shift
  compose_environment docker --context default compose --project-name laneway --project-directory "$base_dir" \
    --env-file "$compose_env_file" -f "$base_dir/compose.yaml" "$@"
}

compose() {
  compose_with_env "$env_file" "$@"
}

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
  ' "$schema_file" || die ".env must contain only canonical, managed KEY=value assignments, comments, or blank lines"
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

port_setting_from() {
  setting_file=$1
  setting_key=$2
  port_value=$(read_setting_from "$setting_file" "$setting_key")
  case "$port_value" in *[!0-9]*) die "$setting_key must be a port from 1 through 65535" ;; esac
  [ "$port_value" -ge 1 ] && [ "$port_value" -le 65535 ] || die "$setting_key must be a port from 1 through 65535"
}

controller_port_setting_from() {
  setting_file=$1
  port_value=$(optional_setting_from "$setting_file" LANEWAY_CONTROLLER_PORT)
  [ -n "$port_value" ] || port_value=8443
  case "$port_value" in *[!0-9]*) die "LANEWAY_CONTROLLER_PORT must be a port from 1 through 65535" ;; esac
  [ "$port_value" -ge 1 ] && [ "$port_value" -le 65535 ] || die "LANEWAY_CONTROLLER_PORT must be a port from 1 through 65535"
}

validate_managed_env() {
  managed_file=$1
  if [ ! -f "$managed_file" ] || [ -L "$managed_file" ]; then die ".env must be a regular, non-symlink file"; fi
  validate_env_schema "$managed_file"
  version=$(read_setting_from "$managed_file" LANEWAY_VERSION)
  printf '%s\n' "$version" | grep -Eq '^(dev|[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?)$' || \
    die "LANEWAY_VERSION must be dev or a pinned semantic release"
  install_profile=$(read_setting_from "$managed_file" LANEWAY_INSTALL_PROFILE)
  case "$install_profile" in quick|production) ;; *) die "LANEWAY_INSTALL_PROFILE must be quick or production" ;; esac
  for digest_key in LANEWAY_CONTROLLER_IMAGE_DIGEST LANEWAY_RELAY_IMAGE_DIGEST \
    LANEWAY_ADMIN_IMAGE_DIGEST LANEWAY_EXIT_NODE_IMAGE_DIGEST; do
    digest=$(read_setting_from "$managed_file" "$digest_key")
    printf '%s\n' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || \
      die "$digest_key must be an immutable sha256 image manifest digest"
    if [ "$version" != dev ] && [ "$digest" = sha256:0000000000000000000000000000000000000000000000000000000000000000 ]; then
      die "$digest_key must use the release digest, not the development placeholder"
    fi
  done
  connector_digest=$(optional_setting_from "$managed_file" LANEWAY_CONNECTOR_IMAGE_DIGEST)
  if [ -n "$connector_digest" ]; then
    printf '%s\n' "$connector_digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || \
      die "LANEWAY_CONNECTOR_IMAGE_DIGEST must be an immutable sha256 image manifest digest"
    if [ "$version" != dev ] && [ "$connector_digest" = sha256:0000000000000000000000000000000000000000000000000000000000000000 ]; then
      die "LANEWAY_CONNECTOR_IMAGE_DIGEST must use the release digest, not the development placeholder"
    fi
  fi
  read_setting_from "$managed_file" LANEWAY_BIND_ADDRESS >/dev/null
  controller_port_setting_from "$managed_file"
  port_setting_from "$managed_file" LANEWAY_RELAY_QUIC_PORT
  port_setting_from "$managed_file" LANEWAY_RELAY_TCP_PORT
  port_setting_from "$managed_file" LANEWAY_EXIT_DIRECT_PORT
  read_setting_from "$managed_file" LANEWAY_CONTROLLER_SERVER_NAME >/dev/null
  network_id=$(read_setting_from "$managed_file" LANEWAY_NETWORK_ID)
  controller_id=$(read_setting_from "$managed_file" LANEWAY_CONTROLLER_SERVICE_ID)
  relay_id=$(read_setting_from "$managed_file" LANEWAY_RELAY_SERVICE_ID)
  case "$network_id:$controller_id:$relay_id" in
    *:*:*:*|*[!0-9a-f:]*) die "network, controller, and relay IDs must be distinct 32-character lowercase hex values" ;;
  esac
  if [ "${#network_id}" -ne 32 ] || [ "${#controller_id}" -ne 32 ] || \
    [ "${#relay_id}" -ne 32 ] || [ "$network_id" = "$controller_id" ] || \
    [ "$network_id" = "$relay_id" ] || [ "$controller_id" = "$relay_id" ]; then
    die "network, controller, and relay IDs must be distinct 32-character lowercase hex values"
  fi
  for managed_key in LANEWAY_NETWORK_NAME LANEWAY_IPV4_POOL LANEWAY_RELAY_PUBLIC_ENDPOINT; do
    read_setting_from "$managed_file" "$managed_key" >/dev/null
  done
  recipient=$(read_setting_from "$managed_file" LANEWAY_BACKUP_RECIPIENT)
  printf '%s\n' "$recipient" | grep -Eq '^age1[0-9a-z]{58}$' || \
    die "LANEWAY_BACKUP_RECIPIENT must be an age X25519 recipient"
}

validate_initial_network() {
  managed_file=$1
  controller_config=$2
  expected_network_id=$(read_setting_from "$managed_file" LANEWAY_NETWORK_ID)
  expected_name=$(read_setting_from "$managed_file" LANEWAY_NETWORK_NAME)
  expected_pool=$(read_setting_from "$managed_file" LANEWAY_IPV4_POOL)
  inspected=$(laneway config inspect-controller-initial-network -config "$controller_config") || \
    die "controller configuration is invalid"
  printf '%s\n' "$inspected" | jq -e \
    --arg network_id "$expected_network_id" --arg name "$expected_name" --arg ipv4_pool "$expected_pool" '
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
}
validate_name() {
  case "$1" in ''|.*|*/*|*[!A-Za-z0-9._-]*|*.age.*) die "bundle name must be a simple NAME.age" ;; esac
  case "$1" in *.age) ;; *) die "bundle name must end in .age" ;; esac
}
require_regular() {
  if [ ! -f "$1" ] || [ -L "$1" ]; then
    die "required regular file is missing or unsafe: $1"
  fi
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

[ "$(id -u)" -eq 0 ] || die "run as root to read and restore fixed-UID secrets safely"
for command in age awk chown docker env find grep install jq laneway sed sha256sum sort stat sync tar; do
  command -v "$command" >/dev/null 2>&1 || die "required command is missing: $command"
done
configure_trusted_docker_client

case "${1:-}" in
  backup)
    [ "$#" -eq 2 ] || die "usage: recovery.sh backup NAME.age"
    name=$2; validate_name "$name"
    require_regular "$env_file"
    validate_managed_env "$env_file"
    recipient=$(read_setting LANEWAY_BACKUP_RECIPIENT)
    printf '%s\n' "$recipient" | grep -Eq '^age1[0-9a-z]{58}$' || die "LANEWAY_BACKUP_RECIPIENT must be an age X25519 recipient"
    if [ -e "$recovery_dir/$name" ] || [ -L "$recovery_dir/$name" ]; then
      die "recovery bundle already exists: $name"
    fi
    env -u DOCKER_CONFIG -u ENV -u BASH_ENV -u CDPATH -u IFS HOME=/root "$base_dir/validate.sh"
    install -d -m 0700 "$backup_dir"
    chown 65532:65532 "$backup_dir"
    if [ -e "$recovery_dir" ] || [ -L "$recovery_dir" ]; then
      if [ ! -d "$recovery_dir" ] || [ -L "$recovery_dir" ]; then
        die "generated/recovery must be a real directory"
      fi
    fi
    install -d -m 0700 -o 0 -g 0 "$recovery_dir"
    work=$(mktemp -d "$base_dir/generated/.recovery-backup.XXXXXX")
    install -d -m 0700 "$work/database" "$work/generated/config" "$work/generated/pki" "$work/generated/secrets"
    database_name=.lane-recovery-$PPID-$$.db
    database_snapshot=$backup_dir/$database_name
    compose run --rm --no-deps controller -config /etc/laneway/controller.toml -backup "/backups/$database_name"
    require_regular "$database_snapshot"
    install -m 0600 "$database_snapshot" "$work/database/controller.db"
    cleanup_database_snapshot

    files="
generated/config/controller.toml
generated/config/relay.toml
generated/pki/ca.crt
generated/pki/intermediate-chain.crt
generated/pki/intermediate.key
generated/pki/controller.crt
generated/pki/controller.key
generated/pki/relay.crt
generated/pki/relay.key
generated/secrets/admin.token"
    install -m 0600 "$env_file" "$work/.env"
    for relative in $files; do
      require_regular "$base_dir/$relative"
      install -D -m 0600 "$base_dir/$relative" "$work/$relative"
    done
    exit_files="generated/config/exit-node.toml generated/pki/exit-node.crt generated/pki/exit-node.key"
    exit_count=0
    for relative in $exit_files; do [ ! -e "$base_dir/$relative" ] || exit_count=$((exit_count + 1)); done
    [ "$exit_count" -eq 0 ] || [ "$exit_count" -eq 3 ] || die "optional Exit Node recovery material is partial"
    if [ "$exit_count" -eq 3 ]; then
      for relative in $exit_files; do
        require_regular "$base_dir/$relative"
        install -D -m 0600 "$base_dir/$relative" "$work/$relative"
        files="$files
$relative"
      done
    fi
    printf '%s\n' 'LANEWAY_RECOVERY_VERSION=1' > "$work/FORMAT"
    (
      cd "$work"
      # Every value in files is an internally fixed, whitespace-free relative path.
      # shellcheck disable=SC2086
      sha256sum FORMAT .env database/controller.db $files > MANIFEST.sha256
      # shellcheck disable=SC2086
      tar -cf recovery.tar FORMAT MANIFEST.sha256 .env database/controller.db $files
    )
    age --encrypt -r "$recipient" -o "$work/$name" "$work/recovery.tar"
    chmod 0600 "$work/$name"; chown 0:0 "$work/$name"
    ln "$work/$name" "$recovery_dir/$name"
    published="$recovery_dir/$name"
    sync -f "$recovery_dir/$name"
    sync -f "$recovery_dir"
    published=
    echo "laneway-control: encrypted recovery bundle: generated/recovery/$name"
    ;;
  restore)
    [ "$#" -eq 3 ] || die "usage: recovery.sh restore BUNDLE.age IDENTITY"
    bundle=$2; identity=$3
    require_regular "$bundle"; require_regular "$identity"
    case "$(basename "$bundle")" in *.age) ;; *) die "recovery bundle must end in .age" ;; esac
    work=$(mktemp -d "$base_dir/.recovery-restore.XXXXXX")
    age --decrypt -i "$identity" -o "$work/recovery.tar" "$bundle"
    LC_ALL=C tar -tvf "$work/recovery.tar" > "$work/list.verbose"
    if grep -Ev '^-rw------- |^-r-------- |^-rw-r--r-- |^-r--r--r-- ' "$work/list.verbose" >/dev/null; then
      die "recovery archive contains a non-regular entry"
    fi
    tar -tf "$work/recovery.tar" | LC_ALL=C sort > "$work/list"
    if uniq -d "$work/list" | grep . >/dev/null; then die "recovery archive contains duplicate entries"; fi
    allowed='FORMAT
MANIFEST.sha256
.env
database/controller.db
generated/config/controller.toml
generated/config/relay.toml
generated/config/exit-node.toml
generated/pki/ca.crt
generated/pki/intermediate-chain.crt
generated/pki/intermediate.key
generated/pki/controller.crt
generated/pki/controller.key
generated/pki/relay.crt
generated/pki/relay.key
generated/pki/exit-node.crt
generated/pki/exit-node.key
generated/secrets/admin.token'
    while IFS= read -r entry; do
      printf '%s\n' "$allowed" | grep -Fx "$entry" >/dev/null || die "unexpected recovery archive entry: $entry"
    done < "$work/list"
    for entry in FORMAT MANIFEST.sha256 .env database/controller.db \
      generated/config/controller.toml generated/config/relay.toml \
      generated/pki/ca.crt generated/pki/intermediate-chain.crt generated/pki/intermediate.key \
      generated/pki/controller.crt generated/pki/controller.key generated/pki/relay.crt \
      generated/pki/relay.key generated/secrets/admin.token; do
      grep -Fx "$entry" "$work/list" >/dev/null || die "recovery archive is missing: $entry"
    done
    exit_count=$(grep -Ec '^(generated/config/exit-node.toml|generated/pki/exit-node.crt|generated/pki/exit-node.key)$' "$work/list" || true)
    [ "$exit_count" -eq 0 ] || [ "$exit_count" -eq 3 ] || die "recovery archive has partial Exit Node material"
    install -d -m 0700 "$work/extracted/database" "$work/extracted/generated/config" \
      "$work/extracted/generated/pki" "$work/extracted/generated/secrets"
    tar --extract --file "$work/recovery.tar" --directory "$work/extracted" \
      --no-same-owner --no-same-permissions --keep-old-files
    [ "$(cat "$work/extracted/FORMAT")" = LANEWAY_RECOVERY_VERSION=1 ] || die "unsupported recovery bundle format"
    (cd "$work/extracted" && sha256sum --check --strict MANIFEST.sha256 >/dev/null) || die "recovery bundle integrity check failed"
    while IFS= read -r entry; do require_regular "$work/extracted/$entry"; done < "$work/list"
    validate_managed_env "$work/extracted/.env"
    validate_initial_network "$work/extracted/.env" "$work/extracted/generated/config/controller.toml"

    targets=".env
generated/config/controller.toml
generated/config/relay.toml
generated/pki/ca.crt
generated/pki/intermediate-chain.crt
generated/pki/intermediate.key
generated/pki/controller.crt
generated/pki/controller.key
generated/pki/relay.crt
generated/pki/relay.key
generated/secrets/admin.token"
    [ "$exit_count" -eq 0 ] || targets="$targets
generated/config/exit-node.toml
generated/pki/exit-node.crt
generated/pki/exit-node.key"
    for relative in $targets; do
      if [ -e "$base_dir/$relative" ] || [ -L "$base_dir/$relative" ]; then
        die "refusing to overwrite existing deployment state: $relative"
      fi
    done
    for directory in generated generated/config generated/pki generated/secrets generated/backups; do
      if [ -e "$base_dir/$directory" ] || [ -L "$base_dir/$directory" ]; then
        if [ ! -d "$base_dir/$directory" ] || [ -L "$base_dir/$directory" ]; then
          die "restore target is not a real directory: $directory"
        fi
      fi
    done
    compose_with_env "$work/extracted/.env" config --quiet
    install -d -m 0700 "$base_dir/generated" "$base_dir/generated/config" "$base_dir/generated/pki" "$base_dir/generated/secrets"
    install -d -m 0700 "$backup_dir"
    chown 65532:65532 "$backup_dir"
    for relative in $targets; do
      case "$relative" in
        *.key|*.token) mode=0400; owner=65532:65532 ;;
        .env) mode=0600; owner=0:0 ;;
        *) mode=0444; owner=0:0 ;;
      esac
      chmod "$mode" "$work/extracted/$relative"
      chown "$owner" "$work/extracted/$relative"
      ln "$work/extracted/$relative" "$base_dir/$relative"
      published="$published $base_dir/$relative"
    done
    if [ -n "$(compose ps --status running -q controller)" ]; then die "restore requires a stopped controller"; fi
    env -u DOCKER_CONFIG -u ENV -u BASH_ENV -u CDPATH -u IFS HOME=/root "$base_dir/validate.sh"
    restore_db=$backup_dir/.lane-restore-$PPID-$$.db
    install -m 0600 "$work/extracted/database/controller.db" "$restore_db"
    chown 65532:65532 "$restore_db"
    database_snapshot=$restore_db
    compose run --rm --no-deps controller -config /etc/laneway/controller.toml -restore "/backups/$(basename "$restore_db")"
    published=
    cleanup_database_snapshot
    echo "laneway-control: recovery bundle restored; run laneway-control init to verify signed images and start the stack"
    ;;
  *) die "usage: recovery.sh <backup NAME.age|restore BUNDLE.age IDENTITY>" ;;
esac
