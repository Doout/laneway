#!/bin/sh -p
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset ENV BASH_ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH
IFS=$(printf ' \t\n_'); IFS=${IFS%_}
set -eu
umask 077

for trusted_command_dir in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin; do
  [ -d "$trusted_command_dir" ] && [ ! -L "$trusted_command_dir" ] && \
    [ "$(/usr/bin/stat -c '%u:%g' "$trusted_command_dir")" = 0:0 ] || {
      echo "Laneway installer: trusted command directory is unsafe: $trusted_command_dir" >&2
      exit 1
    }
  trusted_command_mode=$((0$(/usr/bin/stat -c %a "$trusted_command_dir")))
  [ $((trusted_command_mode & 0022)) -eq 0 ] || {
    echo "Laneway installer: trusted command directory is writable by group or other: $trusted_command_dir" >&2
    exit 1
  }
done

source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository=Doout/laneway
noninteractive=${LANEWAY_NONINTERACTIVE:-false}
answers_file=${LANEWAY_INSTALLER_ANSWERS_FILE:-/var/lib/laneway-installer/control-plane.answers}
production_mode=${LANEWAY_PRODUCTION_MODE:-false}
cosign_bin=/usr/local/libexec/laneway/cosign-v3.1.3
checksum_signature_verified=false
installer_work=
installer_work_claimed=false
issuer_answer_dir=
issuer_source_dir=
recovery_kit=
backup_recipient=
answers_dir=
answers_dir_needs_claim=false
answers_temporary=

die() { echo "Laneway installer: $*" >&2; exit 1; }
add_missing() {
  if [ -n "${missing:-}" ]; then missing="$missing
$1"; else missing=$1; fi
}

if [ "${LANEWAY_REPOSITORY+x}" = x ] || \
  [ "${LANEWAY_RELEASE_BASE_URL+x}" = x ] || \
  [ "${LANEWAY_COSIGN_BIN+x}" = x ] || \
  [ "${LANEWAY_CHECKSUM_SIGNATURE_VERIFIED+x}" = x ]; then
  die "release trust and source overrides are not allowed"
fi

cleanup() {
  if [ -n "$answers_temporary" ] && [ -f "$answers_temporary" ] && \
    [ ! -L "$answers_temporary" ]; then
    find "$answers_temporary" -maxdepth 0 -delete 2>/dev/null || true
  fi
  if [ "$installer_work_claimed" = true ] && [ -n "$installer_work" ] && \
    [ -e "$installer_work" ]; then
    find "$installer_work" -depth -delete 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

case "$production_mode" in true|false) ;; *) die "LANEWAY_PRODUCTION_MODE must be true or false" ;; esac
if [ "$production_mode" = true ]; then install_profile=production; else install_profile=quick; fi

if env | grep -E '^COMPOSE_[A-Za-z0-9_]*=' >/dev/null; then
  die "ambient COMPOSE_* overrides are not allowed"
fi
if env | grep -E '^(COSIGN|SIGSTORE|TUF)_[A-Za-z0-9_]*=' >/dev/null; then
  die "ambient signature trust overrides are not allowed"
fi
if [ "${CURL_CA_BUNDLE+x}" = x ] || [ "${SSL_CERT_FILE+x}" = x ] || \
  [ "${SSL_CERT_DIR+x}" = x ]; then
  die "ambient TLS trust overrides are not allowed"
fi
if [ "${DOCKER_HOST+x}" = x ] || [ "${DOCKER_CONTEXT+x}" = x ] || \
  [ "${DOCKER_TLS+x}" = x ] || \
  [ "${DOCKER_TLS_VERIFY+x}" = x ] || [ "${DOCKER_CERT_PATH+x}" = x ] || \
  [ "${DOCKER_CONFIG+x}" = x ]; then
  die "Docker target overrides are not allowed"
fi
HOME=/root
export HOME

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
    DOCKER_CONFIG=/root/.docker \
    DOCKER_CONTEXT=default \
    "$@"
}

validate_answers_file() {
  if [ ! -e "$answers_file" ] && [ ! -L "$answers_file" ]; then
    return
  fi
  if [ ! -f "$answers_file" ] || [ -L "$answers_file" ]; then
    die "remembered-answer file is not a safe regular file: $answers_file"
  fi
  [ "$(stat -c '%u:%g:%a:%h' "$answers_file")" = 0:0:600:1 ] || \
    die "remembered-answer file must be root-owned, mode 0600, and have one link"
  awk '
    /^[[:space:]]*($|#)/ { next }
    {
      name = $0
      if (name !~ /^[A-Z][A-Z0-9_]*=/) exit 1
      sub(/=.*/, "", name)
      if (name != "LANEWAY_DOMAIN" && name != "LANEWAY_DEPLOY_DIR" &&
          name != "LANEWAY_NETWORK_NAME" && name != "LANEWAY_IPV4_POOL" &&
          name != "LANEWAY_BIND_ADDRESS" && name != "LANEWAY_CONTROLLER_PORT" &&
          name != "LANEWAY_RELAY_QUIC_PORT" && name != "LANEWAY_RELAY_TCP_PORT" &&
          name != "LANEWAY_PREPARED_INPUT_DIR" && name != "LANEWAY_RECOVERY_KIT_DIR" &&
          name != "LANEWAY_BACKUP_RECIPIENT") exit 1
    }
  ' "$answers_file" || die "remembered-answer file contains a malformed or unknown assignment"
  for answer_key in LANEWAY_DOMAIN LANEWAY_DEPLOY_DIR LANEWAY_NETWORK_NAME \
    LANEWAY_IPV4_POOL LANEWAY_BIND_ADDRESS LANEWAY_CONTROLLER_PORT \
    LANEWAY_RELAY_QUIC_PORT LANEWAY_RELAY_TCP_PORT LANEWAY_PREPARED_INPUT_DIR \
    LANEWAY_RECOVERY_KIT_DIR LANEWAY_BACKUP_RECIPIENT; do
    canonical_count=$(grep -c "^${answer_key}=" "$answers_file" || true)
    mention_count=$(grep -Ec "^[[:space:]]*(export[[:space:]]+)?${answer_key}[[:space:]]*=" "$answers_file" || true)
    [ "$mention_count" -eq "$canonical_count" ] || die "remembered-answer file contains malformed $answer_key"
    [ "$canonical_count" -le 1 ] || die "remembered-answer file contains duplicate $answer_key"
    if [ "$canonical_count" -eq 1 ]; then
      answer_value=$(sed -n "s/^${answer_key}=//p" "$answers_file")
      [ -n "$answer_value" ] || die "remembered-answer file contains empty $answer_key"
    fi
  done
}

remembered() {
  key=$1
  fallback=${2:-}
  if [ ! -e "$answers_file" ] && [ ! -L "$answers_file" ]; then
    printf '%s' "$fallback"
    return
  fi
  if grep -q "^${key}=" "$answers_file"; then
    sed -n "s/^${key}=//p" "$answers_file"
  else
    printf '%s' "$fallback"
  fi
}

save_answers() {
  if [ "$answers_dir_needs_claim" = true ]; then
    if [ -e "$answers_dir" ] || [ -L "$answers_dir" ]; then
      die "remembered-answer directory appeared before publication; refusing to reuse it"
    fi
    mkdir "$answers_dir" 2>/dev/null || \
      die "could not atomically claim remembered-answer directory"
    chmod 0700 "$answers_dir"
    chown 0:0 "$answers_dir"
    answers_dir_needs_claim=false
  fi
  revalidate_answers_directory
  answers_temporary=$(mktemp "$answers_dir/.control-plane-installer.XXXXXX")
  {
    printf 'LANEWAY_DOMAIN=%s\n' "$domain"
    printf 'LANEWAY_DEPLOY_DIR=%s\n' "$destination"
    printf 'LANEWAY_NETWORK_NAME=%s\n' "$network_name"
    printf 'LANEWAY_IPV4_POOL=%s\n' "$ipv4_pool"
    printf 'LANEWAY_BIND_ADDRESS=%s\n' "$bind_address"
    printf 'LANEWAY_CONTROLLER_PORT=%s\n' "$controller_port"
    printf 'LANEWAY_RELAY_QUIC_PORT=%s\n' "$relay_quic_port"
    printf 'LANEWAY_RELAY_TCP_PORT=%s\n' "$relay_tcp_port"
    [ -z "${issuer_answer_dir:-}" ] || printf 'LANEWAY_PREPARED_INPUT_DIR=%s\n' "$issuer_answer_dir"
    [ -z "${recovery_kit:-}" ] || printf 'LANEWAY_RECOVERY_KIT_DIR=%s\n' "$recovery_kit"
    [ -z "${backup_recipient:-}" ] || printf 'LANEWAY_BACKUP_RECIPIENT=%s\n' "$backup_recipient"
  } > "$answers_temporary"
  chmod 0600 "$answers_temporary"
  chown 0:0 "$answers_temporary"
  [ "$(stat -c '%u:%g:%a:%h' "$answers_temporary")" = 0:0:600:1 ] || \
    die "temporary remembered-answer file is unsafe"
  revalidate_answers_directory
  mv "$answers_temporary" "$answers_file"
  answers_temporary=
}

ask() {
  label=$1
  default_value=${2:-}
  if [ "$noninteractive" = true ]; then
    REPLY=$default_value
    return
  fi
  if [ -n "$default_value" ]; then
    printf '%s [%s]: ' "$label" "$default_value" >&2
  else
    printf '%s: ' "$label" >&2
  fi
  IFS= read -r REPLY || die "input ended while reading: $label"
  [ -n "$REPLY" ] || REPLY=$default_value
}

valid_dns_name() {
  printf '%s\n' "$1" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
}

valid_port() {
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  [ "$1" -ge 1 ] || return 1
  [ "$1" -le 65535 ]
}

valid_ipv4() {
  candidate=$1
  first=${candidate%%.*}; remainder=${candidate#*.}
  [ "$remainder" != "$candidate" ] || return 1
  second=${remainder%%.*}; next=${remainder#*.}
  [ "$next" != "$remainder" ] || return 1
  third=${next%%.*}; fourth=${next#*.}
  [ "$fourth" != "$next" ] || return 1
  case "$fourth" in *.*) return 1 ;; esac
  for octet in "$first" "$second" "$third" "$fourth"; do
    case "$octet" in ''|*[!0-9]*) return 1 ;; esac
    canonical_octet=$(awk -v value="$octet" 'BEGIN { printf "%d", value + 0 }')
    [ "$canonical_octet" = "$octet" ] || return 1
    [ "$octet" -le 255 ] || return 1
  done
}

valid_ipv4_pool() {
  printf '%s\n' "$1" | awk -F/ '
    function overlaps(first, last, reserved_first, reserved_last) {
      return first <= reserved_last && reserved_first <= last
    }
    NF != 2 { exit 1 }
    $2 !~ /^[0-9]+$/ || sprintf("%d", $2 + 0) != $2 || $2 < 8 || $2 > 30 { exit 1 }
    {
      octet_count = split($1, octets, ".")
      if (octet_count != 4) exit 1
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

canonical_absolute_path() {
  candidate_path=$1
  case "$candidate_path" in
    /*) ;;
    *) return 1 ;;
  esac
  case "$candidate_path" in
    /|*/|*//*|*/./*|*/../*|*/.|*/..) return 1 ;;
  esac
  case "$candidate_path" in *[!A-Za-z0-9_./-]*) return 1 ;; esac
}

trusted_directory_chain() {
  checked_path=$1
  while :; do
    [ -d "$checked_path" ] && [ ! -L "$checked_path" ] || return 1
    directory_stat=$(stat -c '%u:%g:%a' "$checked_path") || return 1
    directory_uid=${directory_stat%%:*}
    directory_remainder=${directory_stat#*:}
    directory_gid=${directory_remainder%%:*}
    directory_mode=${directory_remainder#*:}
    [ "$directory_uid" -eq 0 ] && [ "$directory_gid" -eq 0 ] || return 1
    directory_mode_value=$((0$directory_mode))
    if [ $((directory_mode_value & 0022)) -ne 0 ] && \
      [ "$directory_mode" != 1777 ]; then
      return 1
    fi
    [ "$checked_path" != / ] || break
    checked_path=$(dirname "$checked_path")
  done
}

revalidate_answers_directory() {
  [ -d "$answers_dir" ] && [ ! -L "$answers_dir" ] && \
    [ "$(stat -c '%u:%g:%a' "$answers_dir")" = 0:0:700 ] || \
    die "remembered-answer directory must be root-owned with mode 0700"
  trusted_directory_chain "$answers_dir" || \
    die "remembered-answer directory ancestry must be root-owned and non-replaceable"
  physical_answers_dir=$(CDPATH='' cd -- "$answers_dir" 2>/dev/null && pwd -P) || \
    die "remembered-answer directory cannot be resolved"
  [ "$physical_answers_dir" = "$answers_dir" ] || \
    die "remembered-answer directory changed during publication"
}

resolve_answers_file_path() {
  requested_answers_file=$answers_file
  canonical_absolute_path "$requested_answers_file" || \
    die "remembered-answer file must use a canonical safe absolute path"
  requested_answers_dir=${requested_answers_file%/*}
  answers_leaf=${requested_answers_file##*/}
  [ -n "$requested_answers_dir" ] || requested_answers_dir=/
  if [ -e "$requested_answers_dir" ] || [ -L "$requested_answers_dir" ]; then
    [ -d "$requested_answers_dir" ] && [ ! -L "$requested_answers_dir" ] || \
      die "remembered-answer directory is unsafe"
    physical_answers_dir=$(CDPATH='' cd -- "$requested_answers_dir" 2>/dev/null && pwd -P) || \
      die "remembered-answer directory cannot be resolved"
    [ "$physical_answers_dir" = "$requested_answers_dir" ] || \
      die "remembered-answer directory must not contain symbolic-link ancestors"
    answers_dir=$physical_answers_dir
    answers_dir_needs_claim=false
    revalidate_answers_directory
  else
    requested_answers_parent=${requested_answers_dir%/*}
    answers_dir_leaf=${requested_answers_dir##*/}
    [ -n "$requested_answers_parent" ] || requested_answers_parent=/
    [ -n "$answers_dir_leaf" ] || die "remembered-answer directory is invalid"
    physical_answers_parent=$(CDPATH='' cd -- "$requested_answers_parent" 2>/dev/null && pwd -P) || \
      die "remembered-answer directory parent must already exist"
    [ "$physical_answers_parent" = "$requested_answers_parent" ] || \
      die "remembered-answer directory parent must not contain symbolic-link ancestors"
    trusted_directory_chain "$physical_answers_parent" || \
      die "remembered-answer directory parent ancestry must be root-owned and non-replaceable"
    if [ "$physical_answers_parent" = / ]; then
      answers_dir=/$answers_dir_leaf
    else
      answers_dir=$physical_answers_parent/$answers_dir_leaf
    fi
    answers_dir_needs_claim=true
  fi
  answers_file=$answers_dir/$answers_leaf
}

resolve_new_directory_path() {
  unresolved_path=$1
  path_label=$2
  canonical_absolute_path "$unresolved_path" || \
    die "$path_label directory must be a canonical safe absolute path"
  unresolved_parent=${unresolved_path%/*}
  unresolved_leaf=${unresolved_path##*/}
  [ -n "$unresolved_parent" ] || unresolved_parent=/
  resolved_parent=$(CDPATH='' cd -- "$unresolved_parent" 2>/dev/null && pwd -P) || \
    die "$path_label directory parent must already exist"
  case "$resolved_parent" in *[!A-Za-z0-9_./-]*) die "$path_label directory parent resolves to an unsafe path" ;; esac
  trusted_directory_chain "$resolved_parent" || \
    die "$path_label directory parent ancestry must be root-owned and non-replaceable"
  if [ "$resolved_parent" = / ]; then
    RESOLVED_PATH=/$unresolved_leaf
  else
    RESOLVED_PATH=$resolved_parent/$unresolved_leaf
  fi
  case "$RESOLVED_PATH" in
    /dev/shm|/dev/shm/*) die "$path_label directory must be outside /dev/shm" ;;
  esac
}

resolve_existing_directory_path() {
  unresolved_path=$1
  path_label=$2
  canonical_absolute_path "$unresolved_path" || \
    die "$path_label directory must be a canonical safe absolute path"
  [ -d "$unresolved_path" ] && [ ! -L "$unresolved_path" ] || \
    die "$path_label directory is missing or unsafe"
  resolved_existing=$(CDPATH='' cd -- "$unresolved_path" 2>/dev/null && pwd -P) || \
    die "$path_label directory cannot be resolved"
  case "$resolved_existing" in *[!A-Za-z0-9_./-]*) die "$path_label directory resolves to an unsafe path" ;; esac
  trusted_directory_chain "$resolved_existing" || \
    die "$path_label directory ancestry must be root-owned and non-replaceable"
  RESOLVED_PATH=$resolved_existing
}

paths_overlap() {
  first_path=$1
  second_path=$2
  [ "$first_path" = "$second_path" ] && return 0
  case "$first_path/" in "$second_path/"*) return 0 ;; esac
  case "$second_path/" in "$first_path/"*) return 0 ;; esac
  return 1
}

ensure_installer_work() {
  [ -z "$installer_work" ] || return 0
  trusted_directory_chain /var/tmp || \
    die "/var/tmp ancestry must be root-owned and non-replaceable"
  work_candidate=$(mktemp -d /var/tmp/laneway-installer.XXXXXX)
  [ "${work_candidate%/*}" = /var/tmp ] && [ -d "$work_candidate" ] && \
    [ ! -L "$work_candidate" ] || die "installer work directory escaped /var/tmp"
  installer_work=$work_candidate
  installer_work_claimed=true
  [ "$(stat -c '%u:%g:%a' "$installer_work")" = 0:0:700 ] || \
    die "installer work directory must be root-owned with mode 0700"
}

resolve_cosign_command() {
  [ -f "$cosign_bin" ] && [ ! -L "$cosign_bin" ] && [ -x "$cosign_bin" ] || \
    die "pinned Cosign verifier is unavailable"
  cosign_parent=$(dirname "$cosign_bin")
  physical_cosign_parent=$(CDPATH='' cd -- "$cosign_parent" 2>/dev/null && pwd -P) || \
    die "Cosign parent directory cannot be resolved"
  [ "$physical_cosign_parent" = "$cosign_parent" ] || \
    die "Cosign path must not contain symbolic-link ancestors"
  trusted_directory_chain "$cosign_parent" || \
    die "Cosign path ancestry must be root-owned and non-replaceable"
  [ "$(stat -c '%u:%g:%h' "$cosign_bin")" = 0:0:1 ] || \
    die "Cosign must be a root-owned single-link regular file"
  cosign_mode=$((0$(stat -c %a "$cosign_bin")))
  [ $((cosign_mode & 0022)) -eq 0 ] || \
    die "Cosign must not be writable by group or other"
  cosign_version=$("$cosign_bin" version --json 2>/dev/null | \
    sed -n 's/.*"gitVersion":[[:space:]]*"\([^"]*\)".*/\1/p' | sed -n '1p')
  [ "$cosign_version" = v3.1.3 ] || \
    die "pinned Cosign verifier must report version v3.1.3"
}

validate_issuer_file() {
  issuer_file=$1
  issuer_mode=$2
  [ -f "$issuer_file" ] && [ ! -L "$issuer_file" ] || \
    die "prepared input contains an unsafe file: ${issuer_file##*/}"
  [ "$(stat -c '%u:%g:%a:%h' "$issuer_file")" = "0:0:$issuer_mode:1" ] || \
    die "prepared input file ${issuer_file##*/} must be root-owned, mode 0$issuer_mode, and have one link"
}

snapshot_issuer_dir() {
  source_issuer=$1
  resolve_existing_directory_path "$source_issuer" "prepared input"
  source_issuer=$RESOLVED_PATH
  issuer_source_dir=$source_issuer
  [ "$(stat -c '%u:%g:%a' "$source_issuer")" = 0:0:700 ] || \
    die "prepared input directory must be root-owned with mode 0700"
  paths_overlap "$destination" "$source_issuer" && \
    die "prepared input and deployment directories must not overlap"
  if [ -e "$source_issuer/ca.key" ] || [ -L "$source_issuer/ca.key" ]; then
    die "offline root ca.key must not be present in control-plane input"
  fi
  validate_issuer_file "$source_issuer/ca.crt" 444
  validate_issuer_file "$source_issuer/intermediate-chain.crt" 444
  validate_issuer_file "$source_issuer/intermediate.key" 400
  recipient_present=false
  if [ -e "$source_issuer/recovery-recipient.txt" ] || \
    [ -L "$source_issuer/recovery-recipient.txt" ]; then
    validate_issuer_file "$source_issuer/recovery-recipient.txt" 444
    recipient_present=true
  fi
  ensure_installer_work
  issuer_snapshot=$installer_work/issuer
  mkdir "$issuer_snapshot" 2>/dev/null || die "could not claim protected issuer staging"
  chmod 0700 "$issuer_snapshot"
  chown 0:0 "$issuer_snapshot"
  install -m 0444 -o 0 -g 0 "$source_issuer/ca.crt" "$issuer_snapshot/ca.crt"
  install -m 0444 -o 0 -g 0 "$source_issuer/intermediate-chain.crt" "$issuer_snapshot/intermediate-chain.crt"
  install -m 0400 -o 0 -g 0 "$source_issuer/intermediate.key" "$issuer_snapshot/intermediate.key"
  if [ "$recipient_present" = true ]; then
    install -m 0444 -o 0 -g 0 "$source_issuer/recovery-recipient.txt" "$issuer_snapshot/recovery-recipient.txt"
  fi
  [ "$(stat -c '%u:%g:%a' "$issuer_snapshot")" = 0:0:700 ] || \
    die "protected issuer staging has unsafe ownership or mode"
  issuer_dir=$issuer_snapshot
}

missing=
for command in age age-keygen awk chmod chown curl date dirname docker env find getent grep install jq laneway ln mkdir mktemp mv sed sha256sum ss stat sync wc; do
  command -v "$command" >/dev/null 2>&1 || add_missing "$command"
done
[ "$(id -u)" -eq 0 ] || add_missing "root privileges (run with sudo)"
if command -v awk >/dev/null 2>&1 && command -v grep >/dev/null 2>&1 && \
  command -v sed >/dev/null 2>&1 && command -v stat >/dev/null 2>&1; then
  resolve_answers_file_path
  validate_answers_file
fi
if [ -e /root/.docker ] || [ -L /root/.docker ]; then
  if [ ! -d /root/.docker ] || [ -L /root/.docker ]; then
    add_missing "a safe Docker configuration directory at /root/.docker"
  elif ! trusted_directory_chain /root/.docker; then
    add_missing "a root-owned, non-replaceable Docker configuration directory at /root/.docker"
  else
    docker_config_mode=$(stat -c %a /root/.docker)
    docker_config_mode_value=$((0$docker_config_mode))
    if [ $((docker_config_mode_value & 0022)) -ne 0 ]; then
      add_missing "a non-group/world-writable Docker configuration directory at /root/.docker"
    fi
  fi
elif ! trusted_directory_chain /root; then
  add_missing "a root-owned, non-replaceable /root directory"
fi
if command -v docker >/dev/null 2>&1; then
  compose_environment docker --context default compose version >/dev/null 2>&1 || add_missing "Docker Compose v2"
fi
resolve_cosign_command
if [ -n "$missing" ]; then
  echo "Laneway pre-check found missing prerequisites:" >&2
  printf '%s\n' "$missing" | while IFS= read -r item; do printf '  - %s\n' "$item" >&2; done
  die "install the listed prerequisites and rerun; no deployment changes were made"
fi

if [ "$noninteractive" != true ]; then
  cat >&2 <<'EOF'
Laneway control-plane setup

Press Enter to accept a shown default. You will need:
  - a public DNS name that already resolves to this host

By default, the installer creates the issuer and recovery identity for you and
leaves one protected recovery-kit directory to copy off this server. You can
instead provide control-plane-input prepared on a separate trusted host.

No host networking or firewall settings will be changed.
EOF
fi

package_version=
if [ -f "$source_dir/../../VERSION" ] && [ ! -L "$source_dir/../../VERSION" ]; then
  package_version=$(sed -n '1p' "$source_dir/../../VERSION")
fi
version_default=${LANEWAY_VERSION:-$package_version}
if [ -n "${LANEWAY_VERSION:-}" ]; then
  release=$LANEWAY_VERSION
else
  ask "Release tag" "$version_default"
  release=$REPLY
fi
case "$release" in v*) release=${release#v} ;; esac
printf '%s\n' "$release" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || \
  die "release tag must be a stable vMAJOR.MINOR.PATCH tag"
tag=v$release
if [ -n "$package_version" ] && [ "$package_version" != "$release" ]; then
  die "the installed package is $package_version but the selected release is $release; install the matching package first"
fi

ask "Public DNS name" "${LANEWAY_DOMAIN:-$(remembered LANEWAY_DOMAIN)}"
domain=$REPLY
valid_dns_name "$domain" || die "public DNS name is invalid"
getent ahosts "$domain" >/dev/null 2>&1 || die "public DNS does not resolve: $domain"

ask "Deployment directory" "${LANEWAY_DEPLOY_DIR:-$(remembered LANEWAY_DEPLOY_DIR /opt/laneway)}"
destination=$REPLY
resolve_new_directory_path "$destination" "deployment"
destination=$RESOLVED_PATH
if [ -e "$destination" ] || [ -L "$destination" ]; then
  die "deployment directory already exists; refusing to overwrite it: $destination"
fi
if [ -e /usr/local/sbin/laneway-control ] || [ -L /usr/local/sbin/laneway-control ]; then
  die "system control-plane command already exists: /usr/local/sbin/laneway-control"
fi

ask "Network name" "${LANEWAY_NETWORK_NAME:-$(remembered LANEWAY_NETWORK_NAME production)}"
network_name=$REPLY
case "$network_name" in ''|*[!A-Za-z0-9._-]*) die "network name may contain only letters, numbers, dot, underscore, and dash" ;; esac

ask "Overlay IPv4 pool" "${LANEWAY_IPV4_POOL:-$(remembered LANEWAY_IPV4_POOL 100.96.0.0/16)}"
ipv4_pool=$REPLY
valid_ipv4_pool "$ipv4_pool" || die "overlay IPv4 pool is invalid"

ask "Host bind address" "${LANEWAY_BIND_ADDRESS:-$(remembered LANEWAY_BIND_ADDRESS 0.0.0.0)}"
bind_address=$REPLY
valid_ipv4 "$bind_address" || die "bind address must be an IPv4 address"

ask "Controller TCP/UDP port" "${LANEWAY_CONTROLLER_PORT:-$(remembered LANEWAY_CONTROLLER_PORT 8443)}"
controller_port=$REPLY
valid_port "$controller_port" || die "controller port is invalid"
ask "Relay QUIC/UDP port" "${LANEWAY_RELAY_QUIC_PORT:-$(remembered LANEWAY_RELAY_QUIC_PORT 4433)}"
relay_quic_port=$REPLY
valid_port "$relay_quic_port" || die "relay QUIC port is invalid"
ask "Relay TCP fallback port" "${LANEWAY_RELAY_TCP_PORT:-$(remembered LANEWAY_RELAY_TCP_PORT 443)}"
relay_tcp_port=$REPLY
valid_port "$relay_tcp_port" || die "relay TCP port is invalid"
[ "$controller_port" != "$relay_quic_port" ] || die "controller and relay UDP ports must differ"
[ "$controller_port" != "$relay_tcp_port" ] || die "controller and relay TCP ports must differ"

check_available_port() {
  port_protocol=$1
  port_number=$2
  case "$port_protocol" in tcp) port_flag=-ltn ;; udp) port_flag=-lun ;; esac
  port_listeners=$(ss -H "$port_flag" "sport = :$port_number") || \
    die "cannot inspect $port_protocol port $port_number"
  [ -z "$port_listeners" ] || \
    die "$port_protocol port $port_number is already occupied by foreign state"
}
check_available_port tcp "$controller_port"
check_available_port udp "$controller_port"
check_available_port udp "$relay_quic_port"
check_available_port tcp "$relay_tcp_port"

automatic_issuer=false
issuer_dir=${LANEWAY_ISSUER_DIR:-}
if [ -z "$issuer_dir" ]; then
  ask "Prepared control-plane input directory (Enter to generate automatically)" "${LANEWAY_PREPARED_INPUT_DIR:-$(remembered LANEWAY_PREPARED_INPUT_DIR)}"
  issuer_dir=$REPLY
fi
if [ -n "$issuer_dir" ]; then
  snapshot_issuer_dir "$issuer_dir"
  issuer_answer_dir=$issuer_source_dir
  backup_recipient=${LANEWAY_BACKUP_RECIPIENT:-$(remembered LANEWAY_BACKUP_RECIPIENT)}
  if [ -z "$backup_recipient" ] && [ -f "$issuer_dir/recovery-recipient.txt" ] && [ ! -L "$issuer_dir/recovery-recipient.txt" ]; then
    [ "$(wc -l < "$issuer_dir/recovery-recipient.txt")" -eq 1 ] || die "prepared recovery recipient file must contain exactly one line"
    backup_recipient=$(sed -n '1p' "$issuer_dir/recovery-recipient.txt")
  fi
  if [ -z "$backup_recipient" ]; then
    ask "Off-host age recovery recipient" ""
    backup_recipient=$REPLY
  fi
  printf '%s\n' "$backup_recipient" | grep -Eq '^age1[0-9a-z]{58}$' || \
    die "recovery recipient must be an age X25519 public recipient"
  recovery_description="prepared input: $issuer_answer_dir"
else
  automatic_issuer=true
  recovery_default=/root/laneway-recovery-$domain-$(date -u +%Y%m%dT%H%M%SZ)
  ask "Recovery kit directory" "${LANEWAY_RECOVERY_KIT_DIR:-$(remembered LANEWAY_RECOVERY_KIT_DIR "$recovery_default")}"
  recovery_kit=$REPLY
  resolve_new_directory_path "$recovery_kit" "recovery kit"
  recovery_kit=$RESOLVED_PATH
  paths_overlap "$destination" "$recovery_kit" && \
    die "recovery kit and deployment directories must not overlap"
  if [ -e "$recovery_kit" ] || [ -L "$recovery_kit" ]; then
    die "recovery kit already exists; refusing to overwrite it: $recovery_kit"
  fi
  recovery_description="generate automatically; copy $recovery_kit off-host after setup"
fi

ensure_installer_work
metadata_dir=$installer_work
base_url=https://github.com/$repository/releases/download/$tag
for metadata_name in image-digests.txt checksums.txt checksums.sigstore.json; do
  curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --fail --location --silent --show-error \
    "$base_url/$metadata_name" -o "$metadata_dir/$metadata_name"
done

identity="https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/$tag"
"$cosign_bin" verify-blob --bundle "$metadata_dir/checksums.sigstore.json" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$metadata_dir/checksums.txt" >/dev/null || \
  die "release checksum signature verification failed"
(
  cd "$metadata_dir"
  grep '  image-digests.txt$' checksums.txt > image-digests-checksum.txt
  [ "$(wc -l < image-digests-checksum.txt)" -eq 1 ]
  sha256sum -c image-digests-checksum.txt >/dev/null
) || die "signed release checksum does not match image-digests.txt"
checksum_signature_verified=true

image_digest() {
  image=$1
  matches=$(sed -n "s|^${image}@\(sha256:[0-9a-f]\{64\}\)$|\1|p" "$metadata_dir/image-digests.txt")
  [ "$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l)" -eq 1 ] || die "release metadata has no unique digest for $image"
  printf '%s' "$matches"
}

controller_digest=$(image_digest ghcr.io/doout/laneway-controller)
relay_digest=$(image_digest ghcr.io/doout/laneway-relay)
admin_digest=$(image_digest ghcr.io/doout/laneway-admin)
connector_digest=$(image_digest ghcr.io/doout/lane-edge)
exit_node_digest=$(image_digest ghcr.io/doout/laneway-exit-node)
for reference in \
  "ghcr.io/doout/laneway-controller@$controller_digest" \
  "ghcr.io/doout/laneway-relay@$relay_digest" \
  "ghcr.io/doout/laneway-admin@$admin_digest" \
  "ghcr.io/doout/lane-edge@$connector_digest" \
  "ghcr.io/doout/laneway-exit-node@$exit_node_digest"
do
  "$cosign_bin" verify --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$reference" >/dev/null || die "image signature verification failed for $reference"
done
image_signatures_verified=true

network_id=$(laneway id)
controller_id=$(laneway id)
relay_id=$(laneway id)
for value in "$network_id" "$controller_id" "$relay_id"; do
  printf '%s\n' "$value" | grep -Eq '^[0-9a-f]{32}$' || die "laneway generated an invalid identity"
done
if [ "$network_id" = "$controller_id" ] || [ "$network_id" = "$relay_id" ] || [ "$controller_id" = "$relay_id" ]; then
  die "laneway generated duplicate identities"
fi

cat >&2 <<EOF

Laneway is ready to deploy:
  release:      $tag (images are pinned by immutable digest)
  profile:      $install_profile
  public name:  $domain
  directory:    $destination
  overlay pool: $ipv4_pool
  listeners:    $bind_address:$controller_port TCP+UDP, $bind_address:$relay_quic_port UDP, $bind_address:$relay_tcp_port TCP
  recovery:     $recovery_description

This starts an isolated Docker Compose control plane. It does not edit the host
firewall, routes, interfaces, DNS, or sysctls. Ensure DNS and your external
firewall already allow the listed ports while preserving SSH access.
EOF
if [ "$noninteractive" = true ]; then
  confirmation=${LANEWAY_CONFIRM:-no}
else
  ask "Type deploy to continue" ""
  confirmation=$REPLY
fi
[ "$confirmation" = deploy ] || die "cancelled before changing the deployment"

save_answers

if [ "$automatic_issuer" = true ]; then
  if [ ! -f "$source_dir/prepare-control-plane.sh" ] || [ -L "$source_dir/prepare-control-plane.sh" ]; then
    die "packaged automatic issuer helper is missing or unsafe"
  fi
  "$source_dir/prepare-control-plane.sh" "$recovery_kit"
  generated_issuer_dir=$recovery_kit/control-plane-input
  snapshot_issuer_dir "$generated_issuer_dir"
  [ "$(wc -l < "$issuer_dir/recovery-recipient.txt")" -eq 1 ] || die "generated recovery recipient file is invalid"
  backup_recipient=$(sed -n '1p' "$issuer_dir/recovery-recipient.txt")
  printf '%s\n' "$backup_recipient" | grep -Eq '^age1[0-9a-z]{58}$' || die "generated recovery recipient is invalid"
fi

mkdir "$destination" 2>/dev/null || \
  die "deployment directory appeared before publication; refusing to reuse it: $destination"
chmod 0700 "$destination"
chown 0:0 "$destination"
for name in compose.yaml laneway-control bootstrap.sh preflight.sh prepare.sh recovery.sh validate.sh install-control-plane.sh prepare-control-plane.sh upgrade-control-plane.sh README.md; do
  if [ ! -f "$source_dir/$name" ] || [ -L "$source_dir/$name" ]; then
    die "packaged deployment file is missing or unsafe: $name"
  fi
  mode=0644
  case "$name" in laneway-control|*.sh) mode=0755 ;; esac
  install -m "$mode" -o 0 -g 0 "$source_dir/$name" "$destination/$name"
done
ln -s laneway-control "$destination/lane"
ln -s "$destination/laneway-control" /usr/local/sbin/laneway-control

cat > "$destination/PRODUCTION-CHECKLIST.md" <<EOF
# Laneway production checklist

This installation uses the **$install_profile** profile for **$domain** on Laneway **$tag**.
The containers are pinned to immutable image digests. The host firewall and cloud
firewall were not changed by the installer.

## Before production traffic

- [ ] Copy the recovery kit and initial encrypted recovery bundle off this server.
- [ ] Verify the copied recovery kit's \`MANIFEST.sha256\`, then securely remove the server copy.
- [ ] Confirm DNS \`$domain\` resolves to this server's public address.
- [ ] Confirm the external firewall allows TCP 443, UDP 4433, and TCP+UDP 8443.
- [ ] Keep SSH restricted to your trusted access path; do not expose TCP 22 publicly.
- [ ] Run \`sudo laneway-control production-check\` until it succeeds.
- [ ] Test a client enrollment and recovery restore before depending on the service.
- [ ] Configure monitoring, security updates, and recurring encrypted backups.

## Verification recorded during install

- Release checksum signature verified: **$checksum_signature_verified**
- All container image signatures verified: **$image_signatures_verified**

The installer fails closed unless the release package and every container image
pass signature verification. The \`production-check\` command records a root-only
marker only after configuration, service health, DNS, and recovery backup checks pass.

Cloud firewall policy cannot be inspected reliably from inside this host. Confirm it
in your provider's control panel before putting Laneway into production.
EOF
chmod 0644 "$destination/PRODUCTION-CHECKLIST.md"

umask 077
env_tmp=$(mktemp "$destination/.env.XXXXXX")
{
  printf 'LANEWAY_VERSION=%s\n' "$release"
  printf 'LANEWAY_INSTALL_PROFILE=%s\n' "$install_profile"
  printf 'LANEWAY_CONTROLLER_IMAGE_DIGEST=%s\n' "$controller_digest"
  printf 'LANEWAY_RELAY_IMAGE_DIGEST=%s\n' "$relay_digest"
  printf 'LANEWAY_ADMIN_IMAGE_DIGEST=%s\n' "$admin_digest"
  printf 'LANEWAY_CONNECTOR_IMAGE_DIGEST=%s\n' "$connector_digest"
  printf 'LANEWAY_EXIT_NODE_IMAGE_DIGEST=%s\n' "$exit_node_digest"
  printf 'LANEWAY_BIND_ADDRESS=%s\n' "$bind_address"
  printf 'LANEWAY_CONTROLLER_PORT=%s\n' "$controller_port"
  printf 'LANEWAY_RELAY_QUIC_PORT=%s\n' "$relay_quic_port"
  printf 'LANEWAY_RELAY_TCP_PORT=%s\n' "$relay_tcp_port"
  printf 'LANEWAY_EXIT_DIRECT_PORT=4434\n'
  printf 'LANEWAY_CONTROLLER_SERVER_NAME=%s\n' "$domain"
  printf 'LANEWAY_NETWORK_ID=%s\n' "$network_id"
  printf 'LANEWAY_CONTROLLER_SERVICE_ID=%s\n' "$controller_id"
  printf 'LANEWAY_RELAY_SERVICE_ID=%s\n' "$relay_id"
  printf 'LANEWAY_NETWORK_NAME=%s\n' "$network_name"
  printf 'LANEWAY_IPV4_POOL=%s\n' "$ipv4_pool"
  printf 'LANEWAY_RELAY_PUBLIC_ENDPOINT=%s:%s\n' "$domain" "$relay_quic_port"
  printf 'LANEWAY_BACKUP_RECIPIENT=%s\n' "$backup_recipient"
} > "$env_tmp"
chmod 0600 "$env_tmp"
mv "$env_tmp" "$destination/.env"

(cd "$destination" && ./laneway-control init --issuer "$issuer_dir")
initial_backup=initial-recovery-$(date -u +%Y%m%dT%H%M%SZ).age
(cd "$destination" && ./laneway-control backup "$initial_backup")
if [ "$automatic_issuer" = true ]; then
  install -m 0600 -o 0 -g 0 "$destination/generated/recovery/$initial_backup" "$recovery_kit/$initial_backup"
  find "$recovery_kit/control-plane-input" -depth -delete
  cat > "$recovery_kit/DEPLOYED.txt" <<EOF
Laneway $tag was deployed for $domain.

This recovery kit contains the private age identity, encrypted offline root,
and initial encrypted control-plane recovery bundle. Copy the entire directory
off this server, verify the copy, and then securely remove this server copy.
EOF
  chmod 0600 "$recovery_kit/DEPLOYED.txt"
  (
    cd "$recovery_kit"
    sha256sum README.txt DEPLOYED.txt laneway-recovery.identity offline-root.tar.age "$initial_backup" > MANIFEST.sha256
  )
  sync -f "$recovery_kit/MANIFEST.sha256"
  sync -f "$recovery_kit"
fi
cat <<EOF

Laneway $tag is running. Useful commands:
  sudo laneway-control status
  sudo laneway-control production-check
  sudo laneway-control invite --name DEVICE --ephemeral
  sudo laneway-control backup
  initial encrypted backup: $destination/generated/recovery/$initial_backup
EOF
if [ "$automatic_issuer" = true ]; then
  cat <<EOF

IMPORTANT: copy this entire recovery kit off-host now:
  $recovery_kit

After verifying the off-host copy, securely remove the server copy. It contains
the private recovery identity; the running control plane does not need it.
EOF
else
  cat <<EOF

Copy the initial encrypted backup shown above to the trusted host that holds
your recovery kit. The private recovery identity remains off this server.
EOF
fi
