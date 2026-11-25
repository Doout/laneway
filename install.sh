#!/bin/sh
set -eu

# Resolve every command used by a privileged path from fixed system locations,
# never from a caller-controlled PATH or shell startup environment.
caller_path=${PATH:-/usr/local/bin:/usr/bin:/bin}
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
export PATH
unset ENV BASH_ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH XDG_CONFIG_HOME XDG_CACHE_HOME
IFS=$(printf ' \t\n_')
IFS=${IFS%_}
export LC_ALL=C

repository=Doout/laneway
release=${LANEWAY_VERSION:-latest}
install_control_plane=false
prepare_control_plane=false
upgrade_control_plane=false
production_mode=false
quick_control_plane=false
cosign_bin=
download_dir=
lock_dir=
lock_marker=
lock_owner=false
trusted_path=$PATH
published_cosign_tmp=
quick_control_plane_requested=false
active_child_pid=
pending_signal_status=

cleanup() {
  [ -z "$published_cosign_tmp" ] || [ ! -e "$published_cosign_tmp" ] || \
    find "$published_cosign_tmp" -maxdepth 0 -delete 2>/dev/null || true
  [ -z "$download_dir" ] || [ ! -e "$download_dir" ] || \
    find "$download_dir" -depth -delete 2>/dev/null || true
  if [ "$lock_owner" = true ]; then
    [ -z "$lock_marker" ] || [ ! -e "$lock_marker" ] || \
      find "$lock_marker" -maxdepth 0 -delete 2>/dev/null || true
    [ -z "$lock_dir" ] || [ ! -d "$lock_dir" ] || \
      find "$lock_dir" -maxdepth 0 -delete 2>/dev/null || true
  fi
}

forward_active_child_signal() {
  forwarded_signal=$1
  pending_signal_status=$2
  if [ -n "$active_child_pid" ]; then
    # Upgrade children run in their own session/process group so cancellation
    # reaches the updater and every subprocess it is synchronously waiting on.
    kill -"$forwarded_signal" "-$active_child_pid" 2>/dev/null || \
      kill -"$forwarded_signal" "$active_child_pid" 2>/dev/null || true
  fi
}

run_interruptible_upgrade_child() {
  pending_signal_status=
  setsid "$@" &
  active_child_pid=$!
  set +e
  wait "$active_child_pid"
  child_status=$?
  set -e
  active_child_pid=
  if [ -n "$pending_signal_status" ]; then
    return "$pending_signal_status"
  fi
  return "$child_status"
}

trap cleanup EXIT
trap 'forward_active_child_signal HUP 129' HUP
trap 'forward_active_child_signal INT 130' INT
trap 'forward_active_child_signal TERM 143' TERM

add_missing() {
  if [ -n "${missing:-}" ]; then missing="$missing
$1"; else missing=$1; fi
}

validate_trusted_command_path() {
  old_ifs=$IFS
  IFS=:
  for command_dir in $trusted_path; do
    [ -e "$command_dir" ] || return 1
    command_real=$(CDPATH='' cd -- "$command_dir" 2>/dev/null && pwd -P) || {
      IFS=$old_ifs
      return 1
    }
    [ "$command_real" = "$command_dir" ] || {
      IFS=$old_ifs
      return 1
    }
    [ -d "$command_real" ] && [ ! -L "$command_real" ] || {
      IFS=$old_ifs
      return 1
    }
    command_stat=$(/usr/bin/stat -c '%a:%u:%g' "$command_real" 2>/dev/null) || {
      IFS=$old_ifs
      return 1
    }
    command_mode=${command_stat%%:*}
    command_owner_group=${command_stat#*:}
    [ "$command_owner_group" = 0:0 ] && [ $((0$command_mode & 022)) -eq 0 ] || {
      IFS=$old_ifs
      return 1
    }
    validate_protected_ancestor_chain "$command_real" || {
      IFS=$old_ifs
      return 1
    }
  done
  IFS=$old_ifs
}

version_at_least() {
  awk -v have="$1" -v minimum="$2" 'BEGIN {
    sub(/^v/, "", have); sub(/[-+].*$/, "", have)
    split(have, h, "."); split(minimum, m, ".")
    for (i=1; i<=3; i++) {
      if (h[i] !~ /^[0-9]+$/) exit 1
      if ((h[i]+0) > (m[i]+0)) exit 0
      if ((h[i]+0) < (m[i]+0)) exit 1
    }
    exit 0
  }'
}

cosign_version() {
  "$1" version --json 2>/dev/null | sed -n 's/.*"gitVersion":[[:space:]]*"\([^"]*\)".*/\1/p' | sed -n '1p'
}

select_cosign() {
  echo "Laneway verification: using pinned Cosign v3.1.3" >&2
  case "$architecture" in
    amd64) cosign_sha=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 ;;
    arm64) cosign_sha=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a ;;
    *) echo "no pinned Cosign verifier for architecture: $architecture" >&2; return 1 ;;
  esac
  cosign_bin=$download_dir/cosign-v3.1.3
  if ! curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --fail --location --silent --show-error \
    "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-$architecture" -o "$cosign_bin" || \
    ! printf '%s  %s\n' "$cosign_sha" "$cosign_bin" | sha256sum -c - >/dev/null; then
    echo "Laneway verification: could not install the pinned Cosign verifier" >&2
    cosign_bin=
    return 1
  fi
  chmod 0755 "$cosign_bin"
  if [ "$(cosign_version "$cosign_bin")" != v3.1.3 ]; then
    echo "pinned Cosign verifier reported an unexpected version" >&2
    cosign_bin=
    return 1
  fi
}

canonical_deployment_path() {
  candidate_path=$1
  case "$candidate_path" in /*) ;; *) return 1 ;; esac
  case "$candidate_path" in /|*/|*//*|*/./*|*/../*|*/.|*/..) return 1 ;; esac
  case "$candidate_path" in *[!A-Za-z0-9_./-]*) return 1 ;; esac
}

validate_upgrade_lock() {
  [ -d "$lock_dir" ] && [ ! -L "$lock_dir" ] && \
    [ "$(stat -c '%a:%u:%g' "$lock_dir")" = 700:0:0 ] && \
    [ -f "$lock_marker" ] && [ ! -L "$lock_marker" ] && \
    [ "$(stat -c '%a:%u:%g:%h' "$lock_marker")" = 600:0:0:1 ] && \
    [ "$(wc -l < "$lock_marker")" -eq 3 ] && \
    [ "$(sed -n '1p' "$lock_marker")" = version=1 ] && \
    [ "$(sed -n '2p' "$lock_marker")" = "deployment=$upgrade_destination" ] && \
    [ "$(sed -n '3p' "$lock_marker")" = "token=$lock_token" ]
}

validate_protected_ancestor_chain() {
  protected_path=$1
  while [ "$protected_path" != / ]; do
    protected_path=${protected_path%/*}
    [ -n "$protected_path" ] || protected_path=/
    [ -d "$protected_path" ] && [ ! -L "$protected_path" ] || return 1
    protected_stat=$(/usr/bin/stat -c '%a:%u:%g' "$protected_path") || return 1
    protected_mode=${protected_stat%%:*}
    protected_owner_group=${protected_stat#*:}
    [ "$protected_owner_group" = 0:0 ] || return 1
    protected_bits=$((0$protected_mode))
    if [ $((protected_bits & 022)) -ne 0 ] && [ $((protected_bits & 01000)) -eq 0 ]; then
      return 1
    fi
  done
}

publish_cosign() {
  verifier_parent=/usr/local/libexec
  verifier_dir=$verifier_parent/laneway
  for verifier_path in "$verifier_parent" "$verifier_dir"; do
    if [ -e "$verifier_path" ] || [ -L "$verifier_path" ]; then
      [ -d "$verifier_path" ] && [ ! -L "$verifier_path" ] || return 1
    else
      mkdir "$verifier_path" || return 1
      chmod 0755 "$verifier_path" || return 1
      chown 0:0 "$verifier_path" || return 1
    fi
    verifier_real=$(CDPATH='' cd -- "$verifier_path" 2>/dev/null && pwd -P) || return 1
    [ "$verifier_real" = "$verifier_path" ] || return 1
    verifier_stat=$(stat -c '%a:%u:%g' "$verifier_path") || return 1
    verifier_mode=${verifier_stat%%:*}
    [ "${verifier_stat#*:}" = 0:0 ] && [ $((0$verifier_mode & 022)) -eq 0 ] || return 1
    validate_protected_ancestor_chain "$verifier_path" || return 1
  done

  installed_cosign=$verifier_dir/cosign-v3.1.3
  if [ -e "$installed_cosign" ] || [ -L "$installed_cosign" ]; then
    [ -f "$installed_cosign" ] && [ ! -L "$installed_cosign" ] && \
      [ "$(stat -c '%u:%g:%h' "$installed_cosign")" = 0:0:1 ] || return 1
  fi
  published_cosign_tmp=$(mktemp "$verifier_dir/.cosign-v3.1.3.XXXXXX") || return 1
  install -m 0755 -o 0 -g 0 "$cosign_bin" "$published_cosign_tmp" || return 1
  [ -f "$published_cosign_tmp" ] && [ ! -L "$published_cosign_tmp" ] && \
    [ "$(stat -c '%a:%u:%g:%h' "$published_cosign_tmp")" = 755:0:0:1 ] || return 1
  mv -f "$published_cosign_tmp" "$installed_cosign" || return 1
  published_cosign_tmp=
  [ -f "$installed_cosign" ] && [ ! -L "$installed_cosign" ] && \
    [ "$(stat -c '%a:%u:%g:%h' "$installed_cosign")" = 755:0:0:1 ] && \
    [ "$(cosign_version "$installed_cosign")" = v3.1.3 ] || return 1
  cosign_bin=$installed_cosign
}

acquire_upgrade_lock() {
  upgrade_destination=${LANEWAY_DEPLOY_DIR:-/opt/laneway}
  canonical_deployment_path "$upgrade_destination" || {
    echo "LANEWAY_DEPLOY_DIR must be a canonical safe absolute path" >&2
    exit 1
  }
  [ -d "$upgrade_destination" ] && [ ! -L "$upgrade_destination" ] && \
    [ "$(stat -c '%a:%u:%g' "$upgrade_destination")" = 700:0:0 ] || {
      echo "installed control-plane directory is missing or unsafe: $upgrade_destination" >&2
      exit 1
    }
  physical_upgrade_destination=$(CDPATH='' cd -- "$upgrade_destination" && pwd -P) || {
    echo "could not resolve the installed control-plane directory" >&2
    exit 1
  }
  [ "$physical_upgrade_destination" = "$upgrade_destination" ] || {
    echo "LANEWAY_DEPLOY_DIR must not contain symbolic-link ancestors" >&2
    exit 1
  }
  validate_protected_ancestor_chain "$upgrade_destination" || {
    echo "LANEWAY_DEPLOY_DIR ancestors must be root-owned and non-replaceable" >&2
    exit 1
  }
  generated_dir=$upgrade_destination/generated
  lifecycle_dir=$generated_dir/lifecycle
  [ -d "$generated_dir" ] && [ ! -L "$generated_dir" ] && \
    [ "$(stat -c '%a:%u:%g' "$generated_dir")" = 700:0:0 ] || {
      echo "installed generated directory is missing or unsafe" >&2
      exit 1
    }
  if [ -e "$lifecycle_dir" ] || [ -L "$lifecycle_dir" ]; then
    [ -d "$lifecycle_dir" ] && [ ! -L "$lifecycle_dir" ] && \
      [ "$(stat -c '%a:%u:%g' "$lifecycle_dir")" = 700:0:0 ] || {
        echo "installed lifecycle directory is unsafe" >&2
        exit 1
      }
  else
    mkdir "$lifecycle_dir" 2>/dev/null || {
      echo "could not create the lifecycle state directory" >&2
      exit 1
    }
    chmod 0700 "$lifecycle_dir"
    chown 0:0 "$lifecycle_dir"
  fi
  [ -d "$generated_dir" ] && [ ! -L "$generated_dir" ] && \
    [ "$(stat -c '%a:%u:%g' "$generated_dir")" = 700:0:0 ] && \
    [ -d "$lifecycle_dir" ] && [ ! -L "$lifecycle_dir" ] && \
    [ "$(stat -c '%a:%u:%g' "$lifecycle_dir")" = 700:0:0 ] || {
      echo "installed lifecycle path changed during lock acquisition" >&2
      exit 1
    }
  physical_lifecycle_dir=$(CDPATH='' cd -- "$lifecycle_dir" && pwd -P) || {
    echo "could not resolve the lifecycle state directory" >&2
    exit 1
  }
  [ "$physical_lifecycle_dir" = "$lifecycle_dir" ] || {
    echo "lifecycle state path must not contain symbolic-link ancestors" >&2
    exit 1
  }
  lock_dir=$lifecycle_dir/operator.lock
  mkdir "$lock_dir" 2>/dev/null || {
    echo "another lifecycle operation is active" >&2
    exit 1
  }
  lock_owner=true
  chmod 0700 "$lock_dir"
  chown 0:0 "$lock_dir"
  [ -d "$lock_dir" ] && [ ! -L "$lock_dir" ] && \
    [ "$(stat -c '%a:%u:%g' "$lock_dir")" = 700:0:0 ] || {
      echo "could not protect lifecycle operation lock" >&2
      exit 1
    }
  lock_marker=$(mktemp "$lock_dir/.handoff.XXXXXX")
  lock_token=${lock_marker##*/}
  chmod 0600 "$lock_marker"
  chown 0:0 "$lock_marker"
  printf '%s\n' version=1 "deployment=$upgrade_destination" "token=$lock_token" > "$lock_marker"
  validate_upgrade_lock || {
      echo "could not protect lifecycle lock handoff" >&2
      exit 1
    }
}

case "${1:-}" in
  '')
    [ -z "${LANEWAY_DOMAIN:-}" ] || quick_control_plane_requested=true
    ;;
  --client) shift ;;
  --control-plane)
    install_control_plane=true; shift
    if [ "${1:-}" = --production ]; then production_mode=true; shift; fi
    ;;
  --prepare-control-plane) prepare_control_plane=true; shift ;;
  --upgrade-control-plane)
    upgrade_control_plane=true; shift
    if [ "${1:-}" = --production ]; then production_mode=true; shift; fi
    ;;
  -h|--help)
    cat <<'EOF'
usage: sh install.sh [--client | --control-plane [--production] | --prepare-control-plane | --upgrade-control-plane [--production]]

Without options, install the latest Laneway client and packaged files on Linux
or macOS. On Linux, setting LANEWAY_DOMAIN runs the control-plane quick setup
with non-interactive defaults. Use --client to force a client-only install.
For a per-user Linux or macOS install of laneway and lanewayd, use the
release's install-node.sh [vMAJOR.MINOR.PATCH].
With --control-plane, select a stable release tag, verify its signed release,
install it, and start the interactive hardened control-plane installer.
The default quick profile uses non-interactive deployment defaults and writes a
production checklist. Release and image signature checks always fail closed.
With --prepare-control-plane, create a recovery kit and the limited input that
may be copied to a separate production control-plane server.
With --upgrade-control-plane, safely upgrade an existing /opt/laneway control
plane while preserving its identity, PKI, state, endpoints, and host networking.
EOF
    exit 0
    ;;
  *) echo "unknown option: $1" >&2; exit 1 ;;
esac
[ "$#" -eq 0 ] || { echo "too many arguments" >&2; exit 1; }

[ "${TAR_OPTIONS+x}" != x ] || {
  echo "TAR_OPTIONS is not allowed for installation" >&2
  exit 1
}
for tls_override in CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR; do
  case "$tls_override" in
    CURL_CA_BUNDLE) tls_override_present=${CURL_CA_BUNDLE+x} ;;
    SSL_CERT_FILE) tls_override_present=${SSL_CERT_FILE+x} ;;
    SSL_CERT_DIR) tls_override_present=${SSL_CERT_DIR+x} ;;
  esac
  [ "$tls_override_present" != x ] || {
    echo "$tls_override is not allowed for installation" >&2
    exit 1
  }
done

# These fixed operating-system tools are reached only after the command path
# and dynamic-loader inputs have been reset above. A nonprivileged macOS or
# explicit DESTDIR developer install may subsequently restore caller tooling;
# paths that execute as root, now or through sudo, remain fixed.
actual_system=$(/usr/bin/uname -s)
detected_uid=$(/usr/bin/id -u)
detected_system=$actual_system
if [ "$detected_uid" -ne 0 ] && \
  { [ "$actual_system" = Darwin ] || [ -n "${DESTDIR:-}" ]; }; then
  PATH=$caller_path
  export PATH
  detected_system=$(uname -s)
fi
if [ "$quick_control_plane_requested" = true ] && [ "$detected_system" = Linux ]; then
  install_control_plane=true
  quick_control_plane=true
fi

control_plane_mode=false
if [ "$install_control_plane" = true ] || [ "$prepare_control_plane" = true ] || \
  [ "$upgrade_control_plane" = true ]; then
  control_plane_mode=true
  PATH=$trusted_path
  export PATH
fi
if [ "$control_plane_mode" = true ] || \
  { [ "$detected_system" = Linux ] && \
    { [ "$detected_uid" -eq 0 ] || [ -z "${DESTDIR:-}" ]; }; }; then
  validate_trusted_command_path || {
    echo "trusted command path is missing or unsafe" >&2
    exit 1
  }
fi
if [ "$control_plane_mode" = true ]; then
  handoff_override=$(env | sed -n '/^\(LANEWAY_REPOSITORY\|LANEWAY_COSIGN_BIN\|LANEWAY_CHECKSUM_SIGNATURE_VERIFIED\|LANEWAY_AUTHENTICATED_RELEASE_BASE_URL\|LANEWAY_AUTHENTICATED_COSIGN_BIN\|LANEWAY_BOOTSTRAP_ARTIFACTS_FILE\|LANEWAY_LIFECYCLE_LOCK_TOKEN\|LANEWAY_LIFECYCLE_LOCK_ROLE\|LANEWAY_UPGRADE_PREFLIGHT_ONLY\|LANEWAY_CONTROL_COMMAND\|LANEWAY_COMMAND\)=/ {
    s/=.*//
    p
    q
  }')
  [ -z "$handoff_override" ] || {
    echo "$handoff_override is reserved for authenticated control-plane handoff" >&2
    exit 1
  }
  for docker_override in DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY \
    DOCKER_CERT_PATH DOCKER_CONFIG; do
    case "$docker_override" in
      DOCKER_HOST) docker_override_present=${DOCKER_HOST+x} ;;
      DOCKER_CONTEXT) docker_override_present=${DOCKER_CONTEXT+x} ;;
      DOCKER_TLS) docker_override_present=${DOCKER_TLS+x} ;;
      DOCKER_TLS_VERIFY) docker_override_present=${DOCKER_TLS_VERIFY+x} ;;
      DOCKER_CERT_PATH) docker_override_present=${DOCKER_CERT_PATH+x} ;;
      DOCKER_CONFIG) docker_override_present=${DOCKER_CONFIG+x} ;;
    esac
    [ "$docker_override_present" != x ] || {
      echo "$docker_override is not allowed for control-plane installation" >&2
      exit 1
    }
  done
  compose_override=$(env | sed -n 's/^\(COMPOSE_[A-Za-z0-9_]*\)=.*/\1/p' | sed -n '1p')
  [ -z "$compose_override" ] || {
    echo "$compose_override is not allowed for control-plane installation" >&2
    exit 1
  }
  signature_override=$(env | sed -n '/^\(COSIGN\|SIGSTORE\|TUF\)_[A-Za-z0-9_]*=/ {
    s/=.*//
    p
    q
  }')
  [ -z "$signature_override" ] || {
    echo "$signature_override is not allowed for control-plane installation" >&2
    exit 1
  }
  # The privileged workflow never trusts caller-selected temporary or Docker
  # targets. Use root's explicitly selected Docker configuration and force
  # every Docker operation to the local default context.
  unset TMPDIR DOCKER_DEFAULT_PLATFORM CURL_HOME
  HOME=/root
  export HOME
fi

if [ "${PREFIX:-/usr/local}" != /usr/local ]; then
  echo "PREFIX must be /usr/local because the packaged systemd units use that path" >&2
  exit 1
fi

case "$detected_system" in
  Linux) operating_system=linux ;;
  Darwin) operating_system=darwin ;;
  *) echo "Laneway packages support Linux and macOS only" >&2; exit 1 ;;
esac
if [ "$operating_system" = darwin ] && \
  { [ "$install_control_plane" = true ] || [ "$prepare_control_plane" = true ] || [ "$upgrade_control_plane" = true ]; }; then
  echo "control-plane installation is Linux-only; macOS installs the foreground client" >&2
  exit 1
fi
detected_architecture=$(/usr/bin/uname -m)
case "$detected_architecture" in
  x86_64|amd64) architecture=amd64 ;;
  aarch64|arm64) architecture=arm64 ;;
  *)
    echo "unsupported architecture: $detected_architecture" >&2
    exit 1
    ;;
esac
privileged_linux_install=false
if [ "$operating_system" = linux ] && [ "$detected_uid" -eq 0 ]; then
  privileged_linux_install=true
  TMPDIR=/var/tmp
  export TMPDIR
fi

# A caller-selected repository is a trust-anchor substitution. A transport
# mirror is allowed only for signature-authenticated control-plane packages;
# Linux client installs that execute now or later through sudo reject both.
if [ "$control_plane_mode" = true ]; then
  [ "${LANEWAY_REPOSITORY+x}" != x ] || {
    echo "LANEWAY_REPOSITORY is not allowed for control-plane installation" >&2
    exit 1
  }
elif [ "$operating_system" = linux ] && \
  { [ "$detected_uid" -eq 0 ] || [ -z "${DESTDIR:-}" ]; }; then
  for release_override in LANEWAY_REPOSITORY LANEWAY_RELEASE_BASE_URL; do
    case "$release_override" in
      LANEWAY_REPOSITORY) release_override_present=${LANEWAY_REPOSITORY+x} ;;
      LANEWAY_RELEASE_BASE_URL) release_override_present=${LANEWAY_RELEASE_BASE_URL+x} ;;
    esac
    [ "$release_override_present" != x ] || {
      echo "$release_override is not allowed for privileged Linux client installation" >&2
      exit 1
    }
  done
fi
missing=
checksum_command=sha256sum
if [ "$operating_system" = darwin ]; then checksum_command=shasum; fi
for command in awk base64 curl date find grep mktemp readlink sed "$checksum_command" tar wc; do
  command -v "$command" >/dev/null 2>&1 || add_missing "$command"
done
if [ "$privileged_linux_install" = true ]; then
  for command in chmod chown stat; do
    command -v "$command" >/dev/null 2>&1 || add_missing "$command"
  done
fi

if [ "$operating_system" = darwin ] && \
  [ "$install_control_plane" = false ] && [ "$prepare_control_plane" = false ] && [ "$upgrade_control_plane" = false ]; then
  [ "$detected_uid" -ne 0 ] || add_missing "a normal macOS user (do not run the client installer with sudo)"
  command -v sudo >/dev/null 2>&1 || add_missing sudo
fi
if [ "$operating_system" = linux ] && [ -z "${DESTDIR:-}" ] && [ "$detected_uid" -ne 0 ] && \
  [ "$install_control_plane" = false ] && [ "$prepare_control_plane" = false ] && [ "$upgrade_control_plane" = false ]; then
  command -v sudo >/dev/null 2>&1 || add_missing sudo
fi

if [ "$control_plane_mode" = true ]; then
  [ -z "${DESTDIR:-}" ] || { echo "control-plane modes cannot be combined with DESTDIR" >&2; exit 1; }
  [ "$detected_uid" -eq 0 ] || add_missing "root privileges (run with sudo)"
  for command in age chmod chown dirname install mkdir mv stat sync; do
    command -v "$command" >/dev/null 2>&1 || add_missing "$command"
  done
  if [ ! -d /root ] || [ -L /root ] || [ "$(stat -c '%u:%g' /root 2>/dev/null || true)" != 0:0 ] || \
    [ "$((0$(stat -c %a /root 2>/dev/null || echo 777) & 022))" -ne 0 ]; then
    add_missing "/root as a real root-owned directory not writable by group or other"
  fi
fi
if [ "$install_control_plane" = true ] || [ "$prepare_control_plane" = true ]; then
  command -v age-keygen >/dev/null 2>&1 || add_missing "age-keygen"
  if [ ! -d /dev/shm ] || [ -L /dev/shm ] || \
    [ "$(stat -c '%a:%u:%g' /dev/shm 2>/dev/null || true)" != 1777:0:0 ] || \
    { command -v awk >/dev/null 2>&1 && ! awk '$2 == "/dev/shm" && $3 == "tmpfs" { found=1 } END { exit !found }' /proc/mounts; }; then
    add_missing "/dev/shm mounted as root-owned mode 1777 tmpfs (required for memory-only offline-root generation)"
  fi
fi
if [ "$upgrade_control_plane" = true ]; then
  upgrade_destination=${LANEWAY_DEPLOY_DIR:-/opt/laneway}
  command -v setsid >/dev/null 2>&1 || add_missing setsid
  canonical_deployment_path "$upgrade_destination" || add_missing \
    "a canonical safe absolute LANEWAY_DEPLOY_DIR"
  if [ -n "$missing" ]; then
    echo "Laneway pre-check found missing or incompatible prerequisites:" >&2
    printf '%s\n' "$missing" | while IFS= read -r item; do printf '  - %s\n' "$item" >&2; done
    echo "Install the listed prerequisites and rerun; no deployment changes were made." >&2
    exit 1
  fi
  acquire_upgrade_lock
fi
if [ "$install_control_plane" = true ] || [ "$upgrade_control_plane" = true ]; then
  trusted_docker_config=/root/.docker
  if [ -e "$trusted_docker_config" ] || [ -L "$trusted_docker_config" ]; then
    [ -d "$trusted_docker_config" ] && [ ! -L "$trusted_docker_config" ] && \
      [ "$(stat -c '%u:%g' "$trusted_docker_config")" = 0:0 ] && \
      [ "$((0$(stat -c %a "$trusted_docker_config") & 022))" -eq 0 ] || \
      add_missing "/root/.docker as a real root-owned directory not writable by group or other"
  fi
  export DOCKER_CONFIG=$trusted_docker_config
  for command in docker getent ss; do
    command -v "$command" >/dev/null 2>&1 || add_missing "$command"
  done
  if command -v docker >/dev/null 2>&1; then
    docker --context default compose version >/dev/null 2>&1 || add_missing "Docker Compose v2"
    docker_version=$(docker --context default version --format '{{.Server.Version}}' 2>/dev/null || true)
    if [ -z "$docker_version" ]; then
      add_missing "a running Docker Engine daemon"
    elif command -v awk >/dev/null 2>&1 && ! version_at_least "$docker_version" 26.0.0; then
      add_missing "Docker Engine 26 or newer (found $docker_version)"
    fi
  fi
fi
if [ -n "$missing" ]; then
  echo "Laneway pre-check found missing or incompatible prerequisites:" >&2
  printf '%s\n' "$missing" | while IFS= read -r item; do printf '  - %s\n' "$item" >&2; done
  echo "Install the listed prerequisites and rerun; no deployment changes were made." >&2
  exit 1
fi
if [ "$release" = latest ]; then
  latest_url=$(curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --fail --location --silent --show-error \
    --header 'Cache-Control: no-cache' --header 'Pragma: no-cache' \
    --output /dev/null \
    --write-out '%{url_effective}' \
    "https://github.com/$repository/releases/latest?laneway_cache_bust=$(date +%s)")
  default_tag=${latest_url##*/}
else
  default_tag=$release
fi
if [ "$control_plane_mode" = true ]; then
  echo "Laneway pre-check: required host prerequisites are available." >&2
  if [ "$quick_control_plane" = true ] || [ "${LANEWAY_NONINTERACTIVE:-false}" = true ]; then
    selected_tag=$default_tag
  else
    printf 'Stable release tag [%s]: ' "$default_tag" >&2
    IFS= read -r selected_tag || { echo "input ended while reading the release tag" >&2; exit 1; }
    [ -n "$selected_tag" ] || selected_tag=$default_tag
  fi
  case "$selected_tag" in v*) ;; *) selected_tag=v$selected_tag ;; esac
  printf '%s\n' "$selected_tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || {
    echo "control-plane release must be a stable vMAJOR.MINOR.PATCH tag" >&2
    exit 1
  }
  release=$selected_tag
else
  case "$default_tag" in v*) release=$default_tag ;; *) release=v$default_tag ;; esac
  printf '%s\n' "$release" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || {
    echo "release must be latest or a stable vMAJOR.MINOR.PATCH tag" >&2
    exit 1
  }
fi

asset="laneway_${operating_system}_${architecture}.tar.gz"
if [ -n "${LANEWAY_RELEASE_BASE_URL:-}" ]; then
  base_url=${LANEWAY_RELEASE_BASE_URL%/}
elif [ "$release" = latest ]; then
  base_url="https://github.com/$repository/releases/latest/download"
else
  base_url="https://github.com/$repository/releases/download/$release"
fi
if [ "$control_plane_mode" = true ] || [ "$privileged_linux_install" = true ]; then
  trusted_temporary_parent=/var/tmp
  [ -d "$trusted_temporary_parent" ] && [ ! -L "$trusted_temporary_parent" ] && \
    [ "$(stat -c '%a:%u:%g' "$trusted_temporary_parent" 2>/dev/null || true)" = 1777:0:0 ] || {
      echo "privileged installation requires root-owned mode 1777 /var/tmp" >&2
      exit 1
    }
  download_dir=$(mktemp -d "$trusted_temporary_parent/laneway-install.XXXXXX")
  chmod 0700 "$download_dir"
  chown 0:0 "$download_dir"
  [ -d "$download_dir" ] && [ ! -L "$download_dir" ] && \
    [ "$(stat -c '%a:%u:%g' "$download_dir")" = 700:0:0 ] || {
      echo "could not create a protected privileged download directory" >&2
      exit 1
    }
else
  download_dir=$(mktemp -d)
fi

if [ "$install_control_plane" = true ] || [ "$prepare_control_plane" = true ] || [ "$upgrade_control_plane" = true ]; then
  if ! select_cosign; then
    echo "Laneway control-plane installation requires the pinned signature verifier." >&2
    exit 1
  fi
fi

curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --fail --location --silent --show-error \
  "$base_url/$asset" -o "$download_dir/$asset"
curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --fail --location --silent --show-error \
  "$base_url/checksums.txt" -o "$download_dir/checksums.txt"
if [ "$install_control_plane" = true ] || [ "$prepare_control_plane" = true ] || [ "$upgrade_control_plane" = true ]; then
  curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --fail --location --silent --show-error \
    "$base_url/checksums.sigstore.json" -o "$download_dir/checksums.sigstore.json"
  if [ -n "$cosign_bin" ] && "$cosign_bin" verify-blob --bundle "$download_dir/checksums.sigstore.json" \
      --certificate-identity "https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/$release" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "$download_dir/checksums.txt" >/dev/null; then
    :
  else
    echo "Laneway verification: release checksum signature verification failed." >&2
    exit 1
  fi
  curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --fail --location --silent --show-error \
    "$base_url/bootstrap-artifacts.toml" -o "$download_dir/bootstrap-artifacts.toml"
  curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --fail --location --silent --show-error \
    "$base_url/image-digests.txt" -o "$download_dir/image-digests.txt"
  (
    cd "$download_dir"
    grep '  bootstrap-artifacts.toml$' checksums.txt > bootstrap-artifacts-checksum.txt
    test "$(wc -l < bootstrap-artifacts-checksum.txt)" -eq 1
    sha256sum -c bootstrap-artifacts-checksum.txt >/dev/null
    grep '  image-digests.txt$' checksums.txt > image-digests-checksum.txt
    test "$(wc -l < image-digests-checksum.txt)" -eq 1
    sha256sum -c image-digests-checksum.txt >/dev/null
  ) || {
    echo "Laneway verification: signed release metadata is missing or invalid." >&2
    exit 1
  }
fi
(
  cd "$download_dir"
  grep "  $asset\$" checksums.txt > selected-checksum.txt
  test "$(wc -l < selected-checksum.txt)" -eq 1
  if [ "$operating_system" = darwin ]; then
    shasum -a 256 -c selected-checksum.txt
  else
    sha256sum -c selected-checksum.txt
  fi
)
if [ "$operating_system" = darwin ] &&
  tar -tzf "$download_dir/$asset" laneway/bin/lanewayd >/dev/null 2>&1; then
  command -v cosign >/dev/null || {
    echo "Cosign is required to verify the bundled macOS client and node." >&2
    exit 1
  }
  curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --fail --location --silent --show-error \
    "$base_url/checksums.sigstore.json" -o "$download_dir/checksums.sigstore.json"
  (
    for override in $(env | sed -n -E 's/^((COSIGN|SIGSTORE|TUF)_[a-zA-Z0-9_]*)=.*/\1/p'); do
      unset "$override"
    done
    cosign verify-blob --bundle "$download_dir/checksums.sigstore.json" \
      --certificate-identity "https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/$release" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "$download_dir/checksums.txt"
  ) || {
    echo "Laneway verification: release checksum signature verification failed." >&2
    exit 1
  }
fi
(
  cd "$download_dir"
  tar -xzf "$asset"
)
if { [ "$install_control_plane" = true ] || [ "$prepare_control_plane" = true ] || [ "$upgrade_control_plane" = true ]; } && \
  { [ ! -f "$download_dir/laneway/deploy/compose/install-control-plane.sh" ] || \
    [ ! -f "$download_dir/laneway/deploy/compose/prepare-control-plane.sh" ]; }; then
    echo "release $release predates the requested control-plane workflow; select a newer stable tag" >&2
  exit 1
fi
if [ "$upgrade_control_plane" = true ] && \
  [ ! -f "$download_dir/laneway/deploy/compose/upgrade-control-plane.sh" ]; then
  echo "release $release predates control-plane upgrades; select a newer stable tag" >&2
  exit 1
fi
if [ "$operating_system" = darwin ]; then
  "$download_dir/laneway/bin/laneway" configure --yes
  "$download_dir/laneway/bin/laneway" configure --check
  echo "Laneway $release is ready."
  echo "Next: ask your administrator for a user token, then run:"
  echo "  laneway login ${LANEWAY_DOMAIN:-YOUR_DOMAIN}"
  echo "  laneway connect ${LANEWAY_DOMAIN:-YOUR_DOMAIN}"
  exit 0
fi

if [ "$upgrade_control_plane" = true ]; then
  package_dir=$download_dir/laneway
  preflight_protocol=$package_dir/CONTROL-PLANE-UPGRADE-PREFLIGHT
  if [ ! -f "$package_dir/VERSION" ] || [ -L "$package_dir/VERSION" ] || \
    [ "$(sed -n '1p' "$package_dir/VERSION")" != "${release#v}" ] || \
    [ ! -f "$package_dir/install.sh" ] || [ -L "$package_dir/install.sh" ] || \
    [ ! -f "$package_dir/bin/laneway" ] || [ -L "$package_dir/bin/laneway" ] || \
    [ ! -x "$package_dir/bin/laneway" ] || \
    [ ! -f "$package_dir/deploy/compose/upgrade-control-plane.sh" ] || \
    [ -L "$package_dir/deploy/compose/upgrade-control-plane.sh" ] || \
    [ ! -f "$preflight_protocol" ] || [ -L "$preflight_protocol" ] || \
    [ "$(wc -l < "$preflight_protocol")" -ne 1 ] || \
    [ "$(sed -n '1p' "$preflight_protocol")" != laneway-control-upgrade-preflight-v1 ]; then
    echo "verified release package is missing safe control-plane upgrade inputs" >&2
    exit 1
  fi
  if ! run_interruptible_upgrade_child env -u ENV -u BASH_ENV -u CDPATH -u IFS -u DOCKER_CONFIG \
    -u LANEWAY_RELEASE_BASE_URL -u LANEWAY_REPOSITORY -u LANEWAY_COSIGN_BIN \
    -u LANEWAY_CHECKSUM_SIGNATURE_VERIFIED -u LANEWAY_CONTROL_COMMAND -u LANEWAY_COMMAND \
    PATH="$package_dir/bin:$PATH" TMPDIR=/var/tmp \
    LANEWAY_DEPLOY_DIR="$upgrade_destination" \
    LANEWAY_AUTHENTICATED_COSIGN_BIN="$cosign_bin" \
    LANEWAY_AUTHENTICATED_RELEASE_BASE_URL="$base_url" \
    LANEWAY_BOOTSTRAP_ARTIFACTS_FILE="$download_dir/bootstrap-artifacts.toml" \
    LANEWAY_LIFECYCLE_LOCK_TOKEN="$lock_token" \
    LANEWAY_LIFECYCLE_LOCK_ROLE=observer \
    LANEWAY_UPGRADE_PREFLIGHT_ONLY=true \
    sh "$package_dir/deploy/compose/upgrade-control-plane.sh"; then
    echo "verified release package failed control-plane preflight" >&2
    exit 1
  fi
  validate_upgrade_lock || {
    echo "lifecycle lock changed during candidate preflight" >&2
    exit 1
  }
fi

if [ "$control_plane_mode" = true ]; then
  publish_cosign || {
    echo "Laneway verification: could not publish the pinned verifier safely." >&2
    exit 1
  }
fi

if [ -z "${DESTDIR:-}" ] && [ "$detected_uid" -ne 0 ]; then
  sudo env -u ENV -u BASH_ENV -u CDPATH -u IFS \
    -u LANEWAY_RELEASE_BASE_URL -u LANEWAY_REPOSITORY -u LANEWAY_COSIGN_BIN \
    -u LANEWAY_CHECKSUM_SIGNATURE_VERIFIED -u LANEWAY_CONTROL_COMMAND -u LANEWAY_COMMAND \
    DESTDIR= PREFIX=/usr/local \
    sh "$download_dir/laneway/install.sh"
elif [ "$upgrade_control_plane" = true ]; then
  run_interruptible_upgrade_child env -u ENV -u BASH_ENV -u CDPATH -u IFS -u DOCKER_CONFIG \
    -u LANEWAY_UPGRADE_PREFLIGHT_ONLY -u LANEWAY_RELEASE_BASE_URL \
    -u LANEWAY_REPOSITORY -u LANEWAY_COSIGN_BIN -u LANEWAY_CHECKSUM_SIGNATURE_VERIFIED \
    -u LANEWAY_CONTROL_COMMAND -u LANEWAY_COMMAND \
    DESTDIR= PREFIX=/usr/local TMPDIR=/var/tmp \
    LANEWAY_DEPLOY_DIR="$upgrade_destination" \
    LANEWAY_LIFECYCLE_LOCK_TOKEN="$lock_token" LANEWAY_LIFECYCLE_LOCK_ROLE=owner \
    sh "$download_dir/laneway/install.sh"
  validate_upgrade_lock || {
    echo "lifecycle lock changed during package installation" >&2
    exit 1
  }
else
  env -u ENV -u BASH_ENV -u CDPATH -u IFS \
    -u LANEWAY_RELEASE_BASE_URL -u LANEWAY_REPOSITORY -u LANEWAY_COSIGN_BIN \
    -u LANEWAY_CHECKSUM_SIGNATURE_VERIFIED -u LANEWAY_CONTROL_COMMAND -u LANEWAY_COMMAND \
    DESTDIR="${DESTDIR:-}" PREFIX=/usr/local sh "$download_dir/laneway/install.sh"
fi

if [ "$install_control_plane" = true ]; then
  control_noninteractive=${LANEWAY_NONINTERACTIVE:-false}
  control_confirmation=${LANEWAY_CONFIRM:-}
  if [ "$quick_control_plane" = true ]; then
    control_noninteractive=true
    control_confirmation=deploy
  fi
  env -u ENV -u BASH_ENV -u CDPATH -u IFS -u DOCKER_CONFIG \
    -u LANEWAY_RELEASE_BASE_URL -u LANEWAY_REPOSITORY -u LANEWAY_COSIGN_BIN \
    -u LANEWAY_CHECKSUM_SIGNATURE_VERIFIED -u LANEWAY_CONTROL_COMMAND -u LANEWAY_COMMAND \
    LANEWAY_VERSION="${release#v}" \
    LANEWAY_PRODUCTION_MODE="$production_mode" \
    LANEWAY_NONINTERACTIVE="$control_noninteractive" \
    LANEWAY_CONFIRM="$control_confirmation" \
    LANEWAY_DOMAIN="${LANEWAY_DOMAIN:-}" \
    sh /usr/local/share/laneway/deploy/compose/install-control-plane.sh
  exit $?
fi
if [ "$prepare_control_plane" = true ]; then
  output=${LANEWAY_RECOVERY_KIT_DIR:-/root/laneway-recovery-kit-$(date -u +%Y%m%dT%H%M%SZ)}
  env -u ENV -u BASH_ENV -u CDPATH -u IFS -u DOCKER_CONFIG \
    -u LANEWAY_RELEASE_BASE_URL -u LANEWAY_REPOSITORY -u LANEWAY_COSIGN_BIN \
    -u LANEWAY_CHECKSUM_SIGNATURE_VERIFIED -u LANEWAY_CONTROL_COMMAND -u LANEWAY_COMMAND \
    sh /usr/local/share/laneway/deploy/compose/prepare-control-plane.sh "$output"
  exit $?
fi
if [ "$upgrade_control_plane" = true ]; then
  set +e
  run_interruptible_upgrade_child env -u ENV -u BASH_ENV -u CDPATH -u IFS -u DOCKER_CONFIG \
    -u LANEWAY_RELEASE_BASE_URL -u LANEWAY_REPOSITORY -u LANEWAY_COSIGN_BIN \
    -u LANEWAY_CHECKSUM_SIGNATURE_VERIFIED -u LANEWAY_CONTROL_COMMAND -u LANEWAY_COMMAND \
    TMPDIR=/var/tmp LANEWAY_DEPLOY_DIR="$upgrade_destination" \
    LANEWAY_AUTHENTICATED_RELEASE_BASE_URL="$base_url" \
    LANEWAY_BOOTSTRAP_ARTIFACTS_FILE="$download_dir/bootstrap-artifacts.toml" \
    LANEWAY_LIFECYCLE_LOCK_TOKEN="$lock_token" LANEWAY_LIFECYCLE_LOCK_ROLE=owner \
    LANEWAY_UPGRADE_PREFLIGHT_ONLY=false \
    sh /usr/local/share/laneway/deploy/compose/upgrade-control-plane.sh
  update_status=$?
  set -e
  # The installed updater owns the same handoff and normally removes it. The
  # outer trap is deliberately idempotent for failures before or during it.
  exit "$update_status"
fi
