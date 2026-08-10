#!/bin/sh
set -eu

repository=${LANEWAY_REPOSITORY:-Doout/laneway}
release=${LANEWAY_VERSION:-latest}
install_control_plane=false
prepare_control_plane=false
upgrade_control_plane=false
production_mode=false
quick_control_plane=false
cosign_bin=
cosign_is_fallback=false

add_missing() {
  if [ -n "${missing:-}" ]; then missing="$missing
$1"; else missing=$1; fi
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
  host_cosign=$(command -v cosign 2>/dev/null || true)
  if [ -n "$host_cosign" ]; then
    host_version=$(cosign_version "$host_cosign")
    if [ -n "$host_version" ] && version_at_least "$host_version" 3.1.3; then
      cosign_bin=$host_cosign
      return
    fi
    echo "Laneway pre-check: ignoring incompatible host Cosign (${host_version:-unversioned}); using pinned v3.1.3" >&2
  else
    echo "Laneway pre-check: host Cosign is missing; using pinned v3.1.3" >&2
  fi
  case "$architecture" in
    amd64) cosign_sha=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 ;;
    arm64) cosign_sha=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a ;;
    *) echo "no pinned Cosign verifier for architecture: $architecture" >&2; return 1 ;;
  esac
  cosign_bin=$download_dir/cosign-v3.1.3
  if ! curl --fail --location --silent --show-error \
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
  cosign_is_fallback=true
}

case "${1:-}" in
  '')
    if [ -n "${LANEWAY_DOMAIN:-}" ] && [ "$(uname -s)" = Linux ]; then
      install_control_plane=true
      quick_control_plane=true
    fi
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
With --control-plane, select a stable release tag, verify its signed release,
install it, and start the interactive hardened control-plane installer.
The default quick profile warns on unavailable signature services and writes a
production checklist. Add --production to make all signature checks fail closed.
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

if [ "${PREFIX:-/usr/local}" != /usr/local ]; then
  echo "PREFIX must be /usr/local because the packaged systemd units use that path" >&2
  exit 1
fi

case "$(uname -s)" in
  Linux) operating_system=linux ;;
  Darwin) operating_system=darwin ;;
  *) echo "Laneway packages support Linux and macOS only" >&2; exit 1 ;;
esac
if [ "$operating_system" = darwin ] && \
  { [ "$install_control_plane" = true ] || [ "$prepare_control_plane" = true ] || [ "$upgrade_control_plane" = true ]; }; then
  echo "control-plane installation is Linux-only; macOS installs the foreground client" >&2
  exit 1
fi
case "$(uname -m)" in
  x86_64|amd64) architecture=amd64 ;;
  aarch64|arm64) architecture=arm64 ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac
missing=
checksum_command=sha256sum
if [ "$operating_system" = darwin ]; then checksum_command=shasum; fi
for command in awk base64 curl date find grep mktemp readlink sed "$checksum_command" tar wc; do
  command -v "$command" >/dev/null 2>&1 || add_missing "$command"
done

if [ "$operating_system" = darwin ] && \
  [ "$install_control_plane" = false ] && [ "$prepare_control_plane" = false ] && [ "$upgrade_control_plane" = false ]; then
  [ "$(id -u)" -ne 0 ] || add_missing "a normal macOS user (do not run the client installer with sudo)"
  command -v sudo >/dev/null 2>&1 || add_missing sudo
fi
if [ "$operating_system" = linux ] && [ -z "${DESTDIR:-}" ] && [ "$(id -u)" -ne 0 ] && \
  [ "$install_control_plane" = false ] && [ "$prepare_control_plane" = false ] && [ "$upgrade_control_plane" = false ]; then
  command -v sudo >/dev/null 2>&1 || add_missing sudo
fi

if [ "$install_control_plane" = true ] || [ "$prepare_control_plane" = true ] || [ "$upgrade_control_plane" = true ]; then
  [ -z "${DESTDIR:-}" ] || { echo "control-plane modes cannot be combined with DESTDIR" >&2; exit 1; }
  [ "$(id -u)" -eq 0 ] || add_missing "root privileges (run with sudo)"
  for command in age chmod chown dirname install stat sync; do
    command -v "$command" >/dev/null 2>&1 || add_missing "$command"
  done
fi
if [ "$install_control_plane" = true ] || [ "$prepare_control_plane" = true ]; then
  command -v age-keygen >/dev/null 2>&1 || add_missing "age-keygen"
  if [ ! -d /dev/shm ] || [ -L /dev/shm ] || \
    { command -v awk >/dev/null 2>&1 && ! awk '$2 == "/dev/shm" && $3 == "tmpfs" { found=1 } END { exit !found }' /proc/mounts; }; then
    add_missing "/dev/shm mounted as tmpfs (required for memory-only offline-root generation)"
  fi
fi
if [ "$install_control_plane" = true ] || [ "$upgrade_control_plane" = true ]; then
  for command in docker getent ss; do
    command -v "$command" >/dev/null 2>&1 || add_missing "$command"
  done
  if command -v docker >/dev/null 2>&1; then
    docker compose version >/dev/null 2>&1 || add_missing "Docker Compose v2"
    docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)
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
  latest_url=$(curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
    --header 'Cache-Control: no-cache' --header 'Pragma: no-cache' \
    --output /dev/null \
    --write-out '%{url_effective}' \
    "https://github.com/$repository/releases/latest?laneway_cache_bust=$(date +%s)")
  default_tag=${latest_url##*/}
else
  default_tag=$release
fi
if [ "$install_control_plane" = true ] || [ "$prepare_control_plane" = true ] || [ "$upgrade_control_plane" = true ]; then
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
download_dir=$(mktemp -d)
trap 'find "$download_dir" -depth -delete' EXIT HUP INT TERM

if [ "$install_control_plane" = true ] || [ "$prepare_control_plane" = true ] || [ "$upgrade_control_plane" = true ]; then
  if ! select_cosign && [ "$production_mode" = true ]; then
    echo "Laneway production install requires a working pinned signature verifier." >&2
    exit 1
  fi
fi

curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  "$base_url/$asset" -o "$download_dir/$asset"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  "$base_url/checksums.txt" -o "$download_dir/checksums.txt"
if [ "$install_control_plane" = true ] || [ "$prepare_control_plane" = true ] || [ "$upgrade_control_plane" = true ]; then
  curl --fail --location --silent --show-error \
    "$base_url/checksums.sigstore.json" -o "$download_dir/checksums.sigstore.json"
  checksum_signature_verified=false
  if [ -n "$cosign_bin" ] && "$cosign_bin" verify-blob --bundle "$download_dir/checksums.sigstore.json" \
      --certificate-identity "https://github.com/$repository/.github/workflows/release.yml@refs/tags/$release" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "$download_dir/checksums.txt" >/dev/null; then
    checksum_signature_verified=true
  elif [ "$production_mode" = true ]; then
    echo "Laneway production install: release checksum signature verification failed." >&2
    exit 1
  else
    echo "WARNING: checksum signature could not be verified; archive checksum validation will still run." >&2
  fi
  curl --fail --location --silent --show-error \
    "$base_url/bootstrap-artifacts.toml" -o "$download_dir/bootstrap-artifacts.toml"
  (
    cd "$download_dir"
    grep '  bootstrap-artifacts.toml$' checksums.txt > bootstrap-artifacts-checksum.txt
    test "$(wc -l < bootstrap-artifacts-checksum.txt)" -eq 1
    sha256sum -c bootstrap-artifacts-checksum.txt >/dev/null
  ) || {
    echo "Laneway verification: signed bootstrap artifact manifest is missing or invalid." >&2
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

if [ -z "${DESTDIR:-}" ] && [ "$(id -u)" -ne 0 ]; then
  sudo env DESTDIR= PREFIX=/usr/local sh "$download_dir/laneway/install.sh"
else
  env DESTDIR="${DESTDIR:-}" PREFIX=/usr/local sh "$download_dir/laneway/install.sh"
fi

if [ "$cosign_is_fallback" = true ] && [ -n "$cosign_bin" ]; then
  install -D -m 0755 -o 0 -g 0 "$cosign_bin" /usr/local/libexec/laneway/cosign-v3.1.3
  cosign_bin=/usr/local/libexec/laneway/cosign-v3.1.3
fi

if [ "$install_control_plane" = true ]; then
  control_noninteractive=${LANEWAY_NONINTERACTIVE:-false}
  control_confirmation=${LANEWAY_CONFIRM:-}
  if [ "$quick_control_plane" = true ]; then
    control_noninteractive=true
    control_confirmation=deploy
  fi
  exec env LANEWAY_VERSION="${release#v}" LANEWAY_COSIGN_BIN="$cosign_bin" \
    LANEWAY_BOOTSTRAP_ARTIFACTS_FILE="$download_dir/bootstrap-artifacts.toml" \
    LANEWAY_PRODUCTION_MODE="$production_mode" \
    LANEWAY_CHECKSUM_SIGNATURE_VERIFIED="${checksum_signature_verified:-false}" \
    LANEWAY_NONINTERACTIVE="$control_noninteractive" \
    LANEWAY_CONFIRM="$control_confirmation" \
    LANEWAY_DOMAIN="${LANEWAY_DOMAIN:-}" \
    sh /usr/local/share/laneway/deploy/compose/install-control-plane.sh
fi
if [ "$prepare_control_plane" = true ]; then
  output=${LANEWAY_RECOVERY_KIT_DIR:-/root/laneway-recovery-kit-$(date -u +%Y%m%dT%H%M%SZ)}
  exec env LANEWAY_COSIGN_BIN="$cosign_bin" \
    sh /usr/local/share/laneway/deploy/compose/prepare-control-plane.sh "$output"
fi
if [ "$upgrade_control_plane" = true ]; then
  exec env LANEWAY_COSIGN_BIN="$cosign_bin" \
    LANEWAY_BOOTSTRAP_ARTIFACTS_FILE="$download_dir/bootstrap-artifacts.toml" \
    sh /usr/local/share/laneway/deploy/compose/upgrade-control-plane.sh
fi
