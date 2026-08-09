#!/bin/sh
set -eu

repository=${LANEWAY_REPOSITORY:-Doout/laneway}
release=${LANEWAY_VERSION:-latest}
install_control_plane=false
prepare_control_plane=false

case "${1:-}" in
  '') ;;
  --control-plane) install_control_plane=true; shift ;;
  --prepare-control-plane) prepare_control_plane=true; shift ;;
  -h|--help)
    cat <<'EOF'
usage: sh install.sh [--control-plane | --prepare-control-plane]

Without options, install the latest Laneway binaries and packaged files.
With --control-plane, select a stable release tag, verify its signed release,
install it, and start the interactive hardened control-plane installer.
With --prepare-control-plane, create a recovery kit and the limited input that
may be copied to a separate production control-plane server.
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

if [ "$(uname -s)" != Linux ]; then
  echo "Laneway packages currently support Linux only" >&2
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
for command in curl grep sha256sum tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command is missing: $command" >&2
    exit 1
  fi
done

if [ "$install_control_plane" = true ] || [ "$prepare_control_plane" = true ]; then
  [ -z "${DESTDIR:-}" ] || { echo "control-plane modes cannot be combined with DESTDIR" >&2; exit 1; }
  if ! command -v cosign >/dev/null 2>&1; then
    echo "cosign is required for a control-plane install" >&2
    exit 1
  fi
  if [ "$release" = latest ]; then
    latest_url=$(curl --fail --location --silent --show-error --output /dev/null \
      --write-out '%{url_effective}' "https://github.com/$repository/releases/latest")
    default_tag=${latest_url##*/}
  else
    default_tag=$release
  fi
  printf 'Stable release tag [%s]: ' "$default_tag" >&2
  IFS= read -r selected_tag || { echo "input ended while reading the release tag" >&2; exit 1; }
  [ -n "$selected_tag" ] || selected_tag=$default_tag
  case "$selected_tag" in v*) ;; *) selected_tag=v$selected_tag ;; esac
  printf '%s\n' "$selected_tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || {
    echo "control-plane release must be a stable vMAJOR.MINOR.PATCH tag" >&2
    exit 1
  }
  release=$selected_tag
fi

asset="laneway_linux_${architecture}.tar.gz"
if [ -n "${LANEWAY_RELEASE_BASE_URL:-}" ]; then
  base_url=${LANEWAY_RELEASE_BASE_URL%/}
elif [ "$release" = latest ]; then
  base_url="https://github.com/$repository/releases/latest/download"
else
  base_url="https://github.com/$repository/releases/download/$release"
fi
download_dir=$(mktemp -d)
trap 'find "$download_dir" -depth -delete' EXIT HUP INT TERM

curl --fail --location --silent --show-error \
  "$base_url/$asset" -o "$download_dir/$asset"
curl --fail --location --silent --show-error \
  "$base_url/checksums.txt" -o "$download_dir/checksums.txt"
if [ "$install_control_plane" = true ] || [ "$prepare_control_plane" = true ]; then
  curl --fail --location --silent --show-error \
    "$base_url/checksums.sigstore.json" -o "$download_dir/checksums.sigstore.json"
  cosign verify-blob --bundle "$download_dir/checksums.sigstore.json" \
    --certificate-identity "https://github.com/$repository/.github/workflows/release.yml@refs/tags/$release" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$download_dir/checksums.txt" >/dev/null
fi
(
  cd "$download_dir"
  grep "  $asset\$" checksums.txt > selected-checksum.txt
  test -s selected-checksum.txt
  sha256sum -c selected-checksum.txt
  tar -xzf "$asset"
)
if { [ "$install_control_plane" = true ] || [ "$prepare_control_plane" = true ]; } && \
  { [ ! -f "$download_dir/laneway/deploy/compose/install-control-plane.sh" ] || \
    [ ! -f "$download_dir/laneway/deploy/compose/prepare-control-plane.sh" ]; }; then
    echo "release $release predates the requested control-plane workflow; select a newer stable tag" >&2
  exit 1
fi
env DESTDIR="${DESTDIR:-}" PREFIX="/usr/local" \
  sh "$download_dir/laneway/install.sh"

if [ "$install_control_plane" = true ]; then
  exec env LANEWAY_VERSION="${release#v}" \
    sh /usr/local/share/laneway/deploy/compose/install-control-plane.sh
fi
if [ "$prepare_control_plane" = true ]; then
  output=${LANEWAY_RECOVERY_KIT_DIR:-/root/laneway-recovery-kit-$(date -u +%Y%m%dT%H%M%SZ)}
  exec sh /usr/local/share/laneway/deploy/compose/prepare-control-plane.sh "$output"
fi
