#!/bin/sh
set -eu

repository=${LANEWAY_REPOSITORY:-Doout/laneway}
release=${LANEWAY_VERSION:-latest}

die() {
  echo "Laneway client installer: $*" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || die "required command is missing: curl"
command -v shasum >/dev/null 2>&1 || die "required command is missing: shasum"
command -v mktemp >/dev/null 2>&1 || die "required command is missing: mktemp"
command -v sudo >/dev/null 2>&1 || die "required command is missing: sudo"

[ "$(uname -s)" = Darwin ] || die "this installer is for the macOS user client"
[ "$(id -u)" -ne 0 ] || die "run as your normal macOS user; the verified client will request sudo once"

case "$(uname -m)" in
  arm64|aarch64) architecture=arm64 ;;
  x86_64|amd64) architecture=amd64 ;;
  *) die "unsupported Mac architecture: $(uname -m)" ;;
esac

case "$release" in
  latest)
    latest_url=$(curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
      --header 'Cache-Control: no-cache' --header 'Pragma: no-cache' \
      --output /dev/null --write-out '%{url_effective}' \
      "https://github.com/$repository/releases/latest?laneway_cache_bust=$(date +%s)")
    release=${latest_url##*/}
    ;;
  v*) ;;
  *) release=v$release ;;
esac
printf '%s\n' "$release" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || \
  die "release must be latest or a stable semantic tag"

if [ -n "${LANEWAY_RELEASE_BASE_URL:-}" ]; then
  base_url=${LANEWAY_RELEASE_BASE_URL%/}
else
  base_url="https://github.com/$repository/releases/download/$release"
fi
asset=laneway_darwin_$architecture
download_dir=$(mktemp -d)
trap 'find "$download_dir" -depth -delete' EXIT HUP INT TERM

echo "Downloading Laneway $release for macOS $architecture..."
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  "$base_url/$asset" -o "$download_dir/$asset"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  "$base_url/checksums.txt" -o "$download_dir/checksums.txt"

grep "  $asset\$" "$download_dir/checksums.txt" > "$download_dir/selected-checksum.txt"
[ "$(wc -l < "$download_dir/selected-checksum.txt" | tr -d ' ')" = 1 ] || \
  die "release checksum manifest does not contain exactly one $asset entry"
(
  cd "$download_dir"
  shasum -a 256 -c selected-checksum.txt
) || die "downloaded client failed checksum verification"

chmod 0755 "$download_dir/$asset"
"$download_dir/$asset" configure --yes
"$download_dir/$asset" configure --check

echo "Laneway $release is ready."
echo "Next: ask your administrator for a user token, then run:"
echo "  laneway login YOUR_DOMAIN"
echo "  laneway connect YOUR_DOMAIN"
