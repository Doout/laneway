#!/bin/sh
set -eu

repository=${LANEWAY_REPOSITORY:-Doout/laneway}
release=${LANEWAY_VERSION:-latest}

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
for command in curl sha256sum tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command is missing: $command" >&2
    exit 1
  fi
done

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
(
  cd "$download_dir"
  grep "  $asset\$" checksums.txt > selected-checksum.txt
  test -s selected-checksum.txt
  sha256sum -c selected-checksum.txt
  tar -xzf "$asset"
)
env DESTDIR="${DESTDIR:-}" PREFIX="/usr/local" \
  sh "$download_dir/laneway/install.sh"
