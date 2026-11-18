#!/bin/sh
# Print only the Compose settings for a verified, immutable Rust release.
set -eu

die() { printf 'Rust Compose release: %s\n' "$*" >&2; exit 1; }
mode=settings
case "${1:-}" in
  --prepare) mode=prepare; shift ;;
  --install) mode=install; shift ;;
  --publish) mode=publish; shift ;;
esac
[ "$#" -eq 2 ] || die "usage: sh verify-rust-release.sh [--prepare | --install | --publish] vVERSION RELEASE_METADATA_DIRECTORY"
tag=$1
directory=$2
case "$tag" in *[!v0-9.]*) die "expected a stable release tag";; esac
printf '%s\n' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ||
  die "expected a stable release tag such as v1.2.3"
[ -d "$directory" ] || die "release metadata directory does not exist"
cosign=${LANEWAY_COSIGN_BIN:-cosign}
command -v "$cosign" >/dev/null 2>&1 || die "Cosign is required"
if command -v sha256sum >/dev/null 2>&1; then
  checksum() { sha256sum < "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  checksum() { shasum -a 256 < "$1"; }
else
  die "sha256sum or shasum is required"
fi

umask 077
work=$(mktemp -d)
trap 'find "$work" -depth -delete' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
set -- checksums.txt checksums.sigstore.json image-digests.txt
if [ "$mode" != settings ]; then set -- "$@" bootstrap-artifacts.toml; fi
for asset; do
  source_file=$directory/$asset
  [ -f "$source_file" ] && [ ! -L "$source_file" ] && [ -s "$source_file" ] ||
    die "missing or unsafe metadata file: $asset"
  cp -- "$source_file" "$work/$asset"
done

identity=https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/$tag
issuer=https://token.actions.githubusercontent.com
"$cosign" verify-blob --bundle "$work/checksums.sigstore.json" \
  --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" \
  "$work/checksums.txt" >&2 || die "checksum signature did not match $tag"

verify_asset() {
  asset=$1
  expected=$(awk -v name="$asset" '$2 == name || $2 == "*" name {
    count++
    digest = $1
  }
  END {
    if (count != 1) exit 1
    print digest
  }' "$work/checksums.txt") || die "expected exactly one signed checksum for $asset"
  printf '%s\n' "$expected" | grep -Eq '^[0-9a-f]{64}$' || die "invalid signed checksum for $asset"
  actual=$(checksum "$work/$asset") || die "could not hash $asset"
  [ "${actual%% *}" = "$expected" ] || die "$asset differs from its signed checksum"
}
verify_asset image-digests.txt
if [ "$mode" != settings ]; then verify_asset bootstrap-artifacts.toml; fi

verified_digest() {
  image=$1
  digest=$(awk -v prefix="$image@" 'index($0, prefix) == 1 {
    count++
    digest = substr($0, length(prefix) + 1)
  }
  END {
    if (count != 1) exit 1
    print digest
  }' "$work/image-digests.txt") || die "expected exactly one digest for $image"
  printf '%s\n' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$' ||
    die "invalid immutable digest for $image"
  [ "$digest" != sha256:0000000000000000000000000000000000000000000000000000000000000000 ] ||
    die "placeholder digest for $image"
  "$cosign" verify --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" \
    "$image@$digest" >/dev/null || die "image signature did not match $tag: $image"
  printf '%s\n' "$digest"
}

# Do not publish partial settings when any member fails.
controller=$(verified_digest ghcr.io/doout/laneway-controller-rust) || exit 1
relay=$(verified_digest ghcr.io/doout/laneway-relay-rust) || exit 1
exit_node=$(verified_digest ghcr.io/doout/laneway-exit-node-rust) || exit 1
case "$mode" in install|publish)
  admin=$(verified_digest ghcr.io/doout/laneway-admin) || exit 1
  connector=$(verified_digest ghcr.io/doout/lane-edge-rust) || exit 1
  ;;
esac
if [ "$mode" = publish ]; then
  verified_digest ghcr.io/doout/laneway-node-rust >/dev/null || exit 1
  # Each entry above must exist exactly once. No other runtime or duplicate
  # reference may be included in a newly published release.
  [ "$(awk 'END { print NR }' "$work/image-digests.txt")" -eq 6 ] ||
    die "expected exactly five Rust runtimes and the operator image"
fi
printf 'LANEWAY_RUST_VERSION=%s\nLANEWAY_RUST_CONTROLLER_IMAGE_DIGEST=%s\nLANEWAY_RUST_RELAY_IMAGE_DIGEST=%s\nLANEWAY_RUST_EXIT_NODE_IMAGE_DIGEST=%s\n' \
  "${tag#v}" "$controller" "$relay" "$exit_node"
case "$mode" in install|publish)
  printf 'LANEWAY_ADMIN_IMAGE_DIGEST=%s\nLANEWAY_RUST_CONNECTOR_IMAGE_DIGEST=%s\n' "$admin" "$connector"
  ;;
esac
if [ "$mode" = prepare ]; then cat "$work/bootstrap-artifacts.toml"; fi
