#!/bin/sh
set -eu

die() {
  printf '%s\n' "Laneway installer: $*" >&2
  exit 1
}

[ "$#" -le 1 ] || die 'usage: sh install-node.sh [vMAJOR.MINOR.PATCH]'
[ "$(/usr/bin/id -u)" -ne 0 ] || die 'run the per-user installer without sudo'

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die 'supported systems are Linux and macOS; on Windows use install-node.ps1' ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die 'supported architectures are amd64 and arm64' ;;
esac

command -v cosign >/dev/null || die 'cosign is required to authenticate the signed release'
[ -n "${HOME:-}" ] || die 'HOME is required'
bin_dir=$HOME/.local/bin
cli=laneway-native_${os}_${arch}
compat=laneway-compat_${os}_${arch}
node=lanewayd_${os}_${arch}
repository=Doout/laneway
release_url=https://github.com/$repository/releases
if [ "$#" -eq 1 ]; then
  version=$1
else
  latest_url=$(curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --header 'Cache-Control: no-cache' --header 'Pragma: no-cache' --output /dev/null \
    --write-out '%{url_effective}' "$release_url/latest?laneway_cache_bust=$(date +%s)") ||
    die 'could not resolve the latest release'
  case "$latest_url" in
    "$release_url/tag/"*) version=${latest_url#"$release_url/tag/"} ;;
    *) die 'latest release redirected to an unexpected URL' ;;
  esac
fi
printf '%s\n' "$version" | LC_ALL=C grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ||
  die 'a stable release tag is required'
base_url=$release_url/download/$version

umask 077
mkdir -p "$bin_dir"
staging=$(mktemp -d "$bin_dir/.laneway.XXXXXXXX")
lock=$bin_dir/.laneway-update-lock
lock_held=false
rollback=false
cleanup() {
  keep_backup=false
  if [ "$rollback" = true ]; then
    for name in laneway laneway-compat lanewayd; do
      case "$name" in
        laneway) asset=$cli ;;
        lanewayd) asset=$node ;;
        laneway-compat) asset=$compat ;;
      esac
      [ ! -e "$staging/$asset" ] || continue
      if [ -f "$staging/previous-$name" ]; then
        if ! mv -f -- "$staging/previous-$name" "$bin_dir/$name"; then
          printf 'Could not restore %s from %s\n' "$name" "$staging/previous-$name" >&2
          keep_backup=true
        fi
      else
        rm -f -- "$bin_dir/$name"
      fi
    done
  fi
  if [ "$lock_held" = true ]; then
    rmdir "$lock"
  fi
  if [ "$keep_backup" = false ]; then
    find "$staging" -depth -delete
  fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
for file in checksums.txt checksums.sigstore.json "$cli" "$node" "$compat"; do
  curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    "$base_url/$file" --output "$staging/$file"
done
(
  for override in $(env | sed -n -E 's/^((COSIGN|SIGSTORE|TUF)_[a-zA-Z0-9_]*)=.*/\1/p'); do
    unset "$override"
  done
  cosign verify-blob --bundle "$staging/checksums.sigstore.json" \
    --certificate-identity "https://github.com/$repository/.github/workflows/release.yml@refs/tags/$version" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$staging/checksums.txt"
) || die 'release signature verification failed'

(
  cd "$staging" || exit 1
  for asset in "$cli" "$node" "$compat"; do
    awk -v asset="$asset" '
      $2 == asset && NF == 2 && length($1) == 64 && $1 ~ /^[0-9a-f]+$/ { print; n++ }
      END { if (n != 1) exit 1 }
    ' checksums.txt || exit 1
  done > asset.sha256
  if [ "$os" = darwin ]; then
    shasum -a 256 -c asset.sha256
  else
    sha256sum -c asset.sha256
  fi
) || die 'executable checksum verification failed'

mkdir "$lock" || die "could not lock the installation at $lock"
lock_held=true
for name in laneway laneway-compat lanewayd; do
  destination=$bin_dir/$name
  if [ -L "$destination" ] || { [ -e "$destination" ] && [ ! -f "$destination" ]; }; then
    die "installation target must be a regular file path: $destination"
  fi
  if [ -f "$destination" ]; then
    ln "$destination" "$staging/previous-$name"
  fi
done
chmod 0755 "$staging/$cli" "$staging/$node" "$staging/$compat"
rollback=true
mv -f -- "$staging/$compat" "$bin_dir/laneway-compat"
mv -f -- "$staging/$node" "$bin_dir/lanewayd"
mv -f -- "$staging/$cli" "$bin_dir/laneway"
rollback=false
printf 'Installed laneway, lanewayd, and laneway-compat in %s\n' "$bin_dir"
if [ -f "$staging/previous-lanewayd" ]; then
  printf '%s\n' 'Restart any running lanewayd process to use the new version.'
fi
