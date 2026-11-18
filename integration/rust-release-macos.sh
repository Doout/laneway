#!/bin/sh
# Check the actual release archive on a matching native macOS host.
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: sh integration/rust-release-macos.sh ARCHIVE amd64|arm64 RELEASE_VERSION" >&2
  exit 2
fi
archive=$1
arch=$2
version=$3
case "$(uname -sm):$arch" in
  'Darwin x86_64:amd64'|'Darwin arm64:arm64') ;;
  *) echo "the macOS package probe requires the matching native architecture" >&2; exit 2 ;;
esac
install_probe=${LANEWAY_MACOS_ARCHIVE_INSTALL:-0}
utun_probe=${LANEWAY_MACOS_UTUN_TEST:-0}
case "$install_probe:$utun_probe" in
  0:0|1:0|1:1) ;;
  *) echo "the utun test requires LANEWAY_MACOS_ARCHIVE_INSTALL=1; use 0 or 1 for both settings" >&2; exit 2 ;;
esac
if [ "$install_probe" = 1 ]; then
  marker=/var/run/.laneway-isolated-macos-lab
  if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
    [ -f "$marker" ] && [ ! -L "$marker" ] && [ "$(stat -f '%u:%Lp' "$marker")" = 0:600 ] || {
      echo "the install probe requires a disposable hosted runner or root-owned 0600 $marker" >&2
      exit 2
    }
  fi
fi
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
standalone=$(dirname -- "$archive")/laneway_darwin_$arch
probe_dir=$(mktemp -d)
installed=false
client=/usr/local/bin/laneway
alias_path=/usr/local/bin/lane
helper=/Library/PrivilegedHelperTools/laneway-network-helper
runtime_dir='/Library/Application Support/Laneway'
cleanup() {
  if [ "$installed" = true ]; then
    sudo -n rm -f "$client" "$alias_path" "$helper" "$runtime_dir/lanewayd-rs"
    if [ -d "$runtime_dir" ]; then sudo -n rmdir "$runtime_dir"; fi
  fi
  find "$probe_dir" -depth -delete
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

listing=$(tar -tzf "$archive")
set -- laneway/bin/laneway laneway/bin/lanewayd-rs laneway/bin/lane laneway/install.sh laneway/VERSION
for member in "$@"; do
  count=$(printf '%s\n' "$listing" | grep -Fxc "$member" || true)
  [ "$count" -eq 1 ] || { echo "expected exactly one $member in $archive" >&2; exit 1; }
done
tar -xzf "$archive" -C "$probe_dir" "$@"
package="$probe_dir/laneway"
for file in "$package/bin/laneway" "$package/bin/lanewayd-rs" "$package/install.sh" "$standalone"; do
  [ -f "$file" ] && [ ! -L "$file" ] && [ -x "$file" ] || { echo "not a package executable: $file" >&2; exit 1; }
done
[ "$(readlink "$package/bin/lane")" = laneway ]
cmp -s "$package/bin/laneway" "$standalone"
sh "$root/scripts/verify-rust-macos-runtime.sh" "$package/bin/lanewayd-rs" "$arch"
[ "$(cat "$package/VERSION")" = "$version" ]
[ "$("$package/bin/laneway" version)" = "$version" ]
[ "$("$package/bin/lanewayd-rs" --version)" = "$version" ]

if [ "$install_probe" = 1 ]; then
  for path in "$client" "$alias_path" "$helper" "$runtime_dir"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || { echo "refusing to overwrite $path" >&2; exit 1; }
  done
  installed=true
  sudo -n sh "$package/install.sh" --rust-preview
  "$package/bin/laneway" configure --check --with-rust
  [ "$(readlink "$alias_path")" = laneway ]
  cmp -s "$package/bin/lanewayd-rs" "$runtime_dir/lanewayd-rs"
  if [ "$utun_probe" = 1 ]; then
    # The default Go client retains its own helper. The Rust gate must run
    # without that compatibility helper after verifying the package install.
    sudo -n rm -f "$helper"
    cargo test --locked --manifest-path "$root/rust/Cargo.toml" -p lanewayd-rs --lib \
      darwin_installed_helper_routes_and_restores_real_utun -- --ignored
  fi
fi
printf 'Verified the macOS %s archive and standalone Go client at version %s.\n' "$arch" "$version"
