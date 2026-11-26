#!/bin/sh
# Check the actual release archive on a matching macOS architecture.
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: sh integration/rust-release-macos.sh ARCHIVE amd64|arm64 RELEASE_VERSION" >&2
  exit 2
fi
archive=$(CDPATH='' cd -- "$(dirname -- "$1")" && pwd)/$(basename -- "$1")
arch=$2
version=$3
case "$(uname -sm):$arch" in
  'Darwin x86_64:amd64'|'Darwin arm64:arm64') ;;
  *) echo "the macOS package probe requires the matching architecture" >&2; exit 2 ;;
esac
install_probe=${LANEWAY_MACOS_ARCHIVE_INSTALL:-0}
utun_probe=${LANEWAY_MACOS_UTUN_TEST:-0}
desktop_probe=${LANEWAY_MACOS_DESKTOP_TEST:-0}
case "$install_probe:$utun_probe" in
  0:0|1:0|1:1) ;;
  *) echo "the utun test requires LANEWAY_MACOS_ARCHIVE_INSTALL=1; use 0 or 1 for both settings" >&2; exit 2 ;;
esac
case "$desktop_probe" in
  0|1) ;;
  *) echo "use 0 or 1 for LANEWAY_MACOS_DESKTOP_TEST" >&2; exit 2 ;;
esac
if [ "$install_probe" = 1 ]; then
  if [ "$(/usr/sbin/sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
    echo "the installed macOS helper probe requires native hardware, not Rosetta" >&2
    exit 2
  fi
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
    sudo -n rm -f "$client" "$alias_path" "$runtime_dir/lanewayd-rs"
    if [ -d "$runtime_dir" ]; then sudo -n rmdir "$runtime_dir"; fi
  fi
  find "$probe_dir" -depth -delete
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

listing=$(tar -tzf "$archive")
set -- laneway/bin/laneway laneway/bin/lanewayd-rs laneway/bin/lane laneway/install.sh laneway/VERSION laneway/macos-runtime
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
[ "$(cat "$package/macos-runtime")" = rust-v1 ]
cmp -s "$package/bin/laneway" "$standalone"
sh "$root/scripts/verify-rust-macos-runtime.sh" "$package/bin/lanewayd-rs" "$arch"
[ "$(cat "$package/VERSION")" = "$version" ]
[ "$("$package/bin/laneway" version)" = "$version" ]
[ "$("$package/bin/lanewayd-rs" --version)" = "$version" ]
LANEWAY_MACOS_TEST_ARCHIVE="$archive" LANEWAY_MACOS_TEST_VERSION="$version" \
  go -C "$root/go" test ./cmd/laneway -run '^TestMacRustRuntimeArchiveMatchesUpdater$' -count=1

run_probe() {
  probe_executable=$1
  probe_case=$2
  shift 2
  if [ -n "${LANEWAY_MACOS_PROBES_DIR:-}" ]; then
    executable="$LANEWAY_MACOS_PROBES_DIR/$probe_executable"
    [ -f "$executable" ] && [ ! -L "$executable" ] && [ -x "$executable" ] ||
      { echo "invalid cached probe: $executable" >&2; return 1; }
    "$executable" --ignored --exact "$probe_case"
  else
    cargo test --locked --manifest-path "$root/rust/Cargo.toml" -p lanewayd-rs "$@" \
      -- --ignored --exact "$probe_case"
  fi
}

if [ "$desktop_probe" = 1 ]; then
  desktop_case=packaged_daemon_serves_the_desktop_socket
  if ! LANEWAY_MACOS_PACKAGE_DAEMON="$package/bin/lanewayd-rs" LANEWAY_MACOS_PACKAGE_VERSION="$version" \
    run_probe desktop_local_api_lab "$desktop_case" --test desktop_local_api_lab >"$probe_dir/desktop.log" 2>&1; then
    cat "$probe_dir/desktop.log" >&2
    exit 1
  fi
  cat "$probe_dir/desktop.log"
  grep -Fxq "test $desktop_case ... ok" "$probe_dir/desktop.log" || \
    { echo 'the packaged desktop socket probe did not run' >&2; exit 1; }
fi

if [ "$install_probe" = 1 ]; then
  for path in "$client" "$alias_path" "$helper" "$runtime_dir"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || { echo "refusing to overwrite $path" >&2; exit 1; }
  done
  installed=true
  sudo -n sh "$package/install.sh"
  "$package/bin/laneway" configure --check
  "$client" configure --check
  [ ! -e "$helper" ] && [ ! -L "$helper" ]
  [ "$(readlink "$alias_path")" = laneway ]
  cmp -s "$package/bin/lanewayd-rs" "$runtime_dir/lanewayd-rs"
  sh "$root/integration/rust-release-rootless.sh" "$client" "$runtime_dir/lanewayd-rs"
  if [ "$utun_probe" = 1 ]; then
    utun_case=tun::darwin::tests::darwin_installed_helper_routes_and_restores_real_utun
    if ! run_probe lanewayd_rs "$utun_case" --lib >"$probe_dir/utun.log" 2>&1; then
      cat "$probe_dir/utun.log" >&2
      exit 1
    fi
    cat "$probe_dir/utun.log"
    grep -Fxq "test $utun_case ... ok" "$probe_dir/utun.log" ||
      { echo 'the installed Rust utun probe did not run' >&2; exit 1; }
    go -C "$root/go" test -c -o "$probe_dir/go-nethelper.test" ./internal/nethelper
    # Keep the test log owned by the ordinary user for cleanup.
    # shellcheck disable=SC2024
    if ! sudo -n env LANEWAY_PRIVILEGED_TEST=1 LANEWAY_TEST_HELPER="$runtime_dir/lanewayd-rs" \
      "$probe_dir/go-nethelper.test" -test.v -test.run '^TestDarwinNativeHelper$' >"$probe_dir/go-helper.log" 2>&1; then
      cat "$probe_dir/go-helper.log" >&2
      exit 1
    fi
    cat "$probe_dir/go-helper.log"
    grep -Eq '^--- PASS: TestDarwinNativeHelper ' "$probe_dir/go-helper.log" || \
      { echo 'the installed Go to Rust helper probe did not run' >&2; exit 1; }
  fi
fi
printf 'Verified the macOS %s archive and standalone Go client at version %s.\n' "$arch" "$version"
