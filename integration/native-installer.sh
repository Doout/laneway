#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'find "$work" -depth -delete' EXIT HUP INT TERM
mkdir "$work/bin"
export FIXTURE_REAL_MV
FIXTURE_REAL_MV=$(command -v mv)

cat >"$work/bin/uname" <<'MOCK'
#!/bin/sh
set -eu
case "$1" in -s) echo "$FIXTURE_OS" ;; -m) echo "$FIXTURE_ARCH" ;; *) exit 1 ;; esac
MOCK
cat >"$work/bin/curl" <<'MOCK'
#!/bin/sh
set -eu
for last do :; done
case "$last" in
  https://github.com/Doout/laneway/releases/latest\?laneway_cache_bust=*)
    printf '%s\n' "${FIXTURE_LATEST_URL:-https://github.com/Doout/laneway/releases/tag/v9.8.7}"
    exit 0
    ;;
esac
[ "$#" -eq 12 ]
[ "$1" = --disable ] && [ "$7" = '=https' ] && [ "$9" = '=https' ]
case "${10}" in
  https://github.com/Doout/laneway/releases/download/v9.8.7/*) ;;
  *) exit 1 ;;
esac
[ "${11}" = --output ]
cp "$FIXTURE_ASSETS/${10##*/}" "${12}"
MOCK
cat >"$work/bin/cosign" <<'MOCK'
#!/bin/sh
set -eu
[ "$#" -eq 8 ] && [ "$1" = verify-blob ] && [ "$2" = --bundle ]
[ "$(cat "$3")" = 'fixture signature' ]
[ "$4" = --certificate-identity ] && [ "$5" = https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/v9.8.7 ]
[ "$6" = --certificate-oidc-issuer ] && [ "$7" = https://token.actions.githubusercontent.com ]
[ -f "$8" ]
[ -z "${COSIGN_INSECURE_IGNORE_TLOG+x}" ]
[ "${FIXTURE_FAIL_SIGNATURE:-0}" = 0 ]
MOCK
cat >"$work/bin/mv" <<'MOCK'
#!/bin/sh
set -eu
if [ "${FIXTURE_FAIL_NODE_INSTALL:-0}" = 1 ]; then
  case "$3" in */lanewayd_*) exit 1 ;; esac
fi
exec "$FIXTURE_REAL_MV" "$@"
MOCK
cat >"$work/bin/sudo" <<'MOCK'
#!/bin/sh
echo "Native user installation must not invoke sudo" >&2
exit 1
MOCK
chmod 0755 "$work/bin/"*
export PATH="$work/bin:$PATH"
export COSIGN_INSECURE_IGNORE_TLOG=true

for target in Linux:x86_64:linux_amd64 Darwin:arm64:darwin_arm64; do
  FIXTURE_OS=${target%%:*}
  architecture_and_platform=${target#*:}
  FIXTURE_ARCH=${architecture_and_platform%%:*}
  platform=${architecture_and_platform#*:}
  FIXTURE_ASSETS=$work/$platform
  HOME=$work/home-$platform
  export FIXTURE_OS FIXTURE_ARCH FIXTURE_ASSETS HOME
  mkdir -p "$FIXTURE_ASSETS" "$HOME/.local/bin"
  cli=laneway-native_$platform
  compat=laneway-compat_$platform
  node=lanewayd_$platform
  printf '%s\n' 'fixture signature' >"$FIXTURE_ASSETS/checksums.sigstore.json"
  printf '%s\n' 'previous CLI' >"$HOME/.local/bin/laneway"
  printf '%s\n' 'previous daemon' >"$HOME/.local/bin/lanewayd"
  printf '%s\n' 'previous helper' >"$HOME/.local/bin/laneway-compat"

  make_manifest() {
    (
      cd "$FIXTURE_ASSETS"
      if [ "$FIXTURE_OS" = Darwin ]; then
        shasum -a 256 "$cli" "$node" "$compat" >checksums.txt
      else
        sha256sum "$cli" "$node" "$compat" >checksums.txt
      fi
    )
  }
  check_previous() {
    [ "$(cat "$HOME/.local/bin/laneway")" = 'previous CLI' ]
    [ "$(cat "$HOME/.local/bin/lanewayd")" = 'previous daemon' ]
    [ "$(cat "$HOME/.local/bin/laneway-compat")" = 'previous helper' ]
  }
  install_user() {
    "$repo_dir/scripts/install-node.sh" v9.8.7
  }
  printf '%s\n' 'next CLI' >"$FIXTURE_ASSETS/$cli"
  printf '%s\n' 'next daemon' >"$FIXTURE_ASSETS/$node"
  printf '%s\n' 'next helper' >"$FIXTURE_ASSETS/$compat"
  make_manifest

  if (export FIXTURE_FAIL_SIGNATURE=1; install_user); then exit 1; fi
  check_previous
  grep -F "  $node" "$FIXTURE_ASSETS/checksums.txt" >"$FIXTURE_ASSETS/node-only"
  cp "$FIXTURE_ASSETS/node-only" "$FIXTURE_ASSETS/checksums.txt"
  if install_user; then exit 1; fi
  check_previous
  make_manifest
  printf '%s\n' 'corrupt' >>"$FIXTURE_ASSETS/$node"
  if install_user; then exit 1; fi
  check_previous
  printf '%s\n' 'next daemon' >"$FIXTURE_ASSETS/$node"
  if (export FIXTURE_FAIL_NODE_INSTALL=1; install_user); then exit 1; fi
  check_previous
  mkdir "$HOME/.local/bin/.laneway-update-lock"
  if install_user; then exit 1; fi
  check_previous
  rmdir "$HOME/.local/bin/.laneway-update-lock"
  if (export FIXTURE_LATEST_URL=https://other.example/releases/tag/v9.8.7; "$repo_dir/scripts/install-node.sh"); then exit 1; fi
  check_previous
  "$repo_dir/scripts/install-node.sh"
  cmp "$FIXTURE_ASSETS/$cli" "$HOME/.local/bin/laneway"
  cmp "$FIXTURE_ASSETS/$node" "$HOME/.local/bin/lanewayd"
  cmp "$FIXTURE_ASSETS/$compat" "$HOME/.local/bin/laneway-compat"
  test -x "$HOME/.local/bin/laneway"
  test -x "$HOME/.local/bin/lanewayd"
  test -x "$HOME/.local/bin/laneway-compat"
done
echo "Signed Linux and macOS user installer contract is valid"
