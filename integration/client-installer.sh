#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work_dir=$(mktemp -d)
trap 'find "$work_dir" -depth -delete' EXIT HUP INT TERM
mkdir -p "$work_dir/bin" "$work_dir/fixture/darwin/laneway/bin" \
  "$work_dir/fixture/linux/laneway/sbin" "$work_dir/fixture/legacy"

cat > "$work_dir/fixture/darwin/laneway/bin/laneway" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$LANEWAY_INSTALLER_TEST_RECORD"
EOF
chmod 0755 "$work_dir/fixture/darwin/laneway/bin/laneway"

cat > "$work_dir/fixture/linux/laneway/install.sh" <<'EOF'
#!/bin/sh
printf 'package install DESTDIR=%s PREFIX=%s\n' "$DESTDIR" "$PREFIX" \
  >> "$LANEWAY_INSTALLER_TEST_RECORD"
if [ "$#" -gt 0 ]; then printf '%s\n' "$*" >> "$LANEWAY_INSTALLER_TEST_RECORD"; fi
EOF
chmod 0755 "$work_dir/fixture/linux/laneway/install.sh"
printf '%s\n' '{"test":"signed fixture"}' > "$work_dir/fixture/checksums.sigstore.json"

tar -C "$work_dir/fixture/darwin" -czf "$work_dir/fixture/legacy/laneway_darwin_arm64.tar.gz" laneway
tar -C "$work_dir/fixture/linux" -czf "$work_dir/fixture/legacy/laneway_linux_arm64.tar.gz" laneway
(
  cd "$work_dir/fixture/legacy"
  sha256sum laneway_linux_arm64.tar.gz laneway_darwin_arm64.tar.gz > checksums.txt
  cp ../checksums.sigstore.json .
)
printf '%s\n' rust-v1 > "$work_dir/fixture/darwin/laneway/macos-runtime"
printf '9.8.7\n' > "$work_dir/fixture/darwin/laneway/VERSION"
printf '#!/bin/sh\nexit 0\n' > "$work_dir/fixture/darwin/laneway/bin/lanewayd-rs"
chmod 0755 "$work_dir/fixture/darwin/laneway/bin/lanewayd-rs"
tar -C "$work_dir/fixture/darwin" -czf "$work_dir/fixture/laneway_darwin_arm64.tar.gz" laneway
printf '9.8.7\n' > "$work_dir/fixture/linux/laneway/VERSION"
printf '#!/bin/sh\nexit 0\n' > "$work_dir/fixture/linux/laneway/sbin/lanewayd-rs"
chmod 0755 "$work_dir/fixture/linux/laneway/sbin/lanewayd-rs"
tar -C "$work_dir/fixture/linux" -czf "$work_dir/fixture/laneway_linux_arm64.tar.gz" laneway
(
  cd "$work_dir/fixture"
  sha256sum laneway_darwin_arm64.tar.gz laneway_linux_arm64.tar.gz > checksums.txt
)

cat > "$work_dir/bin/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -s) printf '%s\n' "$LANEWAY_INSTALLER_TEST_OS" ;;
  -m) echo arm64 ;;
  *) printf '%s\n' "$LANEWAY_INSTALLER_TEST_OS" ;;
esac
EOF
cat > "$work_dir/bin/id" <<'EOF'
#!/bin/sh
[ "${1:-}" = -u ] && { echo 501; exit 0; }
exit 1
EOF
cat > "$work_dir/bin/sudo" <<'EOF'
#!/bin/sh
echo "test installer unexpectedly invoked sudo itself" >&2
exit 1
EOF
cat > "$work_dir/bin/cosign" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = version ]; then printf '%s\n' '{"gitVersion":"v3.1.3"}'; exit 0; fi
test "$1" = verify-blob
test "$2" = --bundle
test -s "$3"
test "$4" = --certificate-identity
test "$5" = 'https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/v9.8.7'
test "$6" = --certificate-oidc-issuer
test "$7" = https://token.actions.githubusercontent.com
test -s "$8"
test "${LANEWAY_INSTALLER_TEST_BAD_SIGNATURE:-0}" = 0
printf '%s\n' signature-verified >> "$LANEWAY_INSTALLER_TEST_RECORD"
EOF
cat > "$work_dir/bin/curl" <<'EOF'
#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o|--output) output=$2; shift 2 ;;
    --header|--write-out|--proto) shift 2 ;;
    --tlsv1.2|--fail|--location|--silent|--show-error) shift ;;
    *) url=$1; shift ;;
  esac
done
case "$url" in
  */releases/latest\?laneway_cache_bust=*)
    [ "$output" = /dev/null ]
    printf '%s' 'https://github.com/Doout/laneway/releases/tag/v9.8.7'
    ;;
  */laneway_darwin_arm64.tar.gz)
    cp "$LANEWAY_INSTALLER_TEST_FIXTURE/laneway_darwin_arm64.tar.gz" "$output"
    if [ "${LANEWAY_INSTALLER_TEST_CORRUPT_ARCHIVE:-0}" = 1 ]; then
      printf 'corruption' >> "$output"
    fi
    ;;
  */laneway_linux_arm64.tar.gz)
    cp "$LANEWAY_INSTALLER_TEST_FIXTURE/laneway_linux_arm64.tar.gz" "$output"
    ;;
  */checksums.txt|*/checksums.sigstore.json)
    cp "$LANEWAY_INSTALLER_TEST_FIXTURE/${url##*/}" "$output"
    ;;
  *)
    echo "unexpected installer URL: $url" >&2
    exit 1
    ;;
esac
EOF
chmod 0755 "$work_dir/bin/"*

darwin_record=$work_dir/darwin-record
darwin_output=$(env \
  PATH="$work_dir/bin:$PATH" \
  LANEWAY_DOMAIN=lane.example.test \
  LANEWAY_INSTALLER_TEST_OS=Darwin \
  LANEWAY_INSTALLER_TEST_FIXTURE="$work_dir/fixture" \
  LANEWAY_INSTALLER_TEST_RECORD="$darwin_record" \
  sh "$repo_dir/install.sh")

expected=$(printf '%s\n' signature-verified 'configure --yes' 'configure --check')
[ "$(cat "$darwin_record")" = "$expected" ]
grep -F 'Laneway v9.8.7 is ready.' <<EOF >/dev/null
$darwin_output
EOF
grep -F 'laneway login lane.example.test' <<EOF >/dev/null
$darwin_output
EOF

printf '%s\n' "$darwin_output" | grep -Fx '  laneway connect lane.example.test' >/dev/null

failed_record=$work_dir/failed-signature-record
if env PATH="$work_dir/bin:$PATH" LANEWAY_INSTALLER_TEST_OS=Darwin \
  LANEWAY_INSTALLER_TEST_FIXTURE="$work_dir/fixture" LANEWAY_INSTALLER_TEST_BAD_SIGNATURE=1 \
  LANEWAY_INSTALLER_TEST_RECORD="$failed_record" \
  sh "$repo_dir/install.sh" > "$work_dir/failed-output" 2>&1; then
  echo "the macOS installer accepted a bad signature" >&2
  exit 1
fi
test ! -e "$failed_record"
grep -F 'release checksum signature verification failed' "$work_dir/failed-output" >/dev/null

corrupt_record=$work_dir/corrupt-archive-record
if env PATH="$work_dir/bin:$PATH" LANEWAY_INSTALLER_TEST_OS=Darwin \
  LANEWAY_INSTALLER_TEST_FIXTURE="$work_dir/fixture" LANEWAY_INSTALLER_TEST_CORRUPT_ARCHIVE=1 \
  LANEWAY_INSTALLER_TEST_RECORD="$corrupt_record" \
  sh "$repo_dir/install.sh" > "$work_dir/corrupt-output" 2>&1; then
  echo "the macOS installer accepted an archive with the wrong checksum" >&2
  exit 1
fi
[ "$(cat "$corrupt_record")" = signature-verified ]

legacy_record=$work_dir/darwin-legacy-record
if env PATH="$work_dir/bin:$PATH" LANEWAY_INSTALLER_TEST_OS=Darwin \
  LANEWAY_INSTALLER_TEST_FIXTURE="$work_dir/fixture/legacy" LANEWAY_INSTALLER_TEST_RECORD="$legacy_record" \
  sh "$repo_dir/install.sh" > "$work_dir/darwin-legacy-output" 2>&1; then
  echo 'the macOS installer accepted a Go-only package' >&2
  exit 1
fi
[ "$(cat "$legacy_record")" = signature-verified ]
grep -F 'does not provide the macOS Rust package' "$work_dir/darwin-legacy-output" >/dev/null

linux_record=$work_dir/linux-record
env \
  PATH="$work_dir/bin:$PATH" \
  DESTDIR="$work_dir/linux-root" \
  LANEWAY_INSTALLER_TEST_OS=Linux \
  LANEWAY_INSTALLER_TEST_FIXTURE="$work_dir/fixture" \
  LANEWAY_INSTALLER_TEST_RECORD="$linux_record" \
  sh "$repo_dir/install.sh"

expected=$(printf '%s\n' signature-verified \
  "package install DESTDIR=$work_dir/linux-root PREFIX=/usr/local" --rust-preview)
test "$(cat "$linux_record")" = "$expected"

linux_preview() {
  env PATH="$work_dir/bin:$PATH" DESTDIR="$work_dir/linux-preview" LANEWAY_INSTALLER_TEST_OS=Linux \
    LANEWAY_INSTALLER_TEST_FIXTURE="$1" LANEWAY_INSTALLER_TEST_RECORD="$2" \
    LANEWAY_INSTALLER_TEST_BAD_SIGNATURE="${3:-0}" \
    sh "$repo_dir/install.sh" --rust-preview
}
linux_preview "$work_dir/fixture" "$work_dir/linux-preview-record"
expected=$(printf '%s\n' signature-verified \
  "package install DESTDIR=$work_dir/linux-preview PREFIX=/usr/local" --rust-preview)
test "$(cat "$work_dir/linux-preview-record")" = "$expected"
if linux_preview "$work_dir/fixture" "$work_dir/linux-signature-record" 1 \
    >"$work_dir/linux-bad-signature.out" 2>&1; then
  echo 'Linux preview accepted a bad release signature' >&2
  exit 1
fi
test ! -e "$work_dir/linux-signature-record"
grep -F 'release checksum signature verification failed' "$work_dir/linux-bad-signature.out" >/dev/null
if linux_preview "$work_dir/fixture/legacy" "$work_dir/linux-legacy-record" >"$work_dir/linux-legacy.out" 2>&1; then
  echo 'Linux preview accepted a Go-only release' >&2
  exit 1
fi
test "$(cat "$work_dir/linux-legacy-record")" = signature-verified
grep -F 'does not provide the Linux Rust package' "$work_dir/linux-legacy.out" >/dev/null

echo "one installer detects, verifies, and installs Laneway on macOS and Linux"
