#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work_dir=$(mktemp -d)
trap 'find "$work_dir" -depth -delete' EXIT HUP INT TERM
mkdir -p "$work_dir/bin" "$work_dir/fixture/darwin/laneway/bin" \
  "$work_dir/fixture/linux/laneway"

cat > "$work_dir/fixture/darwin/laneway/bin/laneway" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$LANEWAY_INSTALLER_TEST_RECORD"
EOF
chmod 0755 "$work_dir/fixture/darwin/laneway/bin/laneway"

cat > "$work_dir/fixture/linux/laneway/install.sh" <<'EOF'
#!/bin/sh
printf 'package install DESTDIR=%s PREFIX=%s\n' "$DESTDIR" "$PREFIX" \
  >> "$LANEWAY_INSTALLER_TEST_RECORD"
EOF
chmod 0755 "$work_dir/fixture/linux/laneway/install.sh"

tar -C "$work_dir/fixture/darwin" -czf "$work_dir/fixture/laneway_darwin_arm64.tar.gz" laneway
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
[ "$1" = verify-blob ] && [ "$2" = --bundle ]
[ "$(cat "$3")" = fixture-signature ]
[ "$4" = --certificate-identity ]
[ "$5" = https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/v9.8.7 ]
[ "$6" = --certificate-oidc-issuer ] && [ "$7" = https://token.actions.githubusercontent.com ]
[ -f "$8" ]
[ "${LANEWAY_INSTALLER_TEST_SIGNATURE_FAIL:-0}" = 0 ]
EOF
cat > "$work_dir/bin/curl" <<'EOF'
#!/bin/sh
set -eu
[ "${1:-}" = --disable ]
[ -z "${LANEWAY_INSTALLER_TEST_CALLS:-}" ] || \
  printf '%s\n' curl >> "$LANEWAY_INSTALLER_TEST_CALLS"
output=
url=
proto=false
redirect_proto=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o|--output) output=$2; shift 2 ;;
    --header|--write-out) shift 2 ;;
    --proto) [ "${2:-}" = '=https' ]; proto=true; shift 2 ;;
    --proto-redir) [ "${2:-}" = '=https' ]; redirect_proto=true; shift 2 ;;
    --disable|--tlsv1.2|--fail|--location|--silent|--show-error) shift ;;
    *) url=$1; shift ;;
  esac
done
[ "$proto" = true ] && [ "$redirect_proto" = true ]
case "$url" in
  */releases/latest\?laneway_cache_bust=*)
    [ "$output" = /dev/null ]
    printf '%s' 'https://github.com/Doout/laneway/releases/tag/v9.8.7'
    ;;
  */laneway_darwin_arm64.tar.gz)
    cp "$LANEWAY_INSTALLER_TEST_FIXTURE/laneway_darwin_arm64.tar.gz" "$output"
    ;;
  */laneway_linux_arm64.tar.gz)
    cp "$LANEWAY_INSTALLER_TEST_FIXTURE/laneway_linux_arm64.tar.gz" "$output"
    ;;
  */checksums.txt)
    cp "$LANEWAY_INSTALLER_TEST_FIXTURE/checksums.txt" "$output"
    ;;
  */checksums.sigstore.json)
    cp "$LANEWAY_INSTALLER_TEST_FIXTURE/checksums.sigstore.json" "$output"
    ;;
  *)
    echo "unexpected installer URL: $url" >&2
    exit 1
    ;;
esac
EOF
chmod 0755 "$work_dir/bin/"*

# Caller-selected CA roots can authenticate both a malicious archive and its
# matching checksum. Reject them before curl, temporary creation, or executing
# the downloaded package, including the Linux path that later invokes sudo.
hostile_tmp=$work_dir/hostile-tmp
mkdir "$hostile_tmp"
for hostile_ca in CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR; do
  hostile_calls=$work_dir/$hostile_ca-calls
  hostile_record=$work_dir/$hostile_ca-record
  if env "$hostile_ca=$work_dir/attacker-ca" \
    PATH="$work_dir/bin:$PATH" TMPDIR="$hostile_tmp" \
    DESTDIR="$work_dir/$hostile_ca-root" LANEWAY_VERSION=9.8.7 \
    LANEWAY_INSTALLER_TEST_OS=Linux \
    LANEWAY_INSTALLER_TEST_FIXTURE="$work_dir/fixture" \
    LANEWAY_INSTALLER_TEST_CALLS="$hostile_calls" \
    LANEWAY_INSTALLER_TEST_RECORD="$hostile_record" \
    sh "$repo_dir/install.sh" --client >/dev/null 2> "$work_dir/$hostile_ca.err"; then
    echo "client installer accepted hostile $hostile_ca" >&2
    exit 1
  fi
  test ! -e "$hostile_calls"
  test ! -e "$hostile_record"
  test -z "$(find "$hostile_tmp" -mindepth 1 -print -quit)"
done

darwin_record=$work_dir/darwin-record
darwin_output=$(env \
  PATH="$work_dir/bin:$PATH" \
  DESTDIR="$work_dir/darwin-root" \
  LANEWAY_DOMAIN=lane.example.test \
  LANEWAY_INSTALLER_TEST_OS=Darwin \
  LANEWAY_INSTALLER_TEST_FIXTURE="$work_dir/fixture" \
  LANEWAY_INSTALLER_TEST_RECORD="$darwin_record" \
  sh "$repo_dir/install.sh")

grep -Fx 'configure --yes' "$darwin_record" >/dev/null
grep -Fx 'configure --check' "$darwin_record" >/dev/null
grep -F 'Laneway v9.8.7 is ready.' <<EOF >/dev/null
$darwin_output
EOF
grep -F 'laneway login lane.example.test' <<EOF >/dev/null
$darwin_output
EOF

# A package that includes the matched node must authenticate its archive
# before the bundled configure command runs.
mac_node="$work_dir/fixture/darwin/laneway/bin/lanewayd"
printf '%s\n' 'bundled node fixture' >"$mac_node"
chmod 0755 "$mac_node"
tar -C "$work_dir/fixture/darwin" -czf "$work_dir/fixture/laneway_darwin_arm64.tar.gz" laneway
(
  cd "$work_dir/fixture"
  sha256sum laneway_darwin_arm64.tar.gz laneway_linux_arm64.tar.gz > checksums.txt
  printf '%s\n' fixture-signature >checksums.sigstore.json
)
paired_record=$work_dir/darwin-paired-record
install_paired_mac() {
  env PATH="$work_dir/bin:$PATH" DESTDIR="$work_dir/darwin-root" \
    LANEWAY_INSTALLER_TEST_OS=Darwin \
    LANEWAY_INSTALLER_TEST_FIXTURE="$work_dir/fixture" \
    LANEWAY_INSTALLER_TEST_RECORD="$paired_record" \
    sh "$repo_dir/install.sh" --client
}
if (export LANEWAY_INSTALLER_TEST_SIGNATURE_FAIL=1; install_paired_mac); then
  echo "bundled macOS client installed under an invalid signature" >&2
  exit 1
fi
test ! -e "$paired_record"
install_paired_mac >/dev/null
grep -Fx 'configure --yes' "$paired_record" >/dev/null
grep -Fx 'configure --check' "$paired_record" >/dev/null

linux_record=$work_dir/linux-record
env \
  PATH="$work_dir/bin:$PATH" \
  DESTDIR="$work_dir/linux-root" \
  LANEWAY_INSTALLER_TEST_OS=Linux \
  LANEWAY_INSTALLER_TEST_FIXTURE="$work_dir/fixture" \
  LANEWAY_INSTALLER_TEST_RECORD="$linux_record" \
  sh "$repo_dir/install.sh"

grep -Fx "package install DESTDIR=$work_dir/linux-root PREFIX=/usr/local" \
  "$linux_record" >/dev/null

echo "one installer detects, verifies, and installs Laneway on macOS and Linux"
