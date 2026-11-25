#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "lane-prepare integration must run as root" >&2; exit 1; }
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d)
trusted_mock_dir=/usr/local/sbin
trusted_mocks=
cleanup() {
  for trusted_mock in $trusted_mocks; do
    [ ! -e "$trusted_mock" ] || find "$trusted_mock" -maxdepth 0 -delete
  done
  [ ! -e "$test_dir" ] || find "$test_dir" -depth -delete
}
trap cleanup EXIT HUP INT TERM
compose_dir=$test_dir/compose
issuer_dir="$test_dir/offline export"
fake_bin=$test_dir/bin
log=$test_dir/calls.log
real_install=$(command -v install)
mkdir -p "$compose_dir/generated/backups" "$issuer_dir" "$fake_bin"
chmod 0700 "$issuer_dir"
cp "$repo_dir/deploy/compose/laneway-control" "$repo_dir/deploy/compose/prepare.sh" "$repo_dir/deploy/compose/preflight.sh" "$compose_dir/"
chmod 0755 "$compose_dir/laneway-control" "$compose_dir/prepare.sh" "$compose_dir/preflight.sh"
cat > "$compose_dir/compose.yaml" <<'EOF'
services:
  exit-node:
    image: ghcr.io/doout/laneway-exit-node:${LANEWAY_VERSION:?set LANEWAY_VERSION to a released semantic version}@${LANEWAY_EXIT_NODE_IMAGE_DIGEST:-sha256:0000000000000000000000000000000000000000000000000000000000000000}
EOF
: > "$log"
printf '%s\n' root-public > "$issuer_dir/ca.crt"
printf '%s\n' issuer-chain > "$issuer_dir/intermediate-chain.crt"
printf '%s\n' issuer-private > "$issuer_dir/intermediate.key"
chmod 0444 "$issuer_dir/ca.crt" "$issuer_dir/intermediate-chain.crt"
chmod 0400 "$issuer_dir/intermediate.key"
cat > "$test_dir/bootstrap-artifacts.toml" <<'EOF'
[[bootstrap.artifacts]]
os = "linux"
arch = "amd64"
url = "https://downloads.example.test/laneway_linux_amd64.tar.gz"
sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
size_bytes = 1
[[bootstrap.artifacts]]
os = "linux"
arch = "arm64"
url = "https://downloads.example.test/laneway_linux_arm64.tar.gz"
sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
size_bytes = 1
[[bootstrap.artifacts]]
os = "darwin"
arch = "amd64"
url = "https://downloads.example.test/laneway_darwin_amd64.tar.gz"
sha256 = "3333333333333333333333333333333333333333333333333333333333333333"
size_bytes = 1
[[bootstrap.artifacts]]
os = "darwin"
arch = "arm64"
url = "https://downloads.example.test/laneway_darwin_arm64.tar.gz"
sha256 = "4444444444444444444444444444444444444444444444444444444444444444"
size_bytes = 1
EOF

cat > "$compose_dir/validate.sh" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' validate >> "$LANE_TEST_LOG"
EOF
cat > "$compose_dir/bootstrap.sh" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' bootstrap >> "$LANE_TEST_LOG"
EOF
cat > "$fake_bin/docker" <<'EOF'
#!/bin/sh
set -eu
printf 'docker <%s>\n' "$*" >> "$LANE_TEST_LOG"
case "$*" in
  "version --format "*|"--context default version --format "*) printf '26.1.0\n' ;;
esac
EOF
cat > "$fake_bin/getent" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$fake_bin/ss" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$fake_bin/cosign" <<'EOF'
#!/bin/sh
set -eu
printf 'cosign <%s>\n' "$*" >> "$LANE_TEST_LOG"
EOF
cat > "$fake_bin/age" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$fake_bin/install" <<'EOF'
#!/bin/sh
set -eu
test "$PATH" = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
test "${ENV+x}" != x
test "${BASH_ENV+x}" != x
test "${CDPATH+x}" != x
previous=
last=
for argument do
  previous=$last
  last=$argument
done
"$LANE_TEST_REAL_INSTALL" "$@"
if [ -n "${LANE_TEST_REPLACE_ISSUER_AFTER_COPY:-}" ] && \
  [ "$previous" = "$LANE_TEST_REPLACE_ISSUER_AFTER_COPY" ]; then
  replacement=$previous.lane-test-replacement
  printf '%s\n' replaced-issuer-material > "$replacement"
  chmod 0444 "$replacement"
  chown 0:0 "$replacement"
  mv -f "$replacement" "$previous"
fi
EOF
cat > "$fake_bin/laneway" <<'EOF'
#!/bin/sh
set -eu
test "$PATH" = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
test "${ENV+x}" != x
test "${BASH_ENV+x}" != x
test "${CDPATH+x}" != x
printf 'laneway <%s>\n' "$*" >> "$LANE_TEST_LOG"
if [ "${1:-}" = id ]; then
  printf '%s\n' 0123456789abcdef0123456789abcdef
  exit 0
fi
if [ "${1:-} ${2:-}" = "pki verify-authority" ]; then
  if [ -n "${LANE_TEST_REPLACE_ISSUER_AFTER_VERIFY:-}" ]; then
    replacement=$LANE_TEST_REPLACE_ISSUER_AFTER_VERIFY.lane-test-replacement
    printf '%s\n' replaced-after-verification > "$replacement"
    chmod 0400 "$replacement"
    chown 0:0 "$replacement"
    mv -f "$replacement" "$LANE_TEST_REPLACE_ISSUER_AFTER_VERIFY"
  fi
  exit 0
fi
case "${1:-} ${2:-}" in
  "config inspect-controller-initial-network")
    printf '%s\n' '{"configured":true,"network_id":"11111111111111111111111111111111","name":"production","ipv4_pool":"100.96.0.0/16","bootstrap_network_id":"11111111111111111111111111111111"}'
    ;;
  "pki controller"|"pki relay")
    out_cert=; out_key=
    shift 2
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --out-cert) out_cert=$2; shift 2 ;;
        --out-key) out_key=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    [ -n "$out_cert" ] && [ -n "$out_key" ]
    printf '%s\n' certificate > "$out_cert"
    printf '%s\n' private-key > "$out_key"
    ;;
  *) exit 1 ;;
esac
EOF
chmod 0755 "$compose_dir/validate.sh" "$compose_dir/bootstrap.sh" "$fake_bin/docker" "$fake_bin/cosign" "$fake_bin/install" "$fake_bin/laneway" "$fake_bin/getent" "$fake_bin/ss" "$fake_bin/age"

publish_mock() {
  mock_name=$1
  mock_target=$trusted_mock_dir/$mock_name
  [ ! -e "$mock_target" ] && [ ! -L "$mock_target" ] || {
    echo "trusted mock target already exists: $mock_target" >&2
    exit 1
  }
  /usr/bin/install -m 0755 -o 0 -g 0 "$fake_bin/$mock_name" "$mock_target"
  trusted_mocks="$mock_target $trusted_mocks"
}
for mock_name in age cosign docker getent install laneway ss; do
  publish_mock "$mock_name"
done

cat > "$compose_dir/.env" <<'EOF'
LANEWAY_VERSION=1.0.0
LANEWAY_INSTALL_PROFILE=quick
LANEWAY_CONTROLLER_IMAGE_DIGEST=sha256:1111111111111111111111111111111111111111111111111111111111111111
LANEWAY_RELAY_IMAGE_DIGEST=sha256:2222222222222222222222222222222222222222222222222222222222222222
LANEWAY_ADMIN_IMAGE_DIGEST=sha256:3333333333333333333333333333333333333333333333333333333333333333
LANEWAY_CONNECTOR_IMAGE_DIGEST=sha256:5555555555555555555555555555555555555555555555555555555555555555
LANEWAY_EXIT_NODE_IMAGE_DIGEST=sha256:4444444444444444444444444444444444444444444444444444444444444444
LANEWAY_BIND_ADDRESS=127.0.0.1
LANEWAY_CONTROLLER_PORT=9443
LANEWAY_RELAY_QUIC_PORT=4433
LANEWAY_RELAY_TCP_PORT=443
LANEWAY_EXIT_DIRECT_PORT=4434
LANEWAY_CONTROLLER_SERVER_NAME=lane.example.test
LANEWAY_NETWORK_ID=11111111111111111111111111111111
LANEWAY_CONTROLLER_SERVICE_ID=22222222222222222222222222222222
LANEWAY_RELAY_SERVICE_ID=33333333333333333333333333333333
LANEWAY_NETWORK_NAME=production
LANEWAY_IPV4_POOL=100.96.0.0/16
LANEWAY_RELAY_PUBLIC_ENDPOINT=relay.example.test:4433
LANEWAY_BACKUP_RECIPIENT=age1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
chmod 0600 "$compose_dir/.env"
export PATH="$fake_bin:$PATH" LANE_TEST_LOG="$log" \
  LANE_TEST_REAL_INSTALL="$real_install" \
  LANEWAY_BOOTSTRAP_ARTIFACTS_FILE="$test_dir/bootstrap-artifacts.toml"
export ENV="$test_dir/hostile-env" BASH_ENV="$test_dir/hostile-bash-env" \
  CDPATH="$test_dir"

"$compose_dir/laneway-control" init --issuer "$issuer_dir"
for path in \
  generated/config/controller.toml generated/config/relay.toml \
  generated/pki/ca.crt generated/pki/intermediate-chain.crt generated/pki/intermediate.key \
  generated/pki/controller.crt generated/pki/controller.key generated/pki/relay.crt generated/pki/relay.key \
  generated/secrets/admin.token
do
  if [ ! -f "$compose_dir/$path" ] || [ -L "$compose_dir/$path" ]; then
    echo "missing prepared $path" >&2
    exit 1
  fi
done
for path in generated/pki/intermediate.key generated/pki/controller.key generated/pki/relay.key generated/secrets/admin.token; do
  [ "$(stat -c '%a:%u:%g' "$compose_dir/$path")" = 400:65532:65532 ] || { echo "unsafe ownership for $path" >&2; exit 1; }
done
for path in generated/config/controller.toml generated/config/relay.toml generated/pki/ca.crt generated/pki/intermediate-chain.crt generated/pki/controller.crt generated/pki/relay.crt; do
  [ "$(stat -c '%a:%u:%g' "$compose_dir/$path")" = 444:0:0 ] || { echo "unsafe public material mode for $path" >&2; exit 1; }
done
grep -F 'network_id = "11111111111111111111111111111111"' "$compose_dir/generated/config/relay.toml" >/dev/null
grep -F 'server_name = "lane.example.test"' "$compose_dir/generated/config/relay.toml" >/dev/null
initial_network=$(awk '
  $0 == "[controller.initial_network]" { seen++; active=1; next }
  /^\[/ { active=0 }
  active { print }
  END { if (seen != 1) exit 1 }
' "$compose_dir/generated/config/controller.toml")
printf '%s\n' "$initial_network" | grep -Fx 'network_id = "11111111111111111111111111111111"' >/dev/null
printf '%s\n' "$initial_network" | grep -Fx 'name = "production"' >/dev/null
printf '%s\n' "$initial_network" | grep -Fx 'ipv4_pool = "100.96.0.0/16"' >/dev/null
grep -Fx 'controller_endpoint = "https://lane.example.test:9443"' \
  "$compose_dir/generated/config/controller.toml" >/dev/null
grep -Fx 'controller_quic_endpoint = "lane.example.test:9443"' \
  "$compose_dir/generated/config/controller.toml" >/dev/null
test "$(grep -c '^\[\[bootstrap\.artifacts\]\]$' "$compose_dir/generated/config/controller.toml")" -eq 4
[ ! -e "$compose_dir/generated/pki/ca.key" ]
[ "$(grep -c 'pki controller' "$log")" -eq 1 ]
[ "$(grep -c 'pki relay' "$log")" -eq 1 ]
if grep -F "pki verify-authority --root $issuer_dir/" "$log" >/dev/null; then
  echo "authority verification consumed the mutable issuer source" >&2
  exit 1
fi

"$compose_dir/laneway-control" init --issuer "$issuer_dir"
[ "$(grep -c 'pki controller' "$log")" -eq 1 ] || { echo "idempotent init reissued controller identity" >&2; exit 1; }

expect_issuer_rejection() {
  description=$1
  shift
  controller_calls=$(grep -c 'pki controller' "$log")
  relay_calls=$(grep -c 'pki relay' "$log")
  if "$@" >/dev/null 2>&1; then
    echo "init accepted $description" >&2
    exit 1
  fi
  [ "$(grep -c 'pki controller' "$log")" -eq "$controller_calls" ] || {
    echo "$description issued a new controller identity" >&2
    exit 1
  }
  [ "$(grep -c 'pki relay' "$log")" -eq "$relay_calls" ] || {
    echo "$description issued a new relay identity" >&2
    exit 1
  }
}

chmod 0770 "$issuer_dir"
expect_issuer_rejection "a replaceable issuer directory" \
  "$compose_dir/laneway-control" init --issuer "$issuer_dir"
chmod 0700 "$issuer_dir"

chmod 0770 "$test_dir"
expect_issuer_rejection "an issuer below a replaceable parent directory" \
  "$compose_dir/laneway-control" init --issuer "$issuer_dir"
chmod 0700 "$test_dir"

chmod 0640 "$issuer_dir/intermediate.key"
expect_issuer_rejection "an issuer private key with group access" \
  "$compose_dir/laneway-control" init --issuer "$issuer_dir"
chmod 0400 "$issuer_dir/intermediate.key"

chown 1:0 "$issuer_dir/ca.crt"
expect_issuer_rejection "issuer material not owned by root" \
  "$compose_dir/laneway-control" init --issuer "$issuer_dir"
chown 0:0 "$issuer_dir/ca.crt"

ln "$issuer_dir/ca.crt" "$test_dir/ca-hardlink"
expect_issuer_rejection "hardlinked issuer material" \
  "$compose_dir/laneway-control" init --issuer "$issuer_dir"
find "$test_dir/ca-hardlink" -maxdepth 0 -delete

mv "$issuer_dir/intermediate-chain.crt" "$issuer_dir/intermediate-chain.real"
ln -s intermediate-chain.real "$issuer_dir/intermediate-chain.crt"
expect_issuer_rejection "symlinked issuer material" \
  "$compose_dir/laneway-control" init --issuer "$issuer_dir"
find "$issuer_dir/intermediate-chain.crt" -maxdepth 0 -delete
mv "$issuer_dir/intermediate-chain.real" "$issuer_dir/intermediate-chain.crt"

ln -s "$issuer_dir" "$test_dir/issuer-link"
expect_issuer_rejection "a symlinked issuer directory" \
  "$compose_dir/laneway-control" init --issuer "$test_dir/issuer-link"
find "$test_dir/issuer-link" -maxdepth 0 -delete

expect_issuer_rejection "issuer material replaced during snapshot copy" \
  env LANE_TEST_REPLACE_ISSUER_AFTER_COPY="$issuer_dir/ca.crt" \
  "$compose_dir/laneway-control" init --issuer "$issuer_dir"
printf '%s\n' root-public > "$issuer_dir/ca.crt"
chmod 0444 "$issuer_dir/ca.crt"

# Once the protected snapshot has passed consistency checks, later changes to
# the transfer directory cannot affect verification or idempotent comparison.
env LANE_TEST_REPLACE_ISSUER_AFTER_VERIFY="$issuer_dir/intermediate.key" \
  "$compose_dir/laneway-control" init --issuer "$issuer_dir"
grep -Fx issuer-private "$compose_dir/generated/pki/intermediate.key" >/dev/null
printf '%s\n' issuer-private > "$issuer_dir/intermediate.key"
chmod 0400 "$issuer_dir/intermediate.key"

printf '%s\n' forbidden-root-key > "$issuer_dir/ca.key"
if "$compose_dir/laneway-control" init --issuer "$issuer_dir" >/dev/null 2>&1; then
  echo "init accepted an offline root private key" >&2
  exit 1
fi

echo "Lane clean init preserves the offline-root boundary and restrictive ownership"
