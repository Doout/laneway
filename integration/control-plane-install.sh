#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "control-plane installer integration must run as root" >&2; exit 1; }
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d)
trusted_mock_dir=/usr/local/sbin
trusted_mocks=
trusted_cosign_parent=/usr/local/libexec/laneway
trusted_cosign_parent_claimed=false
trusted_libexec_claimed=false
cleanup() {
  if [ -L /usr/local/sbin/laneway-control ]; then
    case "$(readlink /usr/local/sbin/laneway-control)" in "$test_root"/*) find /usr/local/sbin/laneway-control -maxdepth 0 -delete ;; esac
  fi
  for trusted_mock in $trusted_mocks; do
    [ ! -e "$trusted_mock" ] || find "$trusted_mock" -maxdepth 0 -delete
  done
  [ "$trusted_cosign_parent_claimed" = false ] || \
    find "$trusted_cosign_parent" -maxdepth 0 -delete 2>/dev/null || true
  [ "$trusted_libexec_claimed" = false ] || \
    find /usr/local/libexec -maxdepth 0 -delete 2>/dev/null || true
  [ ! -e "$test_root" ] || find "$test_root" -depth -delete
}
trap cleanup EXIT HUP INT TERM

source_dir=$test_root/package/deploy/compose
mock_bin=$test_root/bin
issuer_dir=$test_root/issuer
destination=$test_root/control-plane
log_file=$test_root/calls.log
counter_file=$test_root/id-counter
answers_file=$test_root/installer-state/answers
mkdir -p "$source_dir" "$mock_bin" "$issuer_dir"
chmod 0700 "$issuer_dir"
printf '0.2.8\n' > "$test_root/package/VERSION"
cp "$repo_dir/deploy/compose/install-control-plane.sh" "$source_dir/install-control-plane.sh"
for name in compose.yaml bootstrap.sh preflight.sh prepare.sh recovery.sh validate.sh README.md; do
  printf 'fixture %s\n' "$name" > "$source_dir/$name"
done
cat > "$source_dir/laneway-control" <<'EOF'
#!/bin/sh
printf 'lane %s\n' "$*" >> "$LANEWAY_TEST_LOG"
case "$1" in
  init)
    test "$2" = --issuer
    test -d "$3"
    test "$(stat -c '%u:%g:%a' "$3")" = 0:0:700
    test "$(stat -c '%u:%g:%a:%h' "$3/ca.crt")" = 0:0:444:1
    test "$(stat -c '%u:%g:%a:%h' "$3/intermediate-chain.crt")" = 0:0:444:1
    test "$(stat -c '%u:%g:%a:%h' "$3/intermediate.key")" = 0:0:400:1
    if [ -n "${LANEWAY_TEST_EXPECTED_ISSUER_PREFIX:-}" ]; then
      grep -Fx "$LANEWAY_TEST_EXPECTED_ISSUER_PREFIX ca.crt" "$3/ca.crt" >/dev/null
      grep -Fx "$LANEWAY_TEST_EXPECTED_ISSUER_PREFIX intermediate-chain.crt" "$3/intermediate-chain.crt" >/dev/null
      grep -Fx "$LANEWAY_TEST_EXPECTED_ISSUER_PREFIX intermediate.key" "$3/intermediate.key" >/dev/null
    fi
    ;;
  backup)
    mkdir -p "$(dirname "$0")/generated/recovery"
    printf 'encrypted recovery fixture\n' > "$(dirname "$0")/generated/recovery/$2"
    ;;
  *) exit 1 ;;
esac
EOF
cat > "$source_dir/prepare-control-plane.sh" <<'EOF'
#!/bin/sh
output=$1
mkdir -p "$output/control-plane-input"
chmod 0700 "$output" "$output/control-plane-input"
for name in ca.crt intermediate-chain.crt intermediate.key; do
  printf 'generated %s\n' "$name" > "$output/control-plane-input/$name"
done
chmod 0444 "$output/control-plane-input/ca.crt" "$output/control-plane-input/intermediate-chain.crt"
chmod 0400 "$output/control-plane-input/intermediate.key"
printf '%s\n' age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq > "$output/control-plane-input/recovery-recipient.txt"
chmod 0444 "$output/control-plane-input/recovery-recipient.txt"
printf 'private identity fixture\n' > "$output/laneway-recovery.identity"
printf 'encrypted root fixture\n' > "$output/offline-root.tar.age"
printf 'instructions\n' > "$output/README.txt"
EOF
cat > "$source_dir/upgrade-control-plane.sh" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "$source_dir/laneway-control" "$source_dir/install-control-plane.sh" "$source_dir/prepare-control-plane.sh" "$source_dir/upgrade-control-plane.sh"
for name in ca.crt intermediate-chain.crt intermediate.key; do
  printf 'fixture %s\n' "$name" > "$issuer_dir/$name"
done
chmod 0444 "$issuer_dir/ca.crt" "$issuer_dir/intermediate-chain.crt"
chmod 0400 "$issuer_dir/intermediate.key"

cat > "$mock_bin/docker" <<'EOF'
#!/bin/sh
test "$PATH" = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
test "${ENV+x}" != x
test "${BASH_ENV+x}" != x
test "${CDPATH+x}" != x
test "$DOCKER_CONFIG" = /root/.docker
test "$DOCKER_CONTEXT" = default
test "$1" = --context
test "$2" = default
test "$3" = compose
test "$4" = version
EOF
cat > "$mock_bin/age" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$mock_bin/age-keygen" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$mock_bin/ss" <<'EOF'
#!/bin/sh
case "$*" in
  *"sport = :${LANEWAY_TEST_OCCUPIED_PORT:-not-a-port}"*) printf 'occupied fixture\n' ;;
esac
exit 0
EOF
cat > "$mock_bin/getent" <<'EOF'
#!/bin/sh
test "$1" = ahosts
printf '203.0.113.10 STREAM %s\n' "$2"
EOF
cat > "$mock_bin/cosign" <<'EOF'
#!/bin/sh
test "$HOME" = /root
if [ "$*" = 'version --json' ]; then
  printf '%s\n' '{"gitVersion":"v3.1.3"}'
  exit 0
fi
printf 'cosign %s\n' "$*" >> "$LANEWAY_TEST_LOG"
case " $* " in
  *" --certificate-identity https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/v0.2.8 "*) ;;
  *) exit 1 ;;
esac
case "$1" in
  verify) [ "${LANEWAY_TEST_COSIGN_FAIL:-0}" = 0 ] ;;
  verify-blob)
    [ "${LANEWAY_TEST_CHECKSUM_SIGNATURE_FAIL:-0}" = 0 ]
    case " $* " in *" --bundle "*"checksums.sigstore.json "*) ;; *) exit 1 ;; esac
    ;;
  *) exit 1 ;;
esac
EOF
cat > "$mock_bin/curl" <<'EOF'
#!/bin/sh
printf 'curl %s\n' "$*" >> "$LANEWAY_TEST_LOG"
test "$1" = --disable
case " $* " in
  *" --proto =https --proto-redir =https --tlsv1.2 "*) ;;
  *) exit 1 ;;
esac
destination=
source_url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) destination=$2; shift 2 ;;
    https://*) source_url=$1; shift ;;
    *) shift ;;
  esac
done
test -n "$destination" && test -n "$source_url"
case "$source_url" in
  */image-digests.txt)
    cp "$LANEWAY_TEST_DIGESTS" "$destination"
    [ "${LANEWAY_TEST_TAMPER_DIGESTS:-0}" = 0 ] || printf 'tampered\n' >> "$destination"
    ;;
  */checksums.txt)
    digest=$(sha256sum "$LANEWAY_TEST_DIGESTS" | awk '{print $1}')
    printf '%s  image-digests.txt\n' "$digest" > "$destination"
    ;;
  */checksums.sigstore.json) printf 'signed checksum fixture\n' > "$destination" ;;
  *) exit 1 ;;
esac
if [ -n "${LANEWAY_TEST_MUTATE_ISSUER_DIR:-}" ] && \
  [ "$source_url" = "${source_url%/image-digests.txt}/image-digests.txt" ]; then
  for issuer_name in ca.crt intermediate-chain.crt intermediate.key; do
    printf 'mutated %s\n' "$issuer_name" > "$LANEWAY_TEST_MUTATE_ISSUER_DIR/$issuer_name"
  done
fi
EOF
cat > "$mock_bin/laneway" <<'EOF'
#!/bin/sh
test "$1" = id
count=$(cat "$LANEWAY_TEST_COUNTER")
case "$count" in
  0) value=000102030405060708090a0b0c0d0e0f ;;
  1) value=101112131415161718191a1b1c1d1e1f ;;
  2) value=202122232425262728292a2b2c2d2e2f ;;
  *) exit 1 ;;
esac
printf '%s\n' $((count + 1)) > "$LANEWAY_TEST_COUNTER"
printf '%s\n' "$value"
EOF
chmod 0755 "$mock_bin"/*

publish_mock() {
  mock_name=$1
  mock_source=${2:-$mock_bin/$mock_name}
  mock_target=$trusted_mock_dir/$mock_name
  [ ! -e "$mock_target" ] && [ ! -L "$mock_target" ] || {
    echo "trusted mock target already exists: $mock_target" >&2
    exit 1
  }
  /usr/bin/install -m 0755 -o 0 -g 0 "$mock_source" "$mock_target"
  trusted_mocks="$mock_target $trusted_mocks"
}
for mock_name in age age-keygen curl docker getent laneway ss; do
  publish_mock "$mock_name"
done
if [ ! -e /usr/local/libexec ] && [ ! -L /usr/local/libexec ]; then
  /usr/bin/install -d -m 0755 -o 0 -g 0 /usr/local/libexec
  trusted_libexec_claimed=true
fi
[ -d /usr/local/libexec ] && [ ! -L /usr/local/libexec ] || {
  echo "trusted Cosign parent is unavailable" >&2
  exit 1
}
if [ ! -e "$trusted_cosign_parent" ] && [ ! -L "$trusted_cosign_parent" ]; then
  /usr/bin/install -d -m 0755 -o 0 -g 0 "$trusted_cosign_parent"
  trusted_cosign_parent_claimed=true
fi
trusted_cosign=$trusted_cosign_parent/cosign-v3.1.3
[ ! -e "$trusted_cosign" ] && [ ! -L "$trusted_cosign" ] || {
  echo "trusted Cosign fixture already exists: $trusted_cosign" >&2
  exit 1
}
/usr/bin/install -m 0755 -o 0 -g 0 "$mock_bin/cosign" "$trusted_cosign"
trusted_mocks="$trusted_cosign $trusted_mocks"

cat > "$test_root/image-digests.txt" <<'EOF'
ghcr.io/doout/laneway-admin@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ghcr.io/doout/laneway-controller@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
ghcr.io/doout/lane-edge@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
ghcr.io/doout/laneway-exit-node@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
ghcr.io/doout/laneway-relay@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
EOF
printf '0\n' > "$counter_file"

recipient=age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
env \
  PATH="$mock_bin:$PATH" \
  ENV="$test_root/hostile-env" \
  BASH_ENV="$test_root/hostile-bash-env" \
  CDPATH="$test_root" \
  LANEWAY_NONINTERACTIVE=true \
  LANEWAY_VERSION=0.2.8 \
  LANEWAY_DOMAIN=lane.example.test \
  LANEWAY_DEPLOY_DIR="$destination" \
  LANEWAY_BACKUP_RECIPIENT="$recipient" \
  LANEWAY_ISSUER_DIR="$issuer_dir" \
  LANEWAY_CONFIRM=deploy \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  LANEWAY_TEST_MUTATE_ISSUER_DIR="$issuer_dir" \
  LANEWAY_TEST_EXPECTED_ISSUER_PREFIX=fixture \
  LANEWAY_INSTALLER_ANSWERS_FILE="$answers_file" \
  "$source_dir/install-control-plane.sh" >/dev/null

test "$(stat -c %a "$destination")" = 700
test "$(stat -c %a "$destination/.env")" = 600
grep -Fx 'LANEWAY_VERSION=0.2.8' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_INSTALL_PROFILE=quick' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_CONTROLLER_IMAGE_DIGEST=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_CONNECTOR_IMAGE_DIGEST=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_EXIT_NODE_IMAGE_DIGEST=sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_CONTROLLER_SERVER_NAME=lane.example.test' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_RELAY_PUBLIC_ENDPOINT=lane.example.test:4433' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_NETWORK_ID=000102030405060708090a0b0c0d0e0f' "$destination/.env" >/dev/null
managed_keys='LANEWAY_VERSION LANEWAY_INSTALL_PROFILE LANEWAY_CONTROLLER_IMAGE_DIGEST LANEWAY_RELAY_IMAGE_DIGEST LANEWAY_ADMIN_IMAGE_DIGEST LANEWAY_CONNECTOR_IMAGE_DIGEST LANEWAY_EXIT_NODE_IMAGE_DIGEST LANEWAY_BIND_ADDRESS LANEWAY_CONTROLLER_PORT LANEWAY_RELAY_QUIC_PORT LANEWAY_RELAY_TCP_PORT LANEWAY_EXIT_DIRECT_PORT LANEWAY_CONTROLLER_SERVER_NAME LANEWAY_NETWORK_ID LANEWAY_CONTROLLER_SERVICE_ID LANEWAY_RELAY_SERVICE_ID LANEWAY_NETWORK_NAME LANEWAY_IPV4_POOL LANEWAY_RELAY_PUBLIC_ENDPOINT LANEWAY_BACKUP_RECIPIENT'
for managed_key in $managed_keys; do
  test "$(grep -c "^${managed_key}=" "$destination/.env")" -eq 1 || {
    echo "installer did not emit exactly one canonical $managed_key assignment" >&2
    exit 1
  }
done
if grep -Ev '^(#.*|[[:space:]]*|[A-Z][A-Z0-9_]*=[A-Za-z0-9._:/+-]+)$' "$destination/.env" >/dev/null || \
  grep -E '^[[:space:]]*(export[[:space:]]+|COMPOSE_(PROJECT_NAME|PROFILES)[[:space:]]*=)' \
    "$destination/.env" >/dev/null; then
  echo "installer emitted a noncanonical or Compose-control environment assignment" >&2
  exit 1
fi
test "$(grep -c '^cosign verify ' "$log_file")" -eq 5
grep -E '^lane init --issuer /var/tmp/laneway-installer\.[A-Za-z0-9]+/issuer$' "$log_file" >/dev/null
grep -E '^lane backup initial-recovery-[0-9]{8}T[0-9]{6}Z\.age$' "$log_file" >/dev/null
test "$(stat -c %a "$answers_file")" = 600
grep -Fx 'LANEWAY_DOMAIN=lane.example.test' "$answers_file" >/dev/null
grep -Fx 'LANEWAY_CONTROLLER_PORT=8443' "$answers_file" >/dev/null
grep -Fx "LANEWAY_PREPARED_INPUT_DIR=$issuer_dir" "$answers_file" >/dev/null
test -f "$destination/PRODUCTION-CHECKLIST.md"
grep -F 'laneway-control production-check' "$destination/PRODUCTION-CHECKLIST.md" >/dev/null
test -x "$destination/laneway-control"
test -L "$destination/lane"
test "$(readlink "$destination/lane")" = laneway-control
test "$(readlink /usr/local/sbin/laneway-control)" = "$destination/laneway-control"
find /usr/local/sbin/laneway-control -maxdepth 0 -delete

# Compose process controls and Docker daemon selectors are never installer
# inputs. Reject them before fetching metadata, generating identities, writing
# remembered answers, publishing a destination, or installing the system link.
for override_key in \
  COMPOSE_PROJECT_NAME COMPOSE_PROFILES COMPOSE_FILE COMPOSE_PATH_SEPARATOR \
  COMPOSE_ENV_FILES COMPOSE_DISABLE_ENV_FILE COMPOSE_CONVERT_WINDOWS_PATHS \
  COMPOSE_IGNORE_ORPHANS COMPOSE_REMOVE_ORPHANS COMPOSE_PARALLEL_LIMIT \
  COMPOSE_ANSI COMPOSE_PROGRESS COMPOSE_STATUS_STDOUT COMPOSE_MENU \
  COMPOSE_EXPERIMENTAL COMPOSE_BAKE COMPOSE_HTTP_TIMEOUT \
  COMPOSE_UNRECOGNIZED_CONTROL \
  DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH \
  DOCKER_CONFIG COSIGN_REPOSITORY SIGSTORE_TRUST_ROOT_FILE TUF_ROOT \
  CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR \
  LANEWAY_RELEASE_BASE_URL LANEWAY_REPOSITORY \
  LANEWAY_COSIGN_BIN LANEWAY_CHECKSUM_SIGNATURE_VERIFIED
do
  override_destination=$test_root/override-$override_key
  override_answers=$test_root/override-$override_key.answers
  : > "$log_file"
  printf '0\n' > "$counter_file"
  if env "$override_key=shadow" \
    PATH="$mock_bin:$PATH" \
    LANEWAY_NONINTERACTIVE=true \
    LANEWAY_VERSION=0.2.8 \
    LANEWAY_DOMAIN=override.example.test \
    LANEWAY_DEPLOY_DIR="$override_destination" \
    LANEWAY_BACKUP_RECIPIENT="$recipient" \
    LANEWAY_ISSUER_DIR="$issuer_dir" \
    LANEWAY_CONFIRM=deploy \
    LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
    LANEWAY_TEST_COUNTER="$counter_file" \
    LANEWAY_TEST_LOG="$log_file" \
    LANEWAY_INSTALLER_ANSWERS_FILE="$override_answers" \
    "$source_dir/install-control-plane.sh" \
      > /dev/null 2> "$test_root/override-$override_key.err"; then
    echo "installer accepted ambient $override_key" >&2
    exit 1
  fi
  test ! -s "$log_file"
  test "$(sed -n '1p' "$counter_file")" -eq 0
  test ! -e "$override_answers"
  test ! -e "$override_destination"
  test ! -e /usr/local/sbin/laneway-control
done

# Neither a caller-selected executable nor a forged verification boolean can
# cross the inner installer's authenticity boundary.
hostile_cosign=$test_root/hostile-cosign
hostile_cosign_marker=$test_root/hostile-cosign-ran
cat > "$hostile_cosign" <<'EOF'
#!/bin/sh
printf 'executed\n' > "$LANEWAY_TEST_HOSTILE_COSIGN_MARKER"
exit 0
EOF
chmod 0755 "$hostile_cosign"
for forged_trust_case in cosign-path checksum-boolean; do
  forged_destination=$test_root/forged-$forged_trust_case-control-plane
  : > "$log_file"
  printf '0\n' > "$counter_file"
  if [ "$forged_trust_case" = cosign-path ]; then
    forged_name=LANEWAY_COSIGN_BIN
    forged_value=$hostile_cosign
  else
    forged_name=LANEWAY_CHECKSUM_SIGNATURE_VERIFIED
    forged_value=true
  fi
  if env "$forged_name=$forged_value" \
    PATH="$mock_bin:$PATH" \
    LANEWAY_NONINTERACTIVE=true \
    LANEWAY_VERSION=0.2.8 \
    LANEWAY_DOMAIN=forged-trust.example.test \
    LANEWAY_DEPLOY_DIR="$forged_destination" \
    LANEWAY_BACKUP_RECIPIENT="$recipient" \
    LANEWAY_ISSUER_DIR="$issuer_dir" \
    LANEWAY_CONFIRM=deploy \
    LANEWAY_TEST_HOSTILE_COSIGN_MARKER="$hostile_cosign_marker" \
    LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
    LANEWAY_TEST_COUNTER="$counter_file" \
    LANEWAY_TEST_LOG="$log_file" \
    LANEWAY_INSTALLER_ANSWERS_FILE="$test_root/forged-$forged_trust_case.answers" \
    "$source_dir/install-control-plane.sh" >/dev/null \
      2>"$test_root/forged-$forged_trust_case.err"; then
    echo "installer accepted forged trust input $forged_trust_case" >&2
    exit 1
  fi
  test ! -e "$hostile_cosign_marker"
  test ! -s "$log_file"
  test "$(sed -n '1p' "$counter_file")" -eq 0
  test ! -e "$forged_destination"
  test ! -e /usr/local/sbin/laneway-control
done

# Remembered state must live below a physically stable, protected directory.
# Reject an attacker-writable parent and a symbolic-link directory before any
# metadata, identity, deployment, or system-link side effect.
unsafe_answers_parent=$test_root/unsafe-answers-parent
mkdir "$unsafe_answers_parent"
chmod 0777 "$unsafe_answers_parent"
safe_answers_target=$test_root/safe-answers-target
mkdir "$safe_answers_target"
chmod 0700 "$safe_answers_target"
ln -s "$safe_answers_target" "$test_root/answers-link"
for unsafe_answers_case in writable-parent symlink-directory; do
  unsafe_answers=$unsafe_answers_parent/state/answers
  [ "$unsafe_answers_case" != symlink-directory ] || \
    unsafe_answers=$test_root/answers-link/answers
  unsafe_answers_destination=$test_root/unsafe-answers-$unsafe_answers_case-control-plane
  : > "$log_file"
  printf '0\n' > "$counter_file"
  if env \
    PATH="$mock_bin:$PATH" \
    LANEWAY_NONINTERACTIVE=true \
    LANEWAY_VERSION=0.2.8 \
    LANEWAY_DOMAIN=unsafe-answers.example.test \
    LANEWAY_DEPLOY_DIR="$unsafe_answers_destination" \
    LANEWAY_BACKUP_RECIPIENT="$recipient" \
    LANEWAY_ISSUER_DIR="$issuer_dir" \
    LANEWAY_CONFIRM=deploy \
    LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
    LANEWAY_TEST_COUNTER="$counter_file" \
    LANEWAY_TEST_LOG="$log_file" \
    LANEWAY_INSTALLER_ANSWERS_FILE="$unsafe_answers" \
    "$source_dir/install-control-plane.sh" >/dev/null \
      2>"$test_root/unsafe-answers-$unsafe_answers_case.err"; then
    echo "installer accepted unsafe remembered-answer path $unsafe_answers_case" >&2
    exit 1
  fi
  test ! -s "$log_file"
  test "$(sed -n '1p' "$counter_file")" -eq 0
  test ! -e "$unsafe_answers_destination"
  test ! -e /usr/local/sbin/laneway-control
done
test ! -e "$unsafe_answers_parent/state"
test ! -e "$safe_answers_target/answers"

# Occupied fresh-install listeners fail before metadata, issuer staging,
# remembered answers, recovery generation, destination claim, or system link.
occupied_destination=$test_root/occupied-control-plane
occupied_answers=$test_root/occupied.answers
: > "$log_file"
printf '0\n' > "$counter_file"
if env \
  PATH="$mock_bin:$PATH" \
  LANEWAY_NONINTERACTIVE=true \
  LANEWAY_VERSION=0.2.8 \
  LANEWAY_DOMAIN=occupied.example.test \
  LANEWAY_DEPLOY_DIR="$occupied_destination" \
  LANEWAY_BACKUP_RECIPIENT="$recipient" \
  LANEWAY_ISSUER_DIR="$issuer_dir" \
  LANEWAY_CONFIRM=deploy \
  LANEWAY_TEST_OCCUPIED_PORT=8443 \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  LANEWAY_INSTALLER_ANSWERS_FILE="$occupied_answers" \
  "$source_dir/install-control-plane.sh" >/dev/null 2>"$test_root/occupied.err"; then
  echo "installer accepted an occupied controller port" >&2
  exit 1
fi
grep -F 'tcp port 8443 is already occupied' "$test_root/occupied.err" >/dev/null
test ! -s "$log_file"
test "$(sed -n '1p' "$counter_file")" -eq 0
test ! -e "$occupied_answers"
test ! -e "$occupied_destination"
test ! -e /usr/local/sbin/laneway-control

# Paths with shell separators, noncanonical/volatile physical paths, unsafe
# parents, and noncanonical bind addresses are rejected before side effects.
ln -s /dev/shm "$test_root/dev-shm-alias"
unsafe_deploy_parent=$test_root/unsafe-deploy-parent
mkdir "$unsafe_deploy_parent"
chmod 0777 "$unsafe_deploy_parent"
for invalid_input in \
  unsafe-deployment-path noncanonical-deployment-path dev-shm-alias \
  unsafe-writable-parent noncanonical-bind-address
do
  invalid_destination=$test_root/invalid-input-$invalid_input
  invalid_bind=127.0.0.1
  [ "$invalid_input" != unsafe-deployment-path ] || invalid_destination="$test_root/invalid path"
  [ "$invalid_input" != noncanonical-deployment-path ] || invalid_destination=/tmp/../dev/shm/laneway-invalid-deployment
  [ "$invalid_input" != dev-shm-alias ] || invalid_destination=$test_root/dev-shm-alias/laneway-invalid-deployment
  [ "$invalid_input" != unsafe-writable-parent ] || invalid_destination=$unsafe_deploy_parent/control-plane
  [ "$invalid_input" != noncanonical-bind-address ] || invalid_bind=127.000.0.1
  invalid_answers=$test_root/invalid-input-$invalid_input.answers
  : > "$log_file"
  printf '0\n' > "$counter_file"
  if env \
    PATH="$mock_bin:$PATH" \
    LANEWAY_NONINTERACTIVE=true \
    LANEWAY_VERSION=0.2.8 \
    LANEWAY_DOMAIN=invalid.example.test \
    LANEWAY_DEPLOY_DIR="$invalid_destination" \
    LANEWAY_BIND_ADDRESS="$invalid_bind" \
    LANEWAY_CONFIRM=deploy \
    LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
    LANEWAY_TEST_COUNTER="$counter_file" \
    LANEWAY_TEST_LOG="$log_file" \
    LANEWAY_INSTALLER_ANSWERS_FILE="$invalid_answers" \
    "$source_dir/install-control-plane.sh" >/dev/null 2>"$test_root/invalid-input-$invalid_input.err"; then
    echo "installer accepted $invalid_input" >&2
    exit 1
  fi
  test ! -s "$log_file"
  test "$(sed -n '1p' "$counter_file")" -eq 0
  test ! -e "$invalid_answers"
  test ! -e "$invalid_destination"
  test ! -e /usr/local/sbin/laneway-control
done

# Invalid pools are local input errors. They must fail before remote metadata,
# signatures, generated identities, destination publication, or system links.
for invalid_pool in 100.96.1.0/16 100.96.0.0/31 127.0.0.0/16; do
  invalid_name=$(printf '%s' "$invalid_pool" | tr './' '__')
  invalid_destination=$test_root/invalid-pool-$invalid_name
  : > "$log_file"
  printf '0\n' > "$counter_file"
  if env \
    PATH="$mock_bin:$PATH" \
    LANEWAY_NONINTERACTIVE=true \
    LANEWAY_VERSION=0.2.8 \
    LANEWAY_DOMAIN=invalid.example.test \
    LANEWAY_DEPLOY_DIR="$invalid_destination" \
    LANEWAY_IPV4_POOL="$invalid_pool" \
    LANEWAY_CONFIRM=deploy \
    LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
    LANEWAY_TEST_COUNTER="$counter_file" \
    LANEWAY_TEST_LOG="$log_file" \
    LANEWAY_INSTALLER_ANSWERS_FILE="$test_root/invalid-$invalid_name.answers" \
    "$source_dir/install-control-plane.sh" >/dev/null 2>"$test_root/invalid-$invalid_name.err"; then
    echo "installer accepted invalid overlay pool $invalid_pool" >&2
    exit 1
  fi
  test ! -s "$log_file"
  test "$(sed -n '1p' "$counter_file")" -eq 0
  test ! -e "$invalid_destination"
  test ! -e /usr/local/sbin/laneway-control
done

# Deployment and generated recovery paths are compared after physical parent
# resolution, including aliases, and recovery output cannot land on tmpfs.
physical_parent=$test_root/physical-parent
mkdir "$physical_parent"
ln -s "$physical_parent" "$test_root/physical-parent-alias"
for overlap_case in exact physical-alias recovery-dev-shm; do
  overlap_destination=$test_root/overlap-$overlap_case
  overlap_recovery=$overlap_destination
  case "$overlap_case" in
    physical-alias)
      overlap_destination=$test_root/physical-parent-alias/control-plane
      overlap_recovery=$physical_parent/control-plane
      ;;
    recovery-dev-shm)
      overlap_destination=$test_root/dev-shm-recovery-control-plane
      overlap_recovery=$test_root/dev-shm-alias/laneway-invalid-recovery
      ;;
  esac
  : > "$log_file"
  printf '0\n' > "$counter_file"
  if env \
    PATH="$mock_bin:$PATH" \
    LANEWAY_NONINTERACTIVE=true \
    LANEWAY_VERSION=0.2.8 \
    LANEWAY_DOMAIN=overlap.example.test \
    LANEWAY_DEPLOY_DIR="$overlap_destination" \
    LANEWAY_RECOVERY_KIT_DIR="$overlap_recovery" \
    LANEWAY_CONFIRM=deploy \
    LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
    LANEWAY_TEST_COUNTER="$counter_file" \
    LANEWAY_TEST_LOG="$log_file" \
    LANEWAY_INSTALLER_ANSWERS_FILE="$test_root/overlap-$overlap_case.answers" \
    "$source_dir/install-control-plane.sh" >/dev/null 2>"$test_root/overlap-$overlap_case.err"; then
    echo "installer accepted unsafe recovery path case $overlap_case" >&2
    exit 1
  fi
  test ! -s "$log_file"
  test "$(sed -n '1p' "$counter_file")" -eq 0
  test ! -e "$overlap_destination"
  test ! -e /usr/local/sbin/laneway-control
done

# Prepared issuer input is snapshotted only from a protected, single-link
# source and cannot contain the future deployment directory.
issuer_overlap=$test_root/issuer-overlap
mkdir "$issuer_overlap"
chmod 0700 "$issuer_overlap"
for issuer_name in ca.crt intermediate-chain.crt intermediate.key; do
  printf 'fixture %s\n' "$issuer_name" > "$issuer_overlap/$issuer_name"
done
chmod 0444 "$issuer_overlap/ca.crt" "$issuer_overlap/intermediate-chain.crt"
chmod 0400 "$issuer_overlap/intermediate.key"
issuer_overlap_destination=$issuer_overlap/control-plane
: > "$log_file"
printf '0\n' > "$counter_file"
if env \
  PATH="$mock_bin:$PATH" \
  LANEWAY_NONINTERACTIVE=true \
  LANEWAY_VERSION=0.2.8 \
  LANEWAY_DOMAIN=issuer-overlap.example.test \
  LANEWAY_DEPLOY_DIR="$issuer_overlap_destination" \
  LANEWAY_BACKUP_RECIPIENT="$recipient" \
  LANEWAY_ISSUER_DIR="$issuer_overlap" \
  LANEWAY_CONFIRM=deploy \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  LANEWAY_INSTALLER_ANSWERS_FILE="$test_root/issuer-overlap.answers" \
  "$source_dir/install-control-plane.sh" >/dev/null 2>"$test_root/issuer-overlap.err"; then
  echo "installer accepted prepared input overlapping deployment" >&2
  exit 1
fi
test ! -s "$log_file"
test ! -e "$issuer_overlap_destination"

unsafe_issuer=$test_root/unsafe-issuer
mkdir "$unsafe_issuer"
chmod 0700 "$unsafe_issuer"
for issuer_name in ca.crt intermediate-chain.crt intermediate.key; do
  printf 'fixture %s\n' "$issuer_name" > "$unsafe_issuer/$issuer_name"
done
chmod 0444 "$unsafe_issuer/ca.crt" "$unsafe_issuer/intermediate-chain.crt"
chmod 0400 "$unsafe_issuer/intermediate.key"
ln "$unsafe_issuer/ca.crt" "$unsafe_issuer/ca.crt.extra-link"
unsafe_issuer_destination=$test_root/unsafe-issuer-control-plane
: > "$log_file"
printf '0\n' > "$counter_file"
if env \
  PATH="$mock_bin:$PATH" \
  LANEWAY_NONINTERACTIVE=true \
  LANEWAY_VERSION=0.2.8 \
  LANEWAY_DOMAIN=unsafe-issuer.example.test \
  LANEWAY_DEPLOY_DIR="$unsafe_issuer_destination" \
  LANEWAY_BACKUP_RECIPIENT="$recipient" \
  LANEWAY_ISSUER_DIR="$unsafe_issuer" \
  LANEWAY_CONFIRM=deploy \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  LANEWAY_INSTALLER_ANSWERS_FILE="$test_root/unsafe-issuer.answers" \
  "$source_dir/install-control-plane.sh" >/dev/null 2>"$test_root/unsafe-issuer.err"; then
  echo "installer accepted hard-linked prepared input" >&2
  exit 1
fi
test ! -s "$log_file"
test ! -e "$unsafe_issuer_destination"

remembered_cancel=$test_root/remembered-cancel
printf '0\n' > "$counter_file"
if env \
  PATH="$mock_bin:$PATH" \
  LANEWAY_NONINTERACTIVE=true \
  LANEWAY_VERSION=0.2.8 \
  LANEWAY_DEPLOY_DIR="$remembered_cancel" \
  LANEWAY_CONFIRM=no \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  LANEWAY_INSTALLER_ANSWERS_FILE="$answers_file" \
  "$source_dir/install-control-plane.sh" >/dev/null 2>"$test_root/remembered.err"; then
  echo "installer accepted a remembered deployment without confirmation" >&2
  exit 1
fi
grep -F 'cancelled before changing the deployment' "$test_root/remembered.err" >/dev/null
test ! -e "$remembered_cancel"

# The image manifest must match the selected release's independently verified
# checksum set. A tampered manifest fails before remembered state, identities,
# recovery output, destination publication, or the system link.
tampered_manifest_destination=$test_root/tampered-manifest-control-plane
tampered_manifest_answers=$test_root/tampered-manifest.answers
: > "$log_file"
printf '0\n' > "$counter_file"
if env \
  PATH="$mock_bin:$PATH" \
  LANEWAY_NONINTERACTIVE=true \
  LANEWAY_VERSION=0.2.8 \
  LANEWAY_DOMAIN=tampered-manifest.example.test \
  LANEWAY_DEPLOY_DIR="$tampered_manifest_destination" \
  LANEWAY_BACKUP_RECIPIENT="$recipient" \
  LANEWAY_ISSUER_DIR="$issuer_dir" \
  LANEWAY_CONFIRM=deploy \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_TAMPER_DIGESTS=1 \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  LANEWAY_INSTALLER_ANSWERS_FILE="$tampered_manifest_answers" \
  "$source_dir/install-control-plane.sh" >/dev/null \
    2>"$test_root/tampered-manifest.err"; then
  echo "installer accepted image metadata outside the signed checksum set" >&2
  exit 1
fi
grep -F 'signed release checksum does not match image-digests.txt' \
  "$test_root/tampered-manifest.err" >/dev/null
test "$(sed -n '1p' "$counter_file")" -eq 0
test ! -e "$tampered_manifest_answers"
test ! -e "$tampered_manifest_destination"
test ! -e /usr/local/sbin/laneway-control

# Quick setup has the same authenticity boundary as production: a failed
# image signature stops before destination publication or the system link.
quick_signature_failed=$test_root/quick-signature-failed
printf '0\n' > "$counter_file"
if env \
  PATH="$mock_bin:$PATH" \
  LANEWAY_NONINTERACTIVE=true \
  LANEWAY_VERSION=0.2.8 \
  LANEWAY_DOMAIN=quick-signature.example.test \
  LANEWAY_DEPLOY_DIR="$quick_signature_failed" \
  LANEWAY_BACKUP_RECIPIENT="$recipient" \
  LANEWAY_ISSUER_DIR="$issuer_dir" \
  LANEWAY_CONFIRM=deploy \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  LANEWAY_TEST_COSIGN_FAIL=1 \
  LANEWAY_INSTALLER_ANSWERS_FILE="$test_root/quick-signature.answers" \
  "$source_dir/install-control-plane.sh" >/dev/null \
    2>"$test_root/quick-signature.err"; then
  echo "quick installer accepted failed image signatures" >&2
  exit 1
fi
grep -F 'image signature verification failed' "$test_root/quick-signature.err" >/dev/null
test ! -e "$quick_signature_failed"
test ! -e /usr/local/sbin/laneway-control

automatic=$test_root/automatic-control-plane
automatic_kit=$test_root/automatic-recovery-kit
automatic_answers=$test_root/automatic-installer-state/answers
printf '0\n' > "$counter_file"
env \
  PATH="$mock_bin:$PATH" \
  LANEWAY_NONINTERACTIVE=true \
  LANEWAY_VERSION=0.2.8 \
  LANEWAY_DOMAIN=auto.example.test \
  LANEWAY_DEPLOY_DIR="$automatic" \
  LANEWAY_RECOVERY_KIT_DIR="$automatic_kit" \
  LANEWAY_CONFIRM=deploy \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  LANEWAY_INSTALLER_ANSWERS_FILE="$automatic_answers" \
  "$source_dir/install-control-plane.sh" >/dev/null
test -f "$automatic_kit/laneway-recovery.identity"
test -f "$automatic_kit/offline-root.tar.age"
test -f "$automatic_kit/DEPLOYED.txt"
test -f "$automatic_kit/MANIFEST.sha256"
test ! -e "$automatic_kit/control-plane-input"
test "$(find "$automatic_kit" -maxdepth 1 -name 'initial-recovery-*.age' | wc -l)" -eq 1
grep -Fx "LANEWAY_BACKUP_RECIPIENT=$recipient" "$automatic/.env" >/dev/null
grep -Fx 'LANEWAY_INSTALL_PROFILE=quick' "$automatic/.env" >/dev/null
grep -F 'All container image signatures verified: **true**' "$automatic/PRODUCTION-CHECKLIST.md" >/dev/null
find /usr/local/sbin/laneway-control -maxdepth 0 -delete

production_failed=$test_root/production-failed
printf '0\n' > "$counter_file"
if env \
  PATH="$mock_bin:$PATH" \
  LANEWAY_NONINTERACTIVE=true \
  LANEWAY_VERSION=0.2.8 \
  LANEWAY_PRODUCTION_MODE=true \
  LANEWAY_DOMAIN=prod.example.test \
  LANEWAY_DEPLOY_DIR="$production_failed" \
  LANEWAY_BACKUP_RECIPIENT="$recipient" \
  LANEWAY_ISSUER_DIR="$issuer_dir" \
  LANEWAY_CONFIRM=deploy \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  LANEWAY_TEST_COSIGN_FAIL=1 \
  LANEWAY_INSTALLER_ANSWERS_FILE="$test_root/production-installer-state/answers" \
  "$source_dir/install-control-plane.sh" >/dev/null 2>"$test_root/production.err"; then
  echo "production installer accepted failed image signatures" >&2
  exit 1
fi
grep -F 'image signature verification failed' "$test_root/production.err" >/dev/null
test ! -e "$production_failed"

cancelled=$test_root/cancelled
printf '0\n' > "$counter_file"
if env \
  PATH="$mock_bin:$PATH" \
  LANEWAY_NONINTERACTIVE=true \
  LANEWAY_VERSION=0.2.8 \
  LANEWAY_DOMAIN=lane.example.test \
  LANEWAY_DEPLOY_DIR="$cancelled" \
  LANEWAY_BACKUP_RECIPIENT="$recipient" \
  LANEWAY_ISSUER_DIR="$issuer_dir" \
  LANEWAY_CONFIRM=no \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  LANEWAY_INSTALLER_ANSWERS_FILE="$test_root/cancelled-installer-state/answers" \
  "$source_dir/install-control-plane.sh" >/dev/null 2>&1; then
  echo "installer accepted a deployment without explicit confirmation" >&2
  exit 1
fi
test ! -e "$cancelled"

# A competing creator that wins the destination mkdir is never reused or
# removed by installer cleanup.
claim_race_bin=$test_root/claim-race-bin
claim_race_destination=$test_root/claim-race-control-plane
mkdir "$claim_race_bin"
cat > "$claim_race_bin/mkdir" <<'EOF'
#!/bin/sh
if [ "$#" -eq 1 ] && [ "$1" = "$LANEWAY_TEST_RACE_DESTINATION" ]; then
  /bin/mkdir "$1"
  printf 'competitor\n' > "$1/owner"
  exit 1
fi
exec /bin/mkdir "$@"
EOF
chmod 0755 "$claim_race_bin/mkdir"
publish_mock mkdir "$claim_race_bin/mkdir"
printf '0\n' > "$counter_file"
if env \
  PATH="$claim_race_bin:$mock_bin:$PATH" \
  LANEWAY_NONINTERACTIVE=true \
  LANEWAY_VERSION=0.2.8 \
  LANEWAY_DOMAIN=race.example.test \
  LANEWAY_DEPLOY_DIR="$claim_race_destination" \
  LANEWAY_BACKUP_RECIPIENT="$recipient" \
  LANEWAY_ISSUER_DIR="$issuer_dir" \
  LANEWAY_CONFIRM=deploy \
  LANEWAY_TEST_RACE_DESTINATION="$claim_race_destination" \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  LANEWAY_INSTALLER_ANSWERS_FILE="$test_root/claim-race.answers" \
  "$source_dir/install-control-plane.sh" >/dev/null 2>"$test_root/claim-race.err"; then
  echo "installer reused a destination won by a competing creator" >&2
  exit 1
fi
grep -Fx competitor "$claim_race_destination/owner" >/dev/null
test ! -e /usr/local/sbin/laneway-control

echo "Interactive control-plane installer contract is valid"
