#!/bin/sh
set -eu

command -v jq >/dev/null 2>&1 || { echo "control-plane bootstrap integration requires jq" >&2; exit 1; }

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d)
test_dir=$(CDPATH='' cd -- "$test_dir" && pwd -P)
trap 'find "$test_dir" -depth -delete' EXIT HUP INT TERM
compose_dir=$test_dir/compose
fake_bin=$test_dir/bin
log=$test_dir/calls.log
relay_marker=$test_dir/relay.registered
system_control=$test_dir/system-laneway-control
mkdir -p "$compose_dir/generated/secrets" "$fake_bin"
for runtime_name in bootstrap.sh laneway-control; do
  sed \
    -e "s|^PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\$|PATH=$fake_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin|" \
    -e "s|/usr/local/bin/laneway|$fake_bin/laneway|g" \
    -e "s|/usr/local/libexec/laneway/cosign-v3.1.3|$fake_bin/cosign|g" \
    -e "s|/usr/local/sbin/laneway-control|$system_control|g" \
    "$repo_dir/deploy/compose/$runtime_name" > "$compose_dir/$runtime_name"
done
chmod 0755 "$compose_dir/bootstrap.sh" "$compose_dir/laneway-control"
upgrader_under_test=$test_dir/upgrade-control-plane.sh
sed \
  -e "s|^PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\$|PATH=$fake_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin|" \
  -e "s|/usr/local/bin/laneway|$fake_bin/laneway|g" \
  "$repo_dir/deploy/compose/upgrade-control-plane.sh" > "$upgrader_under_test"
chmod 0755 "$upgrader_under_test"
cp "$repo_dir/deploy/compose/compose.yaml" "$compose_dir/compose.yaml"
: > "$log"
printf '%s\n' 'root-bearer-must-not-be-logged' > "$compose_dir/generated/secrets/admin.token"

cat > "$compose_dir/validate.sh" <<'EOF'
#!/bin/sh
set -eu
if [ "${LANE_TEST_REQUIRE_LOCK:-0}" = 1 ]; then
  test -d "$LANEWAY_DEPLOY_DIR/generated/lifecycle/operator.lock"
  test ! -L "$LANEWAY_DEPLOY_DIR/generated/lifecycle/operator.lock"
fi
printf '%s\n' validate >> "$LANE_TEST_LOG"
EOF
cat > "$compose_dir/preflight.sh" <<'EOF'
#!/bin/sh
set -eu
if [ "${LANE_TEST_REQUIRE_LOCK:-0}" = 1 ]; then
  test -d "$LANEWAY_DEPLOY_DIR/generated/lifecycle/operator.lock"
  test ! -L "$LANEWAY_DEPLOY_DIR/generated/lifecycle/operator.lock"
fi
printf '%s\n' preflight >> "$LANE_TEST_LOG"
EOF
cat > "$fake_bin/cosign" <<'EOF'
#!/bin/sh
set -eu
if [ "${1:-}" = version ] && [ "${2:-}" = --json ]; then
  printf '{"gitVersion":"%s"}\n' "${LANE_TEST_COSIGN_VERSION:-v3.1.3}"
  exit 0
fi
printf 'cosign' >> "$LANE_TEST_LOG"
printf ' <%s>' "$@" >> "$LANE_TEST_LOG"
printf '\n' >> "$LANE_TEST_LOG"
EOF
cat > "$fake_bin/stat" <<'EOF'
#!/bin/sh
set -eu
path=${3:-}
case "${2:-}:$path" in
  %u:%g:%h:*/cosign)
    case "${LANE_TEST_COSIGN_METADATA:-protected}" in
      hardlink) printf '%s\n' 0:0:2 ;;
      *) printf '%s\n' 0:0:1 ;;
    esac
    ;;
  %a:%u:%g:/var/tmp) printf '%s\n' 1777:0:0 ;;
  %a:%u:%g:*) printf '%s\n' 755:0:0 ;;
  %u:%g:/root|%u:%g:/root/.docker|%u:%g:/) printf '%s\n' 0:0 ;;
  %a:/root|%a:/root/.docker) printf '%s\n' 700 ;;
  %a:/) printf '%s\n' 755 ;;
  *) /usr/bin/stat "$@" ;;
esac
EOF
cat > "$fake_bin/docker" <<'EOF'
#!/bin/sh
set -eu
if [ "${LANE_TEST_ASSERT_DOCKER_CONTEXT:-0}" = 1 ]; then
  [ "${1:-}" = --context ] && [ "${2:-}" = default ] || {
    echo "Docker command was not pinned to the default daemon context" >&2
    exit 1
  }
fi
if [ "${LANE_TEST_ASSERT_DOCKER_CONTEXT:-0}" = 1 ]; then
  [ "${DOCKER_CONFIG:-}" = /root/.docker ] && [ "${HOME:-}" = /root ] || {
    echo "Docker client configuration was not pinned to the trusted root path" >&2
    exit 1
  }
fi
if [ "${LANE_TEST_ASSERT_COMPOSE_ENV_CLEAN:-0}" = 1 ]; then
  for environment_name in \
    LANEWAY_VERSION LANEWAY_CONTROLLER_IMAGE_DIGEST LANEWAY_RELAY_IMAGE_DIGEST \
    LANEWAY_ADMIN_IMAGE_DIGEST LANEWAY_CONNECTOR_IMAGE_DIGEST \
    LANEWAY_EXIT_NODE_IMAGE_DIGEST LANEWAY_BIND_ADDRESS LANEWAY_CONTROLLER_PORT \
    LANEWAY_RELAY_QUIC_PORT LANEWAY_RELAY_TCP_PORT LANEWAY_EXIT_DIRECT_PORT \
    LANEWAY_CONTROLLER_SERVER_NAME COMPOSE_PROJECT_NAME COMPOSE_PROFILES \
    COMPOSE_FILE COMPOSE_ENV_FILES DOCKER_DEFAULT_PLATFORM
  do
    eval "environment_present=\${${environment_name}+x}"
    if [ "$environment_present" = x ]; then
      echo "Compose inherited forbidden environment variable $environment_name" >&2
      exit 1
    fi
  done
fi
if [ "${LANE_TEST_REQUIRE_LOCK:-0}" = 1 ]; then
  test -d "$LANEWAY_DEPLOY_DIR/generated/lifecycle/operator.lock"
  test ! -L "$LANEWAY_DEPLOY_DIR/generated/lifecycle/operator.lock"
fi
printf 'docker' >> "$LANE_TEST_LOG"
printf ' <%s>' "$@" >> "$LANE_TEST_LOG"
printf '\n' >> "$LANE_TEST_LOG"
case " $* " in
  *" admin controller network get "*)
    case "${LANE_TEST_NETWORK_MODE:-exact}" in
      exact)
        printf '%s\n' '{"network_id":"11111111111111111111111111111111","name":"production","ipv4_pool":"100.96.0.0/16"}'
        ;;
      missing) exit 1 ;;
      mismatch)
        printf '%s\n' '{"network_id":"11111111111111111111111111111111","name":"foreign","ipv4_pool":"100.96.0.0/16"}'
        ;;
      wrong-id) printf '%s\n' '{"network_id":"99999999999999999999999999999999","name":"production","ipv4_pool":"100.96.0.0/16"}' ;;
      malformed) printf '%s\n' '{"network_id":' ;;
      multiple)
        printf '%s\n' \
          '{"network_id":"11111111111111111111111111111111","name":"production","ipv4_pool":"100.96.0.0/16"}' \
          '{"network_id":"11111111111111111111111111111111","name":"production","ipv4_pool":"100.96.0.0/16"}'
        ;;
      *) exit 1 ;;
    esac
    ;;
  *" admin controller relay list "*)
    if [ -f "$LANE_TEST_RELAY_MARKER" ]; then
      printf '%s\n' '{"relays":[{"service_id":"33333333333333333333333333333333","enabled":true,"endpoint":"relay.example.test:4433"}]}'
    else
      printf '%s\n' '{"relays":[]}'
    fi
    ;;
  *" admin controller relay register "*)
    : > "$LANE_TEST_RELAY_MARKER"
    printf '%s\n' '{"registered":true}'
    ;;
esac
EOF
chmod 0755 "$compose_dir/validate.sh" "$compose_dir/preflight.sh" "$fake_bin/cosign" "$fake_bin/docker" "$fake_bin/stat"

cat > "$compose_dir/.env" <<'EOF'
LANEWAY_VERSION=1.0.0
LANEWAY_INSTALL_PROFILE=quick
LANEWAY_CONTROLLER_IMAGE_DIGEST=sha256:1111111111111111111111111111111111111111111111111111111111111111
LANEWAY_RELAY_IMAGE_DIGEST=sha256:2222222222222222222222222222222222222222222222222222222222222222
LANEWAY_ADMIN_IMAGE_DIGEST=sha256:3333333333333333333333333333333333333333333333333333333333333333
LANEWAY_CONNECTOR_IMAGE_DIGEST=sha256:5555555555555555555555555555555555555555555555555555555555555555
LANEWAY_EXIT_NODE_IMAGE_DIGEST=sha256:4444444444444444444444444444444444444444444444444444444444444444
LANEWAY_BIND_ADDRESS=127.0.0.1
LANEWAY_CONTROLLER_PORT=8443
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

export PATH="$fake_bin:$PATH" LANE_TEST_LOG="$log" LANE_TEST_RELAY_MARKER="$relay_marker" \
  LANEWAY_DEPLOY_DIR="$compose_dir"

LANE_TEST_NETWORK_MODE=exact "$compose_dir/bootstrap.sh" >/dev/null
controller_start=$(grep -n '<up> <-d> <controller> <--wait>' "$log" | cut -d: -f1)
network_verify=$(grep -n '<admin> <controller> <network> <get>' "$log" | cut -d: -f1)
relay_register=$(grep -n '<admin> <controller> <relay> <register>' "$log" | cut -d: -f1)
relay_start=$(grep -n '<up> <-d> <relay> <--wait>' "$log" | cut -d: -f1)
[ "$controller_start" -lt "$network_verify" ]
[ "$network_verify" -lt "$relay_register" ]
[ "$relay_register" -lt "$relay_start" ]
if grep -F '<network> <create>' "$log" >/dev/null; then
  echo "bootstrap duplicated controller-owned initial-network creation" >&2
  exit 1
fi
if grep -F '<network> <list>' "$log" >/dev/null; then
  echo "bootstrap used a bounded list instead of exact initial-network lookup" >&2
  exit 1
fi
if grep -F 'root-bearer-must-not-be-logged' "$log" >/dev/null; then
  echo "bootstrap exposed the administrator bearer" >&2
  exit 1
fi

LANE_TEST_NETWORK_MODE=exact "$compose_dir/bootstrap.sh" >/dev/null
[ "$(grep -c '<admin> <controller> <relay> <register>' "$log")" -eq 1 ] || {
  echo "idempotent bootstrap registered the relay twice" >&2
  exit 1
}

for network_mode in missing mismatch wrong-id malformed multiple; do
  : > "$log"
  if LANE_TEST_NETWORK_MODE=$network_mode "$compose_dir/bootstrap.sh" >/dev/null 2> "$test_dir/$network_mode.err"; then
    echo "bootstrap accepted $network_mode controller initial-network state" >&2
    exit 1
  fi
  if grep -E '<relay> <(list|register)>|<up> <-d> <relay>' "$log" >/dev/null; then
    echo "bootstrap reached relay mutation after $network_mode initial-network state" >&2
    exit 1
  fi
done
grep -F 'did not expose configured initial network' "$test_dir/missing.err" >/dev/null
grep -F 'does not match .env' "$test_dir/mismatch.err" >/dev/null
grep -F 'does not match .env' "$test_dir/wrong-id.err" >/dev/null
grep -F 'does not match .env' "$test_dir/malformed.err" >/dev/null
grep -F 'does not match .env' "$test_dir/multiple.err" >/dev/null

# The supported entry point owns the shared lifecycle lock across preflight,
# pull, controller startup, exact network verification, and relay registration.
find "$relay_marker" -maxdepth 0 -delete
: > "$log"
LANE_TEST_REQUIRE_LOCK=1 LANE_TEST_NETWORK_MODE=exact \
  "$compose_dir/laneway-control" init >/dev/null
test ! -e "$compose_dir/generated/lifecycle/operator.lock"
grep -F '<pull>' "$log" >/dev/null
grep -F '<admin> <controller> <network> <get>' "$log" >/dev/null

: > "$log"
if LANE_TEST_REQUIRE_LOCK=1 LANE_TEST_NETWORK_MODE=missing \
  "$compose_dir/laneway-control" init >/dev/null 2>&1; then
  echo "locked init accepted a missing controller initial network" >&2
  exit 1
fi
test ! -e "$compose_dir/generated/lifecycle/operator.lock"

mkdir "$compose_dir/generated/lifecycle/operator.lock"
if "$compose_dir/laneway-control" init >/dev/null 2>&1; then
  echo "init accepted a concurrent lifecycle operation" >&2
  exit 1
fi
rmdir "$compose_dir/generated/lifecycle/operator.lock"

# Every managed setting has one canonical assignment grammar. A second
# assignment-shaped mention in shell export syntax must fail before validation,
# signature verification, Docker, or bootstrap can observe it.
env_source=$test_dir/canonical.env
cp "$compose_dir/.env" "$env_source"
managed_keys='LANEWAY_VERSION LANEWAY_INSTALL_PROFILE LANEWAY_CONTROLLER_IMAGE_DIGEST LANEWAY_RELAY_IMAGE_DIGEST LANEWAY_ADMIN_IMAGE_DIGEST LANEWAY_CONNECTOR_IMAGE_DIGEST LANEWAY_EXIT_NODE_IMAGE_DIGEST LANEWAY_BIND_ADDRESS LANEWAY_CONTROLLER_PORT LANEWAY_RELAY_QUIC_PORT LANEWAY_RELAY_TCP_PORT LANEWAY_EXIT_DIRECT_PORT LANEWAY_CONTROLLER_SERVER_NAME LANEWAY_NETWORK_ID LANEWAY_CONTROLLER_SERVICE_ID LANEWAY_RELAY_SERVICE_ID LANEWAY_NETWORK_NAME LANEWAY_IPV4_POOL LANEWAY_RELAY_PUBLIC_ENDPOINT LANEWAY_BACKUP_RECIPIENT'
required_keys='LANEWAY_VERSION LANEWAY_INSTALL_PROFILE LANEWAY_CONTROLLER_IMAGE_DIGEST LANEWAY_RELAY_IMAGE_DIGEST LANEWAY_ADMIN_IMAGE_DIGEST LANEWAY_EXIT_NODE_IMAGE_DIGEST LANEWAY_BIND_ADDRESS LANEWAY_RELAY_QUIC_PORT LANEWAY_RELAY_TCP_PORT LANEWAY_EXIT_DIRECT_PORT LANEWAY_CONTROLLER_SERVER_NAME LANEWAY_NETWORK_ID LANEWAY_CONTROLLER_SERVICE_ID LANEWAY_RELAY_SERVICE_ID LANEWAY_NETWORK_NAME LANEWAY_IPV4_POOL LANEWAY_RELAY_PUBLIC_ENDPOINT LANEWAY_BACKUP_RECIPIENT'

assert_env_rejected_before_side_effects() {
  fixture_name=$1
  fixture_env=$2
  cp "$fixture_env" "$compose_dir/.env"
  chmod 0600 "$compose_dir/.env"
  find "$relay_marker" -maxdepth 0 -delete 2>/dev/null || true
  : > "$log"
  if "$compose_dir/laneway-control" init \
    > /dev/null 2> "$test_dir/$fixture_name.err"; then
    echo "init accepted adversarial environment fixture $fixture_name" >&2
    exit 1
  fi
  test ! -s "$log" || {
    echo "init reached a side effect for adversarial environment fixture $fixture_name" >&2
    exit 1
  }
  test ! -e "$relay_marker"
  test ! -e "$compose_dir/generated/lifecycle/operator.lock"
}

for managed_key in $managed_keys; do
  fixture=$test_dir/export-$managed_key.env
  cp "$env_source" "$fixture"
  canonical_value=$(sed -n "s/^${managed_key}=//p" "$env_source")
  printf 'export %s=%s\n' "$managed_key" "$canonical_value" >> "$fixture"
  assert_env_rejected_before_side_effects "export-$managed_key" "$fixture"
done

for required_key in $required_keys; do
  fixture=$test_dir/absent-$required_key.env
  grep -v "^${required_key}=" "$env_source" > "$fixture"
  assert_env_rejected_before_side_effects "absent-$required_key" "$fixture"
done

empty_connector_env=$test_dir/empty-connector.env
sed 's/^LANEWAY_CONNECTOR_IMAGE_DIGEST=.*/LANEWAY_CONNECTOR_IMAGE_DIGEST=/' \
  "$env_source" > "$empty_connector_env"
assert_env_rejected_before_side_effects empty-connector "$empty_connector_env"

# Semantic release-environment validation belongs to the wrapper boundary, so
# malformed addressing and identity inputs fail before Cosign, Docker, or any
# controller request can run.
for semantic_fixture in \
  'noncanonical-bind|LANEWAY_BIND_ADDRESS|127.00.0.1' \
  'noncanonical-pool|LANEWAY_IPV4_POOL|100.96.1.0/16' \
  'reserved-pool|LANEWAY_IPV4_POOL|127.0.0.0/16' \
  'wide-prefix|LANEWAY_IPV4_POOL|100.96.0.0/31' \
  'zero-network-id|LANEWAY_NETWORK_ID|00000000000000000000000000000000' \
  'duplicate-service-id|LANEWAY_RELAY_SERVICE_ID|22222222222222222222222222222222' \
  'unsafe-network-name|LANEWAY_NETWORK_NAME|foreign+network'
do
  semantic_name=${semantic_fixture%%|*}
  semantic_remainder=${semantic_fixture#*|}
  semantic_key=${semantic_remainder%%|*}
  semantic_value=${semantic_remainder#*|}
  semantic_env=$test_dir/$semantic_name.env
  sed "s|^${semantic_key}=.*|${semantic_key}=${semantic_value}|" "$env_source" > "$semantic_env"
  assert_env_rejected_before_side_effects "$semantic_name" "$semantic_env"
done

long_network_name=$(awk 'BEGIN { for (character_index = 0; character_index < 254; character_index++) printf "a" }')
long_network_name_env=$test_dir/long-network-name.env
sed "s|^LANEWAY_NETWORK_NAME=.*|LANEWAY_NETWORK_NAME=${long_network_name}|" \
  "$env_source" > "$long_network_name_env"
assert_env_rejected_before_side_effects long-network-name "$long_network_name_env"

for compose_key in COMPOSE_PROJECT_NAME COMPOSE_PROFILES; do
  fixture=$test_dir/file-$compose_key.env
  cp "$env_source" "$fixture"
  printf '%s=shadow\n' "$compose_key" >> "$fixture"
  assert_env_rejected_before_side_effects "file-$compose_key" "$fixture"
done

# True absence of the legacy optional Connector digest remains supported.
legacy_connector_env=$test_dir/legacy-no-connector.env
grep -v '^LANEWAY_CONNECTOR_IMAGE_DIGEST=' "$env_source" > "$legacy_connector_env"
cp "$legacy_connector_env" "$compose_dir/.env"
chmod 0600 "$compose_dir/.env"
: > "$log"
LANE_TEST_NETWORK_MODE=exact \
  "$compose_dir/laneway-control" init >/dev/null
grep -F '<pull>' "$log" >/dev/null
test "$(grep -c '^cosign ' "$log")" -eq 4

# Ambient values for every managed setting are ignored, and all Compose
# interpolation variables are scrubbed at the Docker process boundary.
cp "$env_source" "$compose_dir/.env"
chmod 0600 "$compose_dir/.env"
: > "$log"
env \
  LANEWAY_VERSION=9.9.9 \
  LANEWAY_INSTALL_PROFILE=production \
  LANEWAY_CONTROLLER_IMAGE_DIGEST=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  LANEWAY_RELAY_IMAGE_DIGEST=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  LANEWAY_ADMIN_IMAGE_DIGEST=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  LANEWAY_CONNECTOR_IMAGE_DIGEST=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  LANEWAY_EXIT_NODE_IMAGE_DIGEST=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  LANEWAY_BIND_ADDRESS=203.0.113.99 \
  LANEWAY_CONTROLLER_PORT=65431 LANEWAY_RELAY_QUIC_PORT=65432 \
  LANEWAY_RELAY_TCP_PORT=65433 LANEWAY_EXIT_DIRECT_PORT=65434 \
  LANEWAY_CONTROLLER_SERVER_NAME=shadow.example.test \
  LANEWAY_NETWORK_ID=ffffffffffffffffffffffffffffffff \
  LANEWAY_CONTROLLER_SERVICE_ID=ffffffffffffffffffffffffffffffff \
  LANEWAY_RELAY_SERVICE_ID=ffffffffffffffffffffffffffffffff \
  LANEWAY_NETWORK_NAME=foreign LANEWAY_IPV4_POOL=100.97.0.0/16 \
  LANEWAY_RELAY_PUBLIC_ENDPOINT=shadow.example.test:65432 \
  LANEWAY_BACKUP_RECIPIENT=age1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  DOCKER_DEFAULT_PLATFORM=linux/arm64 \
  HOME="$test_dir/hostile-home" \
  LANE_TEST_ASSERT_COMPOSE_ENV_CLEAN=1 LANE_TEST_ASSERT_DOCKER_CONTEXT=1 \
  LANE_TEST_NETWORK_MODE=exact \
  "$compose_dir/laneway-control" init >/dev/null
if grep -E 'ffffffffffffffff|shadow\.example|100\.97\.0\.0|<foreign>' "$log" >/dev/null; then
  echo "ambient managed settings overrode the canonical release environment" >&2
  exit 1
fi

# Compose process-control variables are not ordinary interpolation inputs:
# reject them before Docker rather than silently selecting another project,
# profile, file, or environment source.
for compose_key in \
  COMPOSE_PROJECT_NAME COMPOSE_PROFILES COMPOSE_FILE COMPOSE_PATH_SEPARATOR \
  COMPOSE_ENV_FILES COMPOSE_DISABLE_ENV_FILE COMPOSE_CONVERT_WINDOWS_PATHS \
  COMPOSE_IGNORE_ORPHANS COMPOSE_REMOVE_ORPHANS COMPOSE_PARALLEL_LIMIT \
  COMPOSE_ANSI COMPOSE_PROGRESS COMPOSE_STATUS_STDOUT COMPOSE_MENU \
  COMPOSE_EXPERIMENTAL COMPOSE_BAKE COMPOSE_HTTP_TIMEOUT \
  COMPOSE_UNRECOGNIZED_CONTROL
do
  : > "$log"
  if env "$compose_key=shadow" \
    "$compose_dir/laneway-control" init > /dev/null 2> "$test_dir/ambient-$compose_key.err"; then
    echo "init accepted ambient $compose_key" >&2
    exit 1
  fi
  test ! -s "$log"
  test ! -e "$compose_dir/generated/lifecycle/operator.lock"
done

# Docker daemon selection is also fail-closed. These controls must be rejected
# before validation, signature verification, Docker, or bootstrap sees them.
for docker_key in DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_CONFIG; do
  : > "$log"
  if env "$docker_key=shadow" \
    "$compose_dir/laneway-control" init > /dev/null 2> "$test_dir/ambient-$docker_key.err"; then
    echo "init accepted ambient $docker_key" >&2
    exit 1
  fi
  test ! -s "$log"
  test ! -e "$compose_dir/generated/lifecycle/operator.lock"
done

: > "$log"
if env TAR_OPTIONS=--checkpoint=1 \
  "$compose_dir/laneway-control" init > /dev/null 2> "$test_dir/ambient-TAR_OPTIONS.err"; then
  echo "init accepted ambient TAR_OPTIONS" >&2
  exit 1
fi
test ! -s "$log"
test ! -e "$compose_dir/generated/lifecycle/operator.lock"

for trust_key in COSIGN_REPOSITORY SIGSTORE_ROOT_FILE TUF_ROOT_JSON \
  CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR LANEWAY_REPOSITORY LANEWAY_RELEASE_BASE_URL \
  LANEWAY_AUTHENTICATED_RELEASE_BASE_URL LANEWAY_AUTHENTICATED_IMAGE_DIGESTS_FILE \
  LANEWAY_AUTHENTICATED_COSIGN_BIN LANEWAY_COSIGN_BIN LANEWAY_COMMAND LANEWAY_CONTROL_COMMAND
do
  : > "$log"
  if env "$trust_key=shadow" \
    "$compose_dir/laneway-control" init > /dev/null 2> "$test_dir/ambient-$trust_key.err"; then
    echo "init accepted ambient $trust_key" >&2
    exit 1
  fi
  test ! -s "$log"
  test ! -e "$compose_dir/generated/lifecycle/operator.lock"
done

# The privileged wrapper accepts only the exact protected verifier artifact:
# neither a different reported version, a hard link, nor a symlink may reach
# Docker or controller mutation.
for verifier_fixture in wrong-version hardlink; do
  : > "$log"
  case "$verifier_fixture" in
    wrong-version)
      verifier_status=0
      LANE_TEST_COSIGN_VERSION=v3.1.2 \
        "$compose_dir/laneway-control" init > /dev/null \
        2> "$test_dir/verifier-$verifier_fixture.err" || verifier_status=$?
      ;;
    hardlink)
      verifier_status=0
      LANE_TEST_COSIGN_METADATA=hardlink \
        "$compose_dir/laneway-control" init > /dev/null \
        2> "$test_dir/verifier-$verifier_fixture.err" || verifier_status=$?
      ;;
  esac
  [ "$verifier_status" -ne 0 ] || {
    echo "init accepted $verifier_fixture Cosign verifier" >&2
    exit 1
  }
  if grep -E '<pull>|<up>|<admin>' "$log" >/dev/null; then
    echo "init reached mutable work with $verifier_fixture Cosign verifier" >&2
    exit 1
  fi
  test ! -e "$compose_dir/generated/lifecycle/operator.lock"
done

mv "$fake_bin/cosign" "$fake_bin/cosign.real"
ln -s cosign.real "$fake_bin/cosign"
: > "$log"
verifier_status=0
"$compose_dir/laneway-control" init > /dev/null \
  2> "$test_dir/verifier-symlink.err" || verifier_status=$?
[ "$verifier_status" -ne 0 ] || {
  echo "init accepted a symlinked Cosign verifier" >&2
  exit 1
}
if grep -E '<pull>|<up>|<admin>' "$log" >/dev/null; then
  echo "init reached mutable work with a symlinked Cosign verifier" >&2
  exit 1
fi
test ! -e "$compose_dir/generated/lifecycle/operator.lock"
find "$fake_bin/cosign" -maxdepth 0 -delete
mv "$fake_bin/cosign.real" "$fake_bin/cosign"

# The standalone upgrader authorizes inherited lifecycle roles before any
# local or remote upgrade work, and rejects noncanonical deployment paths at
# the same early boundary.
cat > "$fake_bin/id" <<'EOF'
#!/bin/sh
[ "${1:-}" = -u ] && { printf '%s\n' 0; exit 0; }
exit 1
EOF
chmod 0755 "$fake_bin/id"
for inherited_role in observer borrower; do
  if env LANEWAY_DEPLOY_DIR=/opt/laneway \
    LANEWAY_LIFECYCLE_LOCK_TOKEN=.handoff.fixture \
    LANEWAY_LIFECYCLE_LOCK_ROLE=$inherited_role \
    sh "$upgrader_under_test" \
    > /dev/null 2> "$test_dir/upgrader-$inherited_role.err"; then
    echo "mutating upgrader accepted inherited $inherited_role role" >&2
    exit 1
  fi
done
grep -F 'observer lifecycle lock handoff is valid only for verified-package preflight' \
  "$test_dir/upgrader-observer.err" >/dev/null
grep -F 'mutating upgrade lock handoff requires the owner role' \
  "$test_dir/upgrader-borrower.err" >/dev/null
if env LANEWAY_DEPLOY_DIR=/opt//laneway \
  sh "$upgrader_under_test" \
  > /dev/null 2> "$test_dir/upgrader-noncanonical-path.err"; then
  echo "upgrader accepted a noncanonical deployment path" >&2
  exit 1
fi
grep -F 'LANEWAY_DEPLOY_DIR must be a canonical safe absolute path' \
  "$test_dir/upgrader-noncanonical-path.err" >/dev/null
mkdir "$test_dir/upgrader-physical"
ln -s "$test_dir/upgrader-physical" "$test_dir/upgrader-alias"
if env LANEWAY_DEPLOY_DIR="$test_dir/upgrader-alias" \
  sh "$upgrader_under_test" \
  > /dev/null 2> "$test_dir/upgrader-symlink-path.err"; then
  echo "upgrader accepted a symlinked deployment path" >&2
  exit 1
fi
grep -F 'LANEWAY_DEPLOY_DIR must identify its exact physical real directory' \
  "$test_dir/upgrader-symlink-path.err" >/dev/null

# The wrapper accepts the historical missing-port environment as 8443 and an
# exact explicit port, but rejects present malformed values before pulling or
# entering bootstrap.
port_source_env=$test_dir/port-source.env
cp "$env_source" "$port_source_env"

assert_port_rejected() {
  fixture_name=$1
  fixture_env=$2
  cp "$fixture_env" "$compose_dir/.env"
  chmod 0600 "$compose_dir/.env"
  : > "$log"
  if LANE_TEST_REQUIRE_LOCK=1 LANE_TEST_NETWORK_MODE=exact \
    "$compose_dir/laneway-control" init > /dev/null 2> "$test_dir/$fixture_name.err"; then
    echo "init accepted $fixture_name controller port input" >&2
    exit 1
  fi
  test ! -e "$compose_dir/generated/lifecycle/operator.lock"
  if grep -E '<pull>|<admin> <controller> <network> <get>' "$log" >/dev/null; then
    echo "init reached mutable bootstrap work for $fixture_name controller port input" >&2
    exit 1
  fi
}

empty_port_env=$test_dir/empty-port.env
sed 's/^LANEWAY_CONTROLLER_PORT=.*/LANEWAY_CONTROLLER_PORT=/' "$port_source_env" > "$empty_port_env"
assert_port_rejected empty "$empty_port_env"

duplicate_port_env=$test_dir/duplicate-port.env
cp "$port_source_env" "$duplicate_port_env"
printf '%s\n' LANEWAY_CONTROLLER_PORT=9443 >> "$duplicate_port_env"
assert_port_rejected duplicate "$duplicate_port_env"

malformed_port_env=$test_dir/malformed-port.env
sed 's/^LANEWAY_CONTROLLER_PORT=.*/LANEWAY_CONTROLLER_PORT =8443/' "$port_source_env" > "$malformed_port_env"
assert_port_rejected malformed "$malformed_port_env"

out_of_range_port_env=$test_dir/out-of-range-port.env
sed 's/^LANEWAY_CONTROLLER_PORT=.*/LANEWAY_CONTROLLER_PORT=65536/' "$port_source_env" > "$out_of_range_port_env"
assert_port_rejected out-of-range "$out_of_range_port_env"

missing_port_env=$test_dir/missing-port.env
grep -v '^LANEWAY_CONTROLLER_PORT=' "$port_source_env" > "$missing_port_env"
cp "$missing_port_env" "$compose_dir/.env"
chmod 0600 "$compose_dir/.env"
: > "$log"
LANE_TEST_REQUIRE_LOCK=1 LANE_TEST_NETWORK_MODE=exact \
  "$compose_dir/laneway-control" init >/dev/null
test ! -e "$compose_dir/generated/lifecycle/operator.lock"
grep -F '<pull>' "$log" >/dev/null

explicit_port_env=$test_dir/explicit-port.env
sed 's/^LANEWAY_CONTROLLER_PORT=.*/LANEWAY_CONTROLLER_PORT=9443/' "$port_source_env" > "$explicit_port_env"
cp "$explicit_port_env" "$compose_dir/.env"
chmod 0600 "$compose_dir/.env"
: > "$log"
LANE_TEST_REQUIRE_LOCK=1 LANE_TEST_NETWORK_MODE=exact \
  "$compose_dir/laneway-control" init >/dev/null
test ! -e "$compose_dir/generated/lifecycle/operator.lock"
grep -F '<pull>' "$log" >/dev/null

# A signature-verified legacy archive without the explicit candidate preflight
# protocol marker must remain inert: neither its updater nor its installer may
# execute, and the lifecycle lock must still be released.
update_fixture=$test_dir/update-fixture
update_package=$test_dir/update-package/laneway
update_mutation=$test_dir/update-mutation
mkdir -p "$update_fixture" "$update_package/bin" "$update_package/deploy/compose" \
  "$compose_dir/generated/config"
cp "$env_source" "$compose_dir/.env"
chmod 0600 "$compose_dir/.env"
: > "$compose_dir/generated/config/controller.toml"
: > "$compose_dir/generated/config/relay.toml"
ln -s "$compose_dir/laneway-control" "$system_control"
printf '%s\n' 2.0.0 > "$update_package/VERSION"
cat > "$update_package/install.sh" <<'EOF'
#!/bin/sh
: > "$LANE_TEST_UPDATE_MUTATION"
EOF
cat > "$update_package/bin/laneway" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$update_package/deploy/compose/upgrade-control-plane.sh" <<'EOF'
#!/bin/sh
: > "$LANE_TEST_UPDATE_MUTATION"
EOF
chmod 0755 "$update_package/install.sh" "$update_package/bin/laneway" \
  "$update_package/deploy/compose/upgrade-control-plane.sh"
(cd "$test_dir/update-package" && /usr/bin/tar -czf "$update_fixture/laneway_linux_amd64.tar.gz" laneway)
for _ in 1 2 3 4; do
  printf '%s\n' '[[bootstrap.artifacts]]' >> "$update_fixture/bootstrap-artifacts.toml"
done
printf '%s\n' 'ghcr.io/doout/lane-edge@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  > "$update_fixture/image-digests.txt"
(cd "$update_fixture" && sha256sum laneway_linux_amd64.tar.gz bootstrap-artifacts.toml \
  image-digests.txt > checksums.txt)
: > "$update_fixture/checksums.sigstore.json"
cat > "$fake_bin/laneway" <<'EOF'
#!/bin/sh
case " $* " in
  *' config inspect-controller-initial-network '*)
    printf '%s\n' '{"configured":true,"network_id":"11111111111111111111111111111111","name":"production","ipv4_pool":"100.96.0.0/16"}'
    ;;
esac
EOF
cat > "$fake_bin/uname" <<'EOF'
#!/bin/sh
[ "${1:-}" = -m ] && { printf '%s\n' x86_64; exit 0; }
exec /usr/bin/uname "$@"
EOF
cat > "$fake_bin/curl" <<'EOF'
#!/bin/sh
set -eu
[ "${1:-}" = --disable ] || exit 1
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --disable|--fail|--location|--silent|--show-error) shift ;;
    --proto|--proto-redir)
      [ "$2" = '=https' ] || exit 1
      shift 2
      ;;
    --header|--write-out) shift 2 ;;
    --output|-o) output=$2; shift 2 ;;
    *) url=$1; shift ;;
  esac
done
case "$url" in
  */releases/latest\?laneway_cache_bust=*)
    [ "$output" = /dev/null ] || exit 1
    printf '%s' 'https://github.com/Doout/laneway/releases/tag/v2.0.0'
    ;;
  */laneway_linux_amd64.tar.gz) cp "$LANE_TEST_UPDATE_FIXTURE/laneway_linux_amd64.tar.gz" "$output" ;;
  */bootstrap-artifacts.toml) cp "$LANE_TEST_UPDATE_FIXTURE/bootstrap-artifacts.toml" "$output" ;;
  */image-digests.txt) cp "$LANE_TEST_UPDATE_FIXTURE/image-digests.txt" "$output" ;;
  */checksums.txt) cp "$LANE_TEST_UPDATE_FIXTURE/checksums.txt" "$output" ;;
  */checksums.sigstore.json) cp "$LANE_TEST_UPDATE_FIXTURE/checksums.sigstore.json" "$output" ;;
  *) exit 1 ;;
esac
EOF
chmod 0755 "$fake_bin/laneway" "$fake_bin/uname" "$fake_bin/curl"
: > "$log"
update_status=0
LANE_TEST_UPDATE_FIXTURE="$update_fixture" LANE_TEST_UPDATE_MUTATION="$update_mutation" \
  "$compose_dir/laneway-control" update > /dev/null \
  2> "$test_dir/update-no-preflight-marker.err" || update_status=$?
[ "$update_status" -ne 0 ] || {
  echo "update accepted a legacy package without the preflight marker" >&2
  exit 1
}
grep -F 'lacks the required control-plane preflight contract' \
  "$test_dir/update-no-preflight-marker.err" >/dev/null
test ! -e "$update_mutation"
test ! -e "$compose_dir/generated/lifecycle/operator.lock"
if grep -E '<pull>|<up>|<stop>|<rm>|<rename>' "$log" >/dev/null; then
  echo "legacy package rejection reached mutable Docker work" >&2
  exit 1
fi

echo "Control-plane bootstrap verifies controller-owned initial state and serializes relay registration"
