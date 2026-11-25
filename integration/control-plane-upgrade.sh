#!/bin/sh
set -eu

# The production commands use a fixed PATH and protected executable locations.
# Populate those locations only inside disposable mount and network namespaces.
case "${1:-}" in
  --isolated)
    [ "$#" -eq 3 ] &&
      [ "$(readlink /proc/self/ns/mnt)" != "$2" ] &&
      [ "$(readlink /proc/self/ns/net)" != "$3" ] &&
      [ "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/1/ns/mnt)" ] &&
      [ "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)" ] || exit 1
    ;;
  '')
    [ "$(id -u)" -eq 0 ] || { echo "run the upgrade fixture as root" >&2; exit 1; }
    exec unshare --mount --net --propagation private -- "$0" --isolated \
      "$(readlink /proc/self/ns/mnt)" "$(readlink /proc/self/ns/net)"
    ;;
  *) exit 1 ;;
esac

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d)
fixture_local_mounted=false
cleanup_fixture() {
  if [ "$fixture_local_mounted" = true ]; then
    umount /usr/local
  fi
  "$test_real_find" "$test_root" -depth -delete
}
trap cleanup_fixture EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
test_real_find=$(command -v find)
test_real_jq=$(command -v jq)
test_real_mktemp=$(command -v mktemp)
test_real_mv=$(command -v mv)
test_real_sync=$(command -v sync)
export test_real_find test_real_jq test_real_mktemp test_real_mv test_real_sync
package_dir=$test_root/package
compose_source=$package_dir/deploy/compose
deployment=$test_root/laneway
fixture_local=$test_root/usr-local
fake_bin=$fixture_local/bin
umask 022
mkdir -p "$fake_bin" "$fixture_local/sbin" "$fixture_local/libexec/laneway"
mount --bind "$fixture_local" /usr/local
fixture_local_mounted=true
mount -t tmpfs -o mode=1777 tmpfs /var/tmp
mount -t tmpfs -o mode=0755 tmpfs /run
log=$test_root/calls.log
release_fixture_dir=$repo_dir/integration/fixtures/control-plane-release
mkdir -p "$compose_source" "$deployment/generated/lifecycle" "$deployment/generated/config" \
  "$deployment/generated/backups" "$fake_bin"
cp "$repo_dir/deploy/compose/upgrade-control-plane.sh" "$repo_dir/deploy/compose/laneway-control" "$compose_source/"
cp "$repo_dir/deploy/compose/compose.yaml" "$compose_source/compose.yaml"
printf '0.2.15\n' > "$package_dir/VERSION"
: > "$deployment/compose.yaml"
cat > "$deployment/generated/config/controller.toml" <<'EOF'
mode = "controller"
[[bootstrap.artifacts]]
os = "linux"
arch = "amd64"
url = "https://downloads.example.test/old.tar.gz"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
size_bytes = 1
EOF
cat > "$deployment/generated/config/relay.toml" <<'EOF'
mode = "relay"
EOF
chmod 0444 "$deployment/generated/config/controller.toml" "$deployment/generated/config/relay.toml"
printf '%s\n' 'pre-migration database' 'private-row-fixture' > "$deployment/database.state"
printf '%s\n' stale-plaintext > "$deployment/generated/backups/.lane-release-stale.db"
ln -s "$deployment/database.state" "$deployment/generated/backups/.lane-release-stale-link"
: > "$log"

cat > "$deployment/.env" <<'EOF'
LANEWAY_VERSION=0.2.14
LANEWAY_INSTALL_PROFILE=quick
LANEWAY_CONTROLLER_IMAGE_DIGEST=sha256:1111111111111111111111111111111111111111111111111111111111111111
LANEWAY_RELAY_IMAGE_DIGEST=sha256:2222222222222222222222222222222222222222222222222222222222222222
LANEWAY_ADMIN_IMAGE_DIGEST=sha256:3333333333333333333333333333333333333333333333333333333333333333
LANEWAY_EXIT_NODE_IMAGE_DIGEST=sha256:4444444444444444444444444444444444444444444444444444444444444444
LANEWAY_BIND_ADDRESS=0.0.0.0
LANEWAY_CONTROLLER_PORT=8443
LANEWAY_RELAY_QUIC_PORT=4433
LANEWAY_RELAY_TCP_PORT=443
LANEWAY_EXIT_DIRECT_PORT=4434
LANEWAY_CONTROLLER_SERVER_NAME=lane.example.test
LANEWAY_NETWORK_ID=000102030405060708090a0b0c0d0e0f
LANEWAY_CONTROLLER_SERVICE_ID=101112131415161718191a1b1c1d1e1f
LANEWAY_RELAY_SERVICE_ID=202122232425262728292a2b2c2d2e2f
LANEWAY_NETWORK_NAME=production
LANEWAY_IPV4_POOL=100.96.0.0/16
LANEWAY_RELAY_PUBLIC_ENDPOINT=lane.example.test:4433
LANEWAY_BACKUP_RECIPIENT=age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
EOF
cat > "$deployment/lane" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$deployment/recovery.sh" <<'EOF'
#!/bin/sh
if [ "${LANEWAY_TEST_ALLOW_NEW_BACKUP:-0}" = 0 ] && grep -Eq '^\[bootstrap\]' "$LANEWAY_DEPLOY_DIR/generated/config/controller.toml"; then
  echo "new controller configuration was installed before the old-controller backup" >&2
  exit 1
fi
printf 'recovery <%s> <%s>\n' "$1" "$2" >> "$LANEWAY_TEST_LOG"
EOF
cat > "$deployment/validate.sh" <<'EOF'
#!/bin/sh
printf 'validate\n' >> "$LANEWAY_TEST_LOG"
[ "${LANEWAY_TEST_FAIL_VALIDATE:-0}" = 0 ] || exit 1
EOF
chmod 0755 "$deployment/lane" "$deployment/recovery.sh" "$deployment/validate.sh"

cat > "$test_root/image-digests.txt" <<'EOF'
ghcr.io/doout/laneway-controller@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ghcr.io/doout/laneway-relay@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
ghcr.io/doout/laneway-admin@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
ghcr.io/doout/lane-edge@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
ghcr.io/doout/laneway-exit-node@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
EOF
cat > "$test_root/bootstrap-artifacts.toml" <<'EOF'
[[bootstrap.artifacts]]
os = "linux"
arch = "amd64"
url = "https://github.com/Doout/laneway/releases/download/v0.2.15/laneway_linux_amd64.tar.gz"
sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
size_bytes = 1
[[bootstrap.artifacts]]
os = "linux"
arch = "arm64"
url = "https://github.com/Doout/laneway/releases/download/v0.2.15/laneway_linux_arm64.tar.gz"
sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
size_bytes = 1
[[bootstrap.artifacts]]
os = "darwin"
arch = "amd64"
url = "https://github.com/Doout/laneway/releases/download/v0.2.15/laneway_darwin_amd64.tar.gz"
sha256 = "3333333333333333333333333333333333333333333333333333333333333333"
size_bytes = 1
[[bootstrap.artifacts]]
os = "darwin"
arch = "arm64"
url = "https://github.com/Doout/laneway/releases/download/v0.2.15/laneway_darwin_arm64.tar.gz"
sha256 = "4444444444444444444444444444444444444444444444444444444444444444"
size_bytes = 1
EOF
(
  cd "$test_root"
  sha256sum bootstrap-artifacts.toml image-digests.txt > checksums.txt
)
: > "$test_root/checksums.sigstore.json"
cat > "$fake_bin/curl" <<'EOF'
#!/bin/sh
set -eu
printf 'curl' >> "$LANEWAY_TEST_LOG"
printf ' <%s>' "$@" >> "$LANEWAY_TEST_LOG"
printf '\n' >> "$LANEWAY_TEST_LOG"
[ "${LANEWAY_TEST_FAIL_CURL:-0}" = 0 ] || exit 1
case " $* " in
  *" /.well-known/laneway/bootstrap.json "*|*"https://lane.example.test/.well-known/laneway/bootstrap.json"*)
    printf '%s\n' '{"network_id":"000102030405060708090a0b0c0d0e0f","artifacts":[{"url":"https://github.com/Doout/laneway/releases/download/v0.2.15/laneway_linux_amd64.tar.gz"}]}'
    exit 0
    ;;
esac
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then output=$2; shift 2; continue; fi
  url=$1
  shift
done
case "$url" in
  https://github.com/Doout/laneway/releases/download/v0.2.15/*) ;;
  *) echo "unexpected release URL: $url" >&2; exit 1 ;;
esac
case "${url##*/}" in
  bootstrap-artifacts.toml) cp "$LANEWAY_TEST_ARTIFACTS" "$output" ;;
  checksums.txt) cp "$LANEWAY_TEST_CHECKSUMS" "$output" ;;
  checksums.sigstore.json) cp "$LANEWAY_TEST_SIGNATURE" "$output" ;;
  image-digests.txt) cp "$LANEWAY_TEST_DIGESTS" "$output" ;;
  *) echo "unexpected release asset: $url" >&2; exit 1 ;;
esac
EOF
cat > "$fake_bin/docker" <<'EOF'
#!/bin/sh
set -eu
if [ "${LANEWAY_TEST_ASSERT_COMPOSE_ENV_CLEAN:-0}" = 1 ]; then
  for environment_name in \
    LANEWAY_VERSION LANEWAY_CONTROLLER_IMAGE_DIGEST LANEWAY_RELAY_IMAGE_DIGEST \
    LANEWAY_ADMIN_IMAGE_DIGEST LANEWAY_CONNECTOR_IMAGE_DIGEST \
    LANEWAY_EXIT_NODE_IMAGE_DIGEST LANEWAY_BIND_ADDRESS LANEWAY_CONTROLLER_PORT \
    LANEWAY_RELAY_QUIC_PORT LANEWAY_RELAY_TCP_PORT LANEWAY_EXIT_DIRECT_PORT \
    LANEWAY_CONTROLLER_SERVER_NAME COMPOSE_PROJECT_NAME COMPOSE_PROFILES \
    COMPOSE_FILE COMPOSE_ENV_FILES
  do
    eval "environment_present=\${${environment_name}+x}"
    if [ "$environment_present" = x ]; then
      echo "Compose inherited forbidden environment variable $environment_name" >&2
      exit 1
    fi
  done
fi
printf 'docker' >> "$LANEWAY_TEST_LOG"
printf ' <%s>' "$@" >> "$LANEWAY_TEST_LOG"
printf '\n' >> "$LANEWAY_TEST_LOG"
[ "${1:-}" = --context ] && [ "${2:-}" = default ] || {
  echo "Docker did not select the default local context" >&2
  exit 1
}
shift 2
volume_marker=$LANEWAY_DEPLOY_DIR/volume.exists
if [ "${1:-}" = version ] && [ "${2:-}" = --format ]; then
  printf '%s\n' 27.0.0
  exit 0
fi
if [ "${1:-}" = volume ] && [ "${2:-}" = inspect ]; then
  [ -f "$volume_marker" ]
  exit
fi
if [ "${1:-}" = volume ] && [ "${2:-}" = rm ]; then
  [ "${3:-}" = laneway-controller-state ]
  find "$volume_marker" -maxdepth 0 -delete
  find "$LANEWAY_DEPLOY_DIR/database.state" -maxdepth 0 -delete
  exit 0
fi
case " $* " in
  *" compose version "*) exit 0 ;;
  *" compose "*" config --format json "*)
    [ "${LANEWAY_TEST_FAIL_COMPOSE_CONFIG_QUERY:-0}" = 0 ] || exit 1
    if [ "${LANEWAY_TEST_FOREIGN_CONTROLLER_MOUNT:-0}" = 1 ]; then
      printf '%s\n' '{"services":{"controller":{"volumes":[{"type":"bind","source":"foreign","target":"/var/lib/laneway-controller"}]}},"volumes":{}}'
    else
      printf '%s\n' '{"services":{"controller":{"volumes":[{"type":"volume","source":"controller-state","target":"/var/lib/laneway-controller"}]}},"volumes":{"controller-state":{"name":"laneway-controller-state"}}}'
    fi
    exit 0
    ;;
  *" ps --status running -q exit-node "*)
    [ "${LANEWAY_TEST_FAIL_EXIT_STATE_QUERY:-0}" = 0 ] || exit 1
    exit 0
    ;;
  *" stop exit-node relay controller "*)
    find "$LANEWAY_DEPLOY_DIR/controller.container" -maxdepth 0 -delete 2>/dev/null || true
    : > "$LANEWAY_DEPLOY_DIR/stop.completed"
    if [ "${LANEWAY_TEST_SIGNAL_DURING_STOP:-0}" = 1 ] && \
      [ ! -f "$LANEWAY_DEPLOY_DIR/stop.signal-sent" ]; then
      : > "$LANEWAY_DEPLOY_DIR/stop.signal-sent"
      kill -TERM "$PPID"
      exit 1
    fi
    [ "${LANEWAY_TEST_FAIL_STOP:-0}" = 0 ] || exit 1
    exit 0
    ;;
  *" ps -a -q controller "*)
    [ "${LANEWAY_TEST_FAIL_CONTROLLER_ABSENCE_QUERY:-0}" = 0 ] || exit 1
    [ -f "$LANEWAY_DEPLOY_DIR/controller.container" ] && printf '%s\n' controller-fixture
    exit 0
    ;;
  *" rm -s -f controller "*)
    find "$LANEWAY_DEPLOY_DIR/controller.container" -maxdepth 0 -delete 2>/dev/null || true
    exit 0
    ;;
  *" run --rm --no-deps controller "*" -backup /backups/"*)
    name=${*##* /backups/}; name=${name%% *}
    version=$(sed -n 's/^LANEWAY_VERSION=//p' "$LANEWAY_DEPLOY_DIR/.env")
    first_line=$(sed -n '1p' "$LANEWAY_DEPLOY_DIR/database.state")
    if [ "$version" = 0.2.14 ] && [ "$first_line" = 'migrated database' ]; then
      echo "old controller rejected migrated database backup" >&2
      exit 1
    fi
    cp "$LANEWAY_DEPLOY_DIR/database.state" "$LANEWAY_DEPLOY_DIR/generated/backups/$name"
    chmod 0600 "$LANEWAY_DEPLOY_DIR/generated/backups/$name"
    chown 65532:65532 "$LANEWAY_DEPLOY_DIR/generated/backups/$name"
    exit 0
    ;;
  *" run --rm --no-deps controller "*" -restore /backups/"*)
    name=${*##* /backups/}; name=${name%% *}
    [ ! -e "$LANEWAY_DEPLOY_DIR/database.state" ] || {
      echo "restore destination still exists" >&2
      exit 1
    }
    if [ "${LANEWAY_TEST_FAIL_FIRST_RESTORE:-0}" = 1 ] && \
      [ ! -f "$LANEWAY_DEPLOY_DIR/first-restore.failed" ]; then
      : > "$LANEWAY_DEPLOY_DIR/first-restore.failed"
      exit 1
    fi
    cp "$LANEWAY_DEPLOY_DIR/generated/backups/$name" "$LANEWAY_DEPLOY_DIR/database.state"
    : > "$volume_marker"
    exit 0
    ;;
  *" up -d --wait controller relay "*)
    version=$(sed -n 's/^LANEWAY_VERSION=//p' "$LANEWAY_DEPLOY_DIR/.env")
    first_line=$(sed -n '1p' "$LANEWAY_DEPLOY_DIR/database.state")
    if [ "$version" = 0.2.14 ] && [ "$first_line" = 'migrated database' ]; then
      echo "old controller rejected migrated database" >&2
      exit 1
    fi
    if [ "$version" = 0.2.15 ]; then
      initial_network=$(awk '
        $0 == "[controller.initial_network]" { seen++; active=1; next }
        /^\[/ { active=0 }
        active { print }
        END { if (seen != 1) exit 1 }
      ' "$LANEWAY_DEPLOY_DIR/generated/config/controller.toml") || {
        echo "candidate controller configuration omitted the initial-network seed" >&2
        exit 1
      }
      printf '%s\n' "$initial_network" | grep -Fx 'network_id = "000102030405060708090a0b0c0d0e0f"' >/dev/null
      printf '%s\n' "$initial_network" | grep -Fx 'name = "production"' >/dev/null
      printf '%s\n' "$initial_network" | grep -Fx 'ipv4_pool = "100.96.0.0/16"' >/dev/null
      printf '%s\n' 'migrated database' > "$LANEWAY_DEPLOY_DIR/database.state"
      [ "${LANEWAY_TEST_FAIL_CANDIDATE_START:-0}" = 0 ] || exit 1
    fi
    if [ "${LANEWAY_TEST_FAIL_START_VERSION:-}" = "$version" ]; then
      exit 1
    fi
    : > "$LANEWAY_DEPLOY_DIR/controller.container"
    exit 0
    ;;
esac
EOF
cat > "$fake_bin/cosign" <<'EOF'
#!/bin/sh
if [ "${1:-}" = version ] && [ "${2:-}" = --json ]; then
  printf '%s\n' '{"gitVersion":"v3.1.3"}'
  exit 0
fi
printf 'cosign' >> "$LANEWAY_TEST_LOG"
printf ' <%s>' "$@" >> "$LANEWAY_TEST_LOG"
printf '\n' >> "$LANEWAY_TEST_LOG"
if [ "${1:-}" = verify-blob ]; then
  [ "$#" -eq 8 ] || exit 1
  [ "$2" = --bundle ] && [ -f "$3" ] && [ "$4" = --certificate-identity ] &&
    [ "$6" = --certificate-oidc-issuer ] && [ "$7" = https://token.actions.githubusercontent.com ] &&
    [ -f "$8" ] || exit 1
  version=v0.2.15
  [ -z "${LANEWAY_TEST_UPDATE_ASSETS:-}" ] || version=v0.2.56
  [ "$5" = "https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/$version" ] || exit 1
  exit 0
fi
if [ "${1:-}" = verify ] && [ -n "${LANEWAY_TEST_STRICT_COSIGN_REFS:-}" ]; then
  reference=
  for argument do reference=$argument; done
  grep -Fx "$reference" "$LANEWAY_TEST_STRICT_COSIGN_REFS" >/dev/null || {
    echo "cosign rejected unexpected image repository/reference: $reference" >&2
    exit 1
  }
fi
case " $* " in
  *"laneway-relay@"*) [ "${LANEWAY_TEST_FAIL_RELAY_SIGNATURE:-0}" = 0 ] || exit 1 ;;
esac
EOF
cat > "$fake_bin/laneway" <<'EOF'
#!/bin/sh
set -eu
printf 'laneway' >> "$LANEWAY_TEST_LOG"
printf ' <%s>' "$@" >> "$LANEWAY_TEST_LOG"
printf '\n' >> "$LANEWAY_TEST_LOG"
case "${1:-} ${2:-} ${3:-}" in
  'config inspect-controller-initial-network -config')
    [ "$#" -eq 4 ] || exit 1
    configuration=$4
    inspection=$(sed -n 's/^# LANE_TEST_INITIAL_NETWORK_INSPECTION=//p' "$configuration")
    case "$inspection" in
      exact)
        printf '%s\n' '{"configured":true,"network_id":"000102030405060708090a0b0c0d0e0f","name":"production","ipv4_pool":"100.96.0.0/16","bootstrap_network_id":"000102030405060708090a0b0c0d0e0f"}'
        ;;
      foreign)
        printf '%s\n' '{"configured":true,"network_id":"000102030405060708090a0b0c0d0e0f","name":"foreign","ipv4_pool":"100.97.0.0/16","bootstrap_network_id":"000102030405060708090a0b0c0d0e0f"}'
        ;;
      bootstrap-foreign)
        printf '%s\n' '{"configured":false,"bootstrap_network_id":"f0e0d0c0b0a090807060504030201000"}'
        ;;
      invalid) exit 1 ;;
      '')
        if grep -Fx '[controller.initial_network]' "$configuration" >/dev/null && \
          grep -Fx 'network_id = "000102030405060708090a0b0c0d0e0f"' "$configuration" >/dev/null && \
          grep -Fx 'name = "production"' "$configuration" >/dev/null && \
          grep -Fx 'ipv4_pool = "100.96.0.0/16"' "$configuration" >/dev/null; then
          printf '%s\n' '{"configured":true,"network_id":"000102030405060708090a0b0c0d0e0f","name":"production","ipv4_pool":"100.96.0.0/16","bootstrap_network_id":"000102030405060708090a0b0c0d0e0f"}'
        else
          printf '%s\n' '{"configured":false}'
        fi
        ;;
      *) exit 1 ;;
    esac
    ;;
  'config validate -config')
    [ "$#" -eq 4 ]
    [ -f "$4" ] && [ ! -L "$4" ]
    ;;
  'controller enrollment-token issue')
    printf '%s\n' '{' '  "enrollment_token": "legacyfixturetoken"' '}'
    ;;
  *)
    echo "unexpected fake laneway invocation" >&2
    exit 1
    ;;
esac
EOF
cat > "$fake_bin/jq" <<'EOF'
#!/bin/sh
exec "$test_real_jq" "$@"
EOF
cat > "$fake_bin/find" <<'EOF'
#!/bin/sh
set -eu
[ -n "${LANEWAY_DEPLOY_DIR:-}" ] || exec "$test_real_find" "$@"
case "${1:-}" in
  "$LANEWAY_DEPLOY_DIR"/generated/lifecycle/.operation-step.*)
    if [ "${LANEWAY_TEST_FAIL_COMMITTED_STEP_LOG_CLEANUP:-0}" = 1 ] && \
      [ "$(sed -n '1p' "$LANEWAY_DEPLOY_DIR/generated/lifecycle/previous-release")" != \
        "${LANEWAY_TEST_OLD_POINTER:-}" ] && \
      [ ! -f "$LANEWAY_DEPLOY_DIR/committed-step-log-cleanup.failed" ]; then
      : > "$LANEWAY_DEPLOY_DIR/committed-step-log-cleanup.failed"
      exit 1
    fi
    ;;
  "$LANEWAY_DEPLOY_DIR"/generated/backups/.lane-release-restore.*)
    if [ "${LANEWAY_TEST_FAIL_FIRST_RESTORE_CLEANUP:-0}" = 1 ] && \
      [ ! -f "$LANEWAY_DEPLOY_DIR/restore-cleanup.failed" ]; then
      : > "$LANEWAY_DEPLOY_DIR/restore-cleanup.failed"
      exit 1
    fi
    ;;
  "$LANEWAY_DEPLOY_DIR"/generated/lifecycle/current-files-before-*)
    if [ "${LANEWAY_TEST_FAIL_POST_COMMIT_CLEANUP:-0}" = 1 ] && \
      [ -f "$LANEWAY_DEPLOY_DIR/generated/lifecycle/previous-release" ] && \
      [ ! -f "$LANEWAY_DEPLOY_DIR/post-commit-cleanup.failed" ]; then
      : > "$LANEWAY_DEPLOY_DIR/post-commit-cleanup.failed"
      exit 1
    fi
    ;;
esac
exec "$test_real_find" "$@"
EOF
cat > "$fake_bin/mktemp" <<'EOF'
#!/bin/sh
set -eu
mktemp_template=
for mktemp_argument do mktemp_template=$mktemp_argument; done
if [ "${LANEWAY_TEST_FAIL_POST_STOP_STEP_LOG:-0}" = 1 ] && \
  [ "$mktemp_template" = "$LANEWAY_DEPLOY_DIR/generated/lifecycle/.operation-step.XXXXXX" ] && \
  [ -f "$LANEWAY_DEPLOY_DIR/stop.completed" ] && \
  [ ! -f "$LANEWAY_DEPLOY_DIR/operation-log.failed" ]; then
  : > "$LANEWAY_DEPLOY_DIR/operation-log.failed"
  exit 1
fi
exec "$test_real_mktemp" "$@"
EOF
cat > "$fake_bin/mv" <<'EOF'
#!/bin/sh
set -eu
mv_destination=
for mv_argument do mv_destination=$mv_argument; done
if [ "${LANEWAY_TEST_FAIL_CANDIDATE_ENV_PUBLISH:-0}" = 1 ] && \
  [ "$mv_destination" = "$LANEWAY_DEPLOY_DIR/.env" ] && \
  grep -q '^\[bootstrap\]$' "$LANEWAY_DEPLOY_DIR/generated/config/controller.toml" && \
  [ ! -f "$LANEWAY_DEPLOY_DIR/candidate-env-publish.failed" ]; then
  : > "$LANEWAY_DEPLOY_DIR/candidate-env-publish.failed"
  exit 1
fi
exec "$test_real_mv" "$@"
EOF
cat > "$fake_bin/sync" <<'EOF'
#!/bin/sh
set -eu
if [ "${LANEWAY_TEST_FAIL_POINTER_DIRECTORY_SYNC:-0}" = 1 ] && [ "$#" -eq 2 ] && \
  [ "$1" = -f ] && [ "$2" = "$LANEWAY_DEPLOY_DIR/generated/lifecycle" ]; then
  sync_count=0
  [ ! -f "$LANEWAY_DEPLOY_DIR/pointer-directory-sync.count" ] || \
    sync_count=$(sed -n '1p' "$LANEWAY_DEPLOY_DIR/pointer-directory-sync.count")
  sync_count=$((sync_count + 1))
  printf '%s\n' "$sync_count" > "$LANEWAY_DEPLOY_DIR/pointer-directory-sync.count"
  if [ "$sync_count" -eq 2 ]; then
    : > "$LANEWAY_DEPLOY_DIR/pointer-directory-sync.failed"
    exit 1
  fi
fi
exec "$test_real_sync" "$@"
EOF
chmod 0755 "$fake_bin/curl" "$fake_bin/docker" "$fake_bin/cosign" "$fake_bin/jq" \
  "$fake_bin/find" "$fake_bin/laneway" "$fake_bin/mktemp" "$fake_bin/mv" "$fake_bin/sync"
install -m 0755 "$fake_bin/cosign" /usr/local/libexec/laneway/cosign-v3.1.3
mkdir -p "$package_dir/bin"
install -m 0755 "$fake_bin/laneway" "$package_dir/bin/laneway"
: > "$deployment/volume.exists"
: > "$deployment/controller.container"

source_selection=$test_root/source-selection
mkdir -p "$source_selection"
cp "$deployment/.env" "$source_selection/release.env"
cp "$deployment/compose.yaml" "$source_selection/compose.yaml"
cp "$deployment/generated/config/controller.toml" "$source_selection/controller.toml"
cp "$deployment/generated/config/relay.toml" "$source_selection/relay.toml"
system_command=/usr/local/sbin/laneway-control
mkdir -p "$(dirname "$system_command")"

assert_source_selection() {
  cmp "$source_selection/release.env" "$deployment/.env"
  cmp "$source_selection/compose.yaml" "$deployment/compose.yaml"
  cmp "$source_selection/controller.toml" "$deployment/generated/config/controller.toml"
  cmp "$source_selection/relay.toml" "$deployment/generated/config/relay.toml"
}

assert_upgrade_preflight_rejects() {
  fixture_name=$1
  fixture_env=$2
  fixture_controller=$3
  fixture_output=$test_root/preflight-$fixture_name.output
  chmod 0600 "$deployment/.env"
  chmod 0644 "$deployment/generated/config/controller.toml"
  cp "$fixture_env" "$deployment/.env"
  cp "$fixture_controller" "$deployment/generated/config/controller.toml"
  chmod 0600 "$deployment/.env"
  chmod 0444 "$deployment/generated/config/controller.toml"
  : > "$log"
  if env -u LANEWAY_TEST_FAIL_CURL \
    LANEWAY_DEPLOY_DIR="$deployment" \
    LANEWAY_TEST_ARTIFACTS="$test_root/bootstrap-artifacts.toml" \
    LANEWAY_TEST_CHECKSUMS="$test_root/checksums.txt" \
    LANEWAY_TEST_SIGNATURE="$test_root/checksums.sigstore.json" \
    LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
    LANEWAY_TEST_LOG="$log" \
    "$compose_source/upgrade-control-plane.sh" > "$fixture_output" 2>&1; then
    echo "upgrade preflight accepted $fixture_name input" >&2
    exit 1
  fi
  if grep -E '^curl|^docker|^cosign|^recovery' "$log" >/dev/null; then
    echo "upgrade preflight reached mutable or remote work for $fixture_name input" >&2
    exit 1
  fi
  cmp "$fixture_env" "$deployment/.env"
  cmp "$fixture_controller" "$deployment/generated/config/controller.toml"
  cmp "$source_selection/compose.yaml" "$deployment/compose.yaml"
  cmp "$source_selection/relay.toml" "$deployment/generated/config/relay.toml"
}

missing_name_env=$test_root/missing-network-name.env
grep -v '^LANEWAY_NETWORK_NAME=' "$source_selection/release.env" > "$missing_name_env"
assert_upgrade_preflight_rejects missing-network-name "$missing_name_env" "$source_selection/controller.toml"

# Every current managed key rejects a second assignment-shaped export before
# the upgrader performs any remote, Docker, signature, recovery, or file work.
upgrade_managed_keys='LANEWAY_VERSION LANEWAY_INSTALL_PROFILE LANEWAY_CONTROLLER_IMAGE_DIGEST LANEWAY_RELAY_IMAGE_DIGEST LANEWAY_ADMIN_IMAGE_DIGEST LANEWAY_EXIT_NODE_IMAGE_DIGEST LANEWAY_BIND_ADDRESS LANEWAY_CONTROLLER_PORT LANEWAY_RELAY_QUIC_PORT LANEWAY_RELAY_TCP_PORT LANEWAY_EXIT_DIRECT_PORT LANEWAY_CONTROLLER_SERVER_NAME LANEWAY_NETWORK_ID LANEWAY_CONTROLLER_SERVICE_ID LANEWAY_RELAY_SERVICE_ID LANEWAY_NETWORK_NAME LANEWAY_IPV4_POOL LANEWAY_RELAY_PUBLIC_ENDPOINT LANEWAY_BACKUP_RECIPIENT'
for managed_key in $upgrade_managed_keys; do
  exported_env=$test_root/export-$managed_key.env
  cp "$source_selection/release.env" "$exported_env"
  managed_value=$(sed -n "s/^${managed_key}=//p" "$source_selection/release.env")
  printf 'export %s=%s\n' "$managed_key" "$managed_value" >> "$exported_env"
  assert_upgrade_preflight_rejects "export-$managed_key" "$exported_env" "$source_selection/controller.toml"
done

# The legacy optional Connector digest is held to the same grammar when
# present. Compose control keys are never members of a signed release env.
connector_export_env=$test_root/export-LANEWAY_CONNECTOR_IMAGE_DIGEST.env
cp "$source_selection/release.env" "$connector_export_env"
printf '%s\n' \
  'LANEWAY_CONNECTOR_IMAGE_DIGEST=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' \
  'export LANEWAY_CONNECTOR_IMAGE_DIGEST=sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' \
  >> "$connector_export_env"
assert_upgrade_preflight_rejects export-LANEWAY_CONNECTOR_IMAGE_DIGEST \
  "$connector_export_env" "$source_selection/controller.toml"
for compose_key in COMPOSE_PROJECT_NAME COMPOSE_PROFILES; do
  compose_control_env=$test_root/file-$compose_key.env
  cp "$source_selection/release.env" "$compose_control_env"
  printf '%s=shadow\n' "$compose_key" >> "$compose_control_env"
  assert_upgrade_preflight_rejects "file-$compose_key" \
    "$compose_control_env" "$source_selection/controller.toml"
done

# Process-control overrides are not release inputs. Both recognized and future
# Compose controls, plus every Docker daemon selector, fail before remote or
# mutable upgrade work while leaving the selected release byte-for-byte intact.
assert_upgrade_runtime_override_rejected() {
  override_key=$1
  chmod 0600 "$deployment/.env"
  chmod 0644 "$deployment/generated/config/controller.toml"
  cp "$source_selection/release.env" "$deployment/.env"
  cp "$source_selection/controller.toml" "$deployment/generated/config/controller.toml"
  chmod 0600 "$deployment/.env"
  chmod 0444 "$deployment/generated/config/controller.toml"
  : > "$log"
  if env "$override_key=shadow" \
    LANEWAY_DEPLOY_DIR="$deployment" \
    LANEWAY_TEST_LOG="$log" \
    "$compose_source/upgrade-control-plane.sh" \
      > "$test_root/ambient-$override_key.output" 2>&1; then
    echo "upgrade accepted ambient $override_key" >&2
    exit 1
  fi
  if grep -E '^curl|^docker|^cosign|^recovery' "$log" >/dev/null; then
    echo "upgrade reached a side effect with ambient $override_key" >&2
    exit 1
  fi
  assert_source_selection
}

for override_key in \
  COMPOSE_PROJECT_NAME COMPOSE_PROFILES COMPOSE_FILE COMPOSE_PATH_SEPARATOR \
  COMPOSE_ENV_FILES COMPOSE_DISABLE_ENV_FILE COMPOSE_CONVERT_WINDOWS_PATHS \
  COMPOSE_IGNORE_ORPHANS COMPOSE_REMOVE_ORPHANS COMPOSE_PARALLEL_LIMIT \
  COMPOSE_ANSI COMPOSE_PROGRESS COMPOSE_STATUS_STDOUT COMPOSE_MENU \
  COMPOSE_EXPERIMENTAL COMPOSE_BAKE COMPOSE_HTTP_TIMEOUT \
  COMPOSE_UNRECOGNIZED_CONTROL \
  LANEWAY_COSIGN_BIN LANEWAY_COMMAND LANEWAY_CONTROL_COMMAND LANEWAY_RELEASE_BASE_URL \
  DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH
do
  assert_upgrade_runtime_override_rejected "$override_key"
done

duplicate_pool_env=$test_root/duplicate-ipv4-pool.env
cp "$source_selection/release.env" "$duplicate_pool_env"
printf '%s\n' LANEWAY_IPV4_POOL=100.97.0.0/16 >> "$duplicate_pool_env"
assert_upgrade_preflight_rejects duplicate-ipv4-pool "$duplicate_pool_env" "$source_selection/controller.toml"

unsafe_name_env=$test_root/unsafe-network-name.env
sed 's/^LANEWAY_NETWORK_NAME=.*/LANEWAY_NETWORK_NAME=production name/' \
  "$source_selection/release.env" > "$unsafe_name_env"
assert_upgrade_preflight_rejects unsafe-network-name "$unsafe_name_env" "$source_selection/controller.toml"

malformed_pool_env=$test_root/malformed-ipv4-pool.env
cp "$source_selection/release.env" "$malformed_pool_env"
printf '%s\n' 'LANEWAY_IPV4_POOL =100.97.0.0/16' >> "$malformed_pool_env"
assert_upgrade_preflight_rejects malformed-ipv4-pool "$malformed_pool_env" "$source_selection/controller.toml"

empty_port_env=$test_root/empty-controller-port.env
sed 's/^LANEWAY_CONTROLLER_PORT=.*/LANEWAY_CONTROLLER_PORT=/' "$source_selection/release.env" > "$empty_port_env"
assert_upgrade_preflight_rejects empty-controller-port "$empty_port_env" "$source_selection/controller.toml"

duplicate_port_env=$test_root/duplicate-controller-port.env
cp "$source_selection/release.env" "$duplicate_port_env"
printf '%s\n' LANEWAY_CONTROLLER_PORT=9443 >> "$duplicate_port_env"
assert_upgrade_preflight_rejects duplicate-controller-port "$duplicate_port_env" "$source_selection/controller.toml"

malformed_port_env=$test_root/malformed-controller-port.env
sed 's/^LANEWAY_CONTROLLER_PORT=.*/LANEWAY_CONTROLLER_PORT =8443/' \
  "$source_selection/release.env" > "$malformed_port_env"
assert_upgrade_preflight_rejects malformed-controller-port "$malformed_port_env" "$source_selection/controller.toml"

out_of_range_port_env=$test_root/out-of-range-controller-port.env
sed 's/^LANEWAY_CONTROLLER_PORT=.*/LANEWAY_CONTROLLER_PORT=65536/' \
  "$source_selection/release.env" > "$out_of_range_port_env"
assert_upgrade_preflight_rejects out-of-range-controller-port "$out_of_range_port_env" "$source_selection/controller.toml"

mismatched_initial_network=$test_root/mismatched-initial-network.toml
cat "$source_selection/controller.toml" > "$mismatched_initial_network"
cat >> "$mismatched_initial_network" <<'EOF'
# LANE_TEST_INITIAL_NETWORK_INSPECTION=foreign
[controller.initial_network]
network_id = "000102030405060708090a0b0c0d0e0f"
name = "foreign"
ipv4_pool = "100.96.0.0/16"
EOF
assert_upgrade_preflight_rejects mismatched-stanza "$source_selection/release.env" "$mismatched_initial_network"

partial_initial_network=$test_root/partial-initial-network.toml
cat "$source_selection/controller.toml" > "$partial_initial_network"
cat >> "$partial_initial_network" <<'EOF'
# LANE_TEST_INITIAL_NETWORK_INSPECTION=invalid
[controller.initial_network]
network_id = "000102030405060708090a0b0c0d0e0f"
name = "production"
EOF
assert_upgrade_preflight_rejects partial-stanza "$source_selection/release.env" "$partial_initial_network"

duplicate_initial_network=$test_root/duplicate-initial-network.toml
cat "$mismatched_initial_network" > "$duplicate_initial_network"
cat >> "$duplicate_initial_network" <<'EOF'
# LANE_TEST_INITIAL_NETWORK_INSPECTION=invalid
[controller.initial_network]
network_id = "000102030405060708090a0b0c0d0e0f"
name = "production"
ipv4_pool = "100.96.0.0/16"
EOF
assert_upgrade_preflight_rejects duplicate-stanza "$source_selection/release.env" "$duplicate_initial_network"

mismatched_bootstrap_network=$test_root/mismatched-bootstrap-network.toml
cat "$source_selection/controller.toml" > "$mismatched_bootstrap_network"
cat >> "$mismatched_bootstrap_network" <<'EOF'
# LANE_TEST_INITIAL_NETWORK_INSPECTION=invalid
[bootstrap]
network_id = "99999999999999999999999999999999"
EOF
assert_upgrade_preflight_rejects mismatched-bootstrap-network \
  "$source_selection/release.env" "$mismatched_bootstrap_network"

# A bootstrap-only network identity can be expressed without a literal table
# header. The semantic inspector must surface it so a deployment mismatch is
# rejected before the first Curl, Docker, Cosign, recovery, or file mutation.
semantic_bootstrap_mismatch=$test_root/semantic-bootstrap-network-mismatch.toml
cat > "$semantic_bootstrap_mismatch" <<'EOF'
# LANE_TEST_INITIAL_NETWORK_INSPECTION=bootstrap-foreign
mode = "controller"
state_dir = "/state"
socket_path = "/socket"
bootstrap.network_id = "f0e0d0c0b0a090807060504030201000"
bootstrap.controller_endpoint = "https://lane.example.test:8443"
bootstrap.controller_quic_endpoint = "lane.example.test:8443"
bootstrap.controller_server_name = "lane.example.test"
[tls]
certificate = "/secret/controller.crt"
private_key = "/secret/controller.key"
ca = "/secret/ca.crt"
[controller]
listen = ":8443"
quic_listen = ":8443"
database = "/state/controller.db"
ca_private_key = "/secret/ca.key"
admin_token_file = "/secret/admin.token"
leaf_validity = "720h"
EOF
assert_upgrade_preflight_rejects semantic-bootstrap-network-mismatch \
  "$source_selection/release.env" "$semantic_bootstrap_mismatch"

# The Go inspector owns TOML semantics. Alternate valid TOML spellings of the
# exact tuple pass local preflight and reach the first deliberately failed
# remote fetch; mismatched or ambiguous semantic shapes fail before Docker,
# Curl, Cosign, recovery, or deployment mutation.
assert_semantic_preflight_accepts() {
  fixture_name=$1
  fixture_controller=$2
  chmod 0644 "$deployment/generated/config/controller.toml"
  cp "$source_selection/release.env" "$deployment/.env"
  cp "$fixture_controller" "$deployment/generated/config/controller.toml"
  chmod 0600 "$deployment/.env"
  chmod 0444 "$deployment/generated/config/controller.toml"
  : > "$log"
  if env \
    LANEWAY_DEPLOY_DIR="$deployment" \
    LANEWAY_TEST_FAIL_CURL=1 \
    LANEWAY_TEST_LOG="$log" \
    "$compose_source/upgrade-control-plane.sh" > "$test_root/semantic-$fixture_name.output" 2>&1; then
    echo "semantic TOML fixture $fixture_name unexpectedly completed" >&2
    exit 1
  fi
  grep -F '<config> <inspect-controller-initial-network> <-config>' "$log" >/dev/null
  grep -E '^curl' "$log" >/dev/null
  if grep -E '^cosign|^recovery|<stop>|<pull>' "$log" >/dev/null; then
    echo "semantic TOML fixture $fixture_name passed beyond the failed first fetch" >&2
    exit 1
  fi
  cmp "$source_selection/release.env" "$deployment/.env"
  cmp "$fixture_controller" "$deployment/generated/config/controller.toml"
  cmp "$source_selection/compose.yaml" "$deployment/compose.yaml"
}

semantic_fixture() {
  fixture_name=$1
  fixture_body=$2
  fixture_path=$test_root/semantic-$fixture_name.toml
  {
    cat "$source_selection/controller.toml"
    printf '%s\n' '# LANE_TEST_INITIAL_NETWORK_INSPECTION=exact'
    printf '%s\n' "$fixture_body"
  } > "$fixture_path"
  assert_semantic_preflight_accepts "$fixture_name" "$fixture_path"
}

semantic_fixture quoted-inline '[controller]
"initial_network" = { network_id = "000102030405060708090a0b0c0d0e0f", name = "production", ipv4_pool = "100.96.0.0/16" }'
semantic_fixture literal-inline "[controller]
'initial_network' = { network_id = '000102030405060708090a0b0c0d0e0f', name = 'production', ipv4_pool = '100.96.0.0/16' }"
semantic_fixture escaped-key '[controller]
"initial\u005fnetwork" = { network_id = "000102030405060708090a0b0c0d0e0f", name = "production", ipv4_pool = "100.96.0.0/16" }'
semantic_fixture dotted '[controller]
initial_network.network_id = "000102030405060708090a0b0c0d0e0f"
initial_network.name = "production"
initial_network.ipv4_pool = "100.96.0.0/16"'
semantic_fixture inline '[controller]
initial_network = { network_id = "000102030405060708090a0b0c0d0e0f", name = "production", ipv4_pool = "100.96.0.0/16" }'

for invalid_semantics in foreign duplicate array malformed; do
  invalid_controller=$test_root/semantic-invalid-$invalid_semantics.toml
  {
    cat "$source_selection/controller.toml"
    case "$invalid_semantics" in
      foreign)
        printf '%s\n' '# LANE_TEST_INITIAL_NETWORK_INSPECTION=foreign' '[controller]' \
          '"initial_network" = { network_id = "000102030405060708090a0b0c0d0e0f", name = "foreign", ipv4_pool = "100.97.0.0/16" }'
        ;;
      duplicate)
        printf '%s\n' '# LANE_TEST_INITIAL_NETWORK_INSPECTION=invalid' '[controller]' \
          'initial_network = { network_id = "000102030405060708090a0b0c0d0e0f", name = "production", ipv4_pool = "100.96.0.0/16" }' \
          '"initial\u005fnetwork" = { network_id = "000102030405060708090a0b0c0d0e0f", name = "foreign", ipv4_pool = "100.97.0.0/16" }'
        ;;
      array)
        printf '%s\n' '# LANE_TEST_INITIAL_NETWORK_INSPECTION=invalid' '[controller]' \
          'initial_network = [{ network_id = "000102030405060708090a0b0c0d0e0f", name = "production", ipv4_pool = "100.96.0.0/16" }]'
        ;;
      malformed)
        printf '%s\n' '# LANE_TEST_INITIAL_NETWORK_INSPECTION=invalid' '[controller]' \
          'initial_network = { network_id = "000102030405060708090a0b0c0d0e0f", name = '
        ;;
    esac
  } > "$invalid_controller"
  assert_upgrade_preflight_rejects "semantic-$invalid_semantics" \
    "$source_selection/release.env" "$invalid_controller"
done

# Restore the exact legacy source before the successful absence-to-seed migration.
chmod 0600 "$deployment/.env"
chmod 0644 "$deployment/generated/config/controller.toml"
cp "$source_selection/release.env" "$deployment/.env"
cp "$source_selection/controller.toml" "$deployment/generated/config/controller.toml"
chmod 0600 "$deployment/.env"
chmod 0444 "$deployment/generated/config/controller.toml"

# Historical deployments omitted the controller port and used 8443. The new
# wrapper and migration must carry that default through full activation.
legacy_missing_port_env=$test_root/legacy-missing-controller-port.env
grep -v '^LANEWAY_CONTROLLER_PORT=' "$deployment/.env" > "$legacy_missing_port_env"
cp "$legacy_missing_port_env" "$deployment/.env"
cp "$legacy_missing_port_env" "$source_selection/release.env"
chmod 0600 "$deployment/.env"

env \
  LANEWAY_VERSION=v9.9.9 \
  LANEWAY_INSTALL_PROFILE=production \
  LANEWAY_CONTROLLER_IMAGE_DIGEST=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  LANEWAY_RELAY_IMAGE_DIGEST=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  LANEWAY_ADMIN_IMAGE_DIGEST=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  LANEWAY_CONNECTOR_IMAGE_DIGEST=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  LANEWAY_EXIT_NODE_IMAGE_DIGEST=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  LANEWAY_BIND_ADDRESS=203.0.113.99 \
  LANEWAY_CONTROLLER_PORT=65431 \
  LANEWAY_RELAY_QUIC_PORT=65432 \
  LANEWAY_RELAY_TCP_PORT=65433 \
  LANEWAY_EXIT_DIRECT_PORT=65434 \
  LANEWAY_CONTROLLER_SERVER_NAME=shadow.example.test \
  LANEWAY_NETWORK_ID=ffffffffffffffffffffffffffffffff \
  LANEWAY_CONTROLLER_SERVICE_ID=ffffffffffffffffffffffffffffffff \
  LANEWAY_RELAY_SERVICE_ID=ffffffffffffffffffffffffffffffff \
  LANEWAY_NETWORK_NAME=foreign \
  LANEWAY_IPV4_POOL=100.97.0.0/16 \
  LANEWAY_RELAY_PUBLIC_ENDPOINT=shadow.example.test:65432 \
  LANEWAY_BACKUP_RECIPIENT=age1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_ARTIFACTS="$test_root/bootstrap-artifacts.toml" \
  LANEWAY_TEST_CHECKSUMS="$test_root/checksums.txt" \
  LANEWAY_TEST_SIGNATURE="$test_root/checksums.sigstore.json" \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_ASSERT_COMPOSE_ENV_CLEAN=1 \
  LANEWAY_TEST_LOG="$log" \
  "$compose_source/upgrade-control-plane.sh" > "$test_root/output"

if grep -E 'ffffffffffffffff|shadow\.example|100\.97\.0\.0|<foreign>' \
  "$log" "$deployment/.env" "$deployment/generated/config/controller.toml" \
  "$deployment/generated/config/relay.toml" >/dev/null; then
  echo "ambient managed settings overrode the signed upgrade inputs" >&2
  exit 1
fi

grep -Fx 'LANEWAY_VERSION=0.2.15' "$deployment/.env" >/dev/null
grep -Fx 'LANEWAY_CONTROLLER_IMAGE_DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$deployment/.env" >/dev/null
grep -Fx 'LANEWAY_CONNECTOR_IMAGE_DIGEST=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' "$deployment/.env" >/dev/null
grep -Fx 'LANEWAY_EXIT_NODE_IMAGE_DIGEST=sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' "$deployment/.env" >/dev/null
test -x "$deployment/laneway-control"
test -L "$deployment/lane"
test "$(readlink "$deployment/lane")" = laneway-control
test -x "$deployment/generated/lifecycle/lane-before-0.2.15"
test -L "$system_command"
test "$(readlink "$system_command")" = "$deployment/laneway-control"
grep -F 'recovery <backup> <pre-upgrade-' "$log" >/dev/null
grep -F 'docker <--context> <default> <compose>' "$log" >/dev/null
grep -E '<-f> <.*/migration/compose.yaml> <pull>' "$log" >/dev/null
grep -F 'cosign <verify>' "$log" >/dev/null
grep -F 'host networking remain unchanged' "$test_root/output" >/dev/null
grep -F '✓ Verify signed container images' "$test_root/output" >/dev/null
grep -F '✓ Create protected pre-migration database snapshot' "$test_root/output" >/dev/null
test ! -e "$deployment/generated/backups/.lane-release-stale.db"
test ! -L "$deployment/generated/backups/.lane-release-stale-link"
grep -F '✓ Start controller and relay' "$test_root/output" >/dev/null
grep -Fx '[bootstrap]' "$deployment/generated/config/controller.toml" >/dev/null
grep -Fx '[controller.initial_network]' "$deployment/generated/config/controller.toml" >/dev/null
grep -Fx 'network_id = "000102030405060708090a0b0c0d0e0f"' "$deployment/generated/config/controller.toml" >/dev/null
grep -Fx 'name = "production"' "$deployment/generated/config/controller.toml" >/dev/null
grep -Fx 'ipv4_pool = "100.96.0.0/16"' "$deployment/generated/config/controller.toml" >/dev/null
grep -Fx 'controller_endpoint = "https://lane.example.test:8443"' "$deployment/generated/config/controller.toml" >/dev/null
test "$(grep -c '^\[\[bootstrap\.artifacts\]\]$' "$deployment/generated/config/controller.toml")" -eq 4
if grep -F 'downloads.example.test/old.tar.gz' "$deployment/generated/config/controller.toml" >/dev/null; then
  echo "upgrade retained a stale bootstrap artifact" >&2
  exit 1
fi
grep -Fx '[public_https]' "$deployment/generated/config/relay.toml" >/dev/null
cmp "$compose_source/compose.yaml" "$deployment/compose.yaml"
candidate_selection=$test_root/candidate-selection
mkdir -p "$candidate_selection"
cp "$deployment/.env" "$candidate_selection/release.env"
cp "$deployment/compose.yaml" "$candidate_selection/compose.yaml"
cp "$deployment/generated/config/controller.toml" "$candidate_selection/controller.toml"
cp "$deployment/generated/config/relay.toml" "$candidate_selection/relay.toml"
assert_candidate_selection() {
  cmp "$candidate_selection/release.env" "$deployment/.env"
  cmp "$candidate_selection/compose.yaml" "$deployment/compose.yaml"
  cmp "$candidate_selection/controller.toml" "$deployment/generated/config/controller.toml"
  cmp "$candidate_selection/relay.toml" "$deployment/generated/config/relay.toml"
}
assert_candidate_selection
previous_generation_name=$(sed -n '1p' "$deployment/generated/lifecycle/previous-release")
previous_generation=$deployment/generated/lifecycle/$previous_generation_name
test -d "$previous_generation"
(cd "$previous_generation" && sha256sum -c MANIFEST.sha256 >/dev/null)
grep -Fx 'pre-migration database' "$previous_generation/database.db" >/dev/null
grep -Fx 'private-row-fixture' "$previous_generation/database.db" >/dev/null

: > "$log"
env \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_ALLOW_NEW_BACKUP=1 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" rollback > "$test_root/rollback-output"
grep -Fx 'LANEWAY_VERSION=0.2.14' "$deployment/.env" >/dev/null
if grep -q '^LANEWAY_CONTROLLER_PORT=' "$deployment/.env"; then
  echo "legacy rollback unexpectedly added a controller port setting" >&2
  exit 1
fi
if grep -q '^LANEWAY_CONNECTOR_IMAGE_DIGEST=' "$deployment/.env"; then
  echo "legacy rollback unexpectedly rewrote the old four-image release environment" >&2
  exit 1
fi
test "$(grep -c '^cosign <verify>' "$log")" -eq 4
grep -F "<-f> <$previous_generation/files/compose.yaml> <pull>" "$log" >/dev/null
grep -F 'control-plane rollback complete' "$test_root/rollback-output" >/dev/null
grep -Fx 'pre-migration database' "$deployment/database.state" >/dev/null
grep -Fx 'private-row-fixture' "$deployment/database.state" >/dev/null
assert_source_selection
if grep -F '[controller.initial_network]' "$deployment/generated/config/controller.toml" >/dev/null; then
  echo "legacy rollback configuration unexpectedly retained a new config table" >&2
  exit 1
fi
restore_line=$(grep -nF '<-restore> </backups/' "$log" | head -n 1 | cut -d: -f1)
start_line=$(grep -nF '<up> <-d> <--wait> <controller> <relay>' "$log" | head -n 1 | cut -d: -f1)
[ -n "$restore_line" ] && [ -n "$start_line" ] && [ "$restore_line" -lt "$start_line" ]
previous_generation_name=$(sed -n '1p' "$deployment/generated/lifecycle/previous-release")
previous_generation=$deployment/generated/lifecycle/$previous_generation_name
(cd "$previous_generation" && sha256sum -c MANIFEST.sha256 >/dev/null)

# Exit running-state discovery must fail before the first mutating stop.
printf '%s\n' 'legacy database' 'exit-state-row' > "$deployment/database.state"
: > "$log"
if env \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_FAIL_EXIT_STATE_QUERY=1 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" upgrade \
    "$deployment/generated/lifecycle/upgrade-0.2.15.env" \
    "$candidate_selection" \
    > "$test_root/exit-state-query-output" 2>&1; then
  echo "upgrade accepted a failed exit-node running-state query" >&2
  exit 1
fi
grep -F 'could not determine whether the exit node is running' "$test_root/exit-state-query-output" >/dev/null
if grep -F '<stop>' "$log" >/dev/null; then
  echo "exit-node state query failure reached the first stop" >&2
  exit 1
fi
grep -Fx 'exit-state-row' "$deployment/database.state" >/dev/null
assert_source_selection

# A non-final signature failure must fail before the stack is quiesced.
printf '%s\n' 'legacy database' 'signature-row' > "$deployment/database.state"
: > "$log"
if env \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_FAIL_RELAY_SIGNATURE=1 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" upgrade \
    "$deployment/generated/lifecycle/upgrade-0.2.15.env" \
    "$candidate_selection" \
    > "$test_root/selective-signature-output" 2>&1; then
  echo "upgrade accepted a non-final image signature failure" >&2
  exit 1
fi
grep -Fx 'LANEWAY_VERSION=0.2.14' "$deployment/.env" >/dev/null
grep -Fx 'signature-row' "$deployment/database.state" >/dev/null
assert_source_selection
if grep -F '<stop>' "$log" >/dev/null; then
  echo "signature failure quiesced the running release" >&2
  exit 1
fi

# The generation's intermediate files directory must not be traversable
# through a symlink, even when all leaf files and checksums are otherwise valid.
mv "$previous_generation/files" "$previous_generation/files.real"
ln -s files.real "$previous_generation/files"
: > "$log"
if env \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" rollback > "$test_root/symlink-generation-output" 2>&1; then
  echo "rollback accepted a symlinked previous release files directory" >&2
  exit 1
fi
grep -F 'previous release files directory is missing or unsafe' "$test_root/symlink-generation-output" >/dev/null
if grep -E '<stop>|<volume> <rm>' "$log" >/dev/null; then
  echo "unsafe previous release generation reached a mutating operation" >&2
  exit 1
fi
find "$previous_generation/files" -maxdepth 0 -delete
mv "$previous_generation/files.real" "$previous_generation/files"
(cd "$previous_generation" && sha256sum -c MANIFEST.sha256 >/dev/null)
assert_source_selection

# TERM delivered while the first stop is in progress must be deferred through
# recovery. A failed baseline restart must be reported as incomplete recovery.
printf '%s\n' 'legacy database' 'signal-row' > "$deployment/database.state"
: > "$deployment/controller.container"
find "$deployment/stop.completed" "$deployment/stop.signal-sent" -maxdepth 0 -delete 2>/dev/null || true
: > "$log"
if env \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_SIGNAL_DURING_STOP=1 \
  LANEWAY_TEST_FAIL_START_VERSION=0.2.14 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" upgrade \
    "$deployment/generated/lifecycle/upgrade-0.2.15.env" \
    "$candidate_selection" \
    > "$test_root/stop-signal-output" 2>&1; then
  echo "signaled stop with a failed baseline restart unexpectedly succeeded" >&2
  exit 1
fi
test -f "$deployment/stop.signal-sent"
grep -F 'automatic recovery incomplete and the source stack may be stopped' "$test_root/stop-signal-output" >/dev/null
grep -Fx 'LANEWAY_VERSION=0.2.14' "$deployment/.env" >/dev/null
grep -Fx 'signal-row' "$deployment/database.state" >/dev/null
test ! -e "$deployment/controller.container"
assert_source_selection
: > "$deployment/controller.container"

# Failure to allocate a protected step log immediately after quiescing must
# enter the same restart path instead of exiting around it.
printf '%s\n' 'legacy database' 'step-log-row' > "$deployment/database.state"
find "$deployment/stop.completed" "$deployment/operation-log.failed" -maxdepth 0 -delete 2>/dev/null || true
: > "$log"
if env \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_FAIL_POST_STOP_STEP_LOG=1 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" upgrade \
    "$deployment/generated/lifecycle/upgrade-0.2.15.env" \
    "$candidate_selection" \
    > "$test_root/post-stop-log-output" 2>&1; then
  echo "post-stop operation-log failure unexpectedly succeeded" >&2
  exit 1
fi
test -f "$deployment/operation-log.failed"
test -f "$deployment/controller.container"
grep -F 'release selection is unchanged and the source stack was restarted' "$test_root/post-stop-log-output" >/dev/null
grep -Fx 'LANEWAY_VERSION=0.2.14' "$deployment/.env" >/dev/null
grep -Fx 'step-log-row' "$deployment/database.state" >/dev/null
assert_source_selection

# If target restoration removes the managed volume and then fails, source
# recovery must recreate the already-missing volume with the source schema.
printf '%s\n' 'legacy database' 'missing-volume-row' > "$deployment/database.state"
: > "$deployment/volume.exists"
: > "$deployment/controller.container"
find "$deployment/first-restore.failed" -maxdepth 0 -delete 2>/dev/null || true
: > "$log"
if env \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_ALLOW_NEW_BACKUP=1 \
  LANEWAY_TEST_FAIL_FIRST_RESTORE=1 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" rollback > "$test_root/missing-volume-output" 2>&1; then
  echo "rollback with an injected first restore failure unexpectedly succeeded" >&2
  exit 1
fi
test -f "$deployment/first-restore.failed"
test -f "$deployment/volume.exists"
grep -Fx 'LANEWAY_VERSION=0.2.14' "$deployment/.env" >/dev/null
grep -Fx 'legacy database' "$deployment/database.state" >/dev/null
grep -Fx 'missing-volume-row' "$deployment/database.state" >/dev/null
assert_source_selection
test "$(grep -cF '<-restore> </backups/' "$log")" -eq 2
grep -F 'previous images, configuration, and database restored' "$test_root/missing-volume-output" >/dev/null

# A restore that succeeds before staging cleanup fails must retry cleanup
# before the source restore and leave no controller-readable plaintext orphan.
printf '%s\n' 'legacy database' 'staging-retry-row' > "$deployment/database.state"
: > "$deployment/volume.exists"
: > "$deployment/controller.container"
find "$deployment/restore-cleanup.failed" -maxdepth 0 -delete 2>/dev/null || true
: > "$log"
if env \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_ALLOW_NEW_BACKUP=1 \
  LANEWAY_TEST_FAIL_FIRST_RESTORE_CLEANUP=1 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" rollback > "$test_root/staging-retry-output" 2>&1; then
  echo "rollback with an injected target staging cleanup failure unexpectedly succeeded" >&2
  exit 1
fi
test -f "$deployment/restore-cleanup.failed"
grep -Fx 'LANEWAY_VERSION=0.2.14' "$deployment/.env" >/dev/null
grep -Fx 'legacy database' "$deployment/database.state" >/dev/null
grep -Fx 'staging-retry-row' "$deployment/database.state" >/dev/null
assert_source_selection
if find "$deployment/generated/backups" -mindepth 1 -maxdepth 1 -name '.lane-release-*' -print | grep .; then
  echo "retried restore cleanup left a controller-readable plaintext snapshot" >&2
  exit 1
fi
grep -F 'previous images, configuration, and database restored' "$test_root/staging-retry-output" >/dev/null

# A failed explicit rollback must put the source release, configuration and
# source-schema database back, rather than leaving the rollback target active.
printf '%s\n' 'legacy database' 'post-rollback-change' > "$deployment/database.state"
: > "$log"
if env \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_ALLOW_NEW_BACKUP=1 \
  LANEWAY_TEST_FAIL_START_VERSION=0.2.15 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" rollback > "$test_root/failed-rollback-output" 2>&1; then
  echo "injected explicit rollback startup failure unexpectedly succeeded" >&2
  exit 1
fi
grep -Fx 'LANEWAY_VERSION=0.2.14' "$deployment/.env" >/dev/null
grep -Fx 'legacy database' "$deployment/database.state" >/dev/null
grep -Fx 'post-rollback-change' "$deployment/database.state" >/dev/null
assert_source_selection
grep -F 'previous images, configuration, and database restored' "$test_root/failed-rollback-output" >/dev/null
if grep -F 'post-rollback-change' "$test_root/failed-rollback-output" "$log" >/dev/null; then
  echo "failed rollback output exposed database contents" >&2
  exit 1
fi

failure_migration=$test_root/failure-migration
mkdir -p "$failure_migration"
cp "$repo_dir/deploy/compose/compose.yaml" "$failure_migration/compose.yaml"
cp "$previous_generation/files/controller.toml" "$failure_migration/controller.toml"
cp "$previous_generation/files/relay.toml" "$failure_migration/relay.toml"

# Candidate selection publication is transactional. Fail the atomic .env move
# after all three candidate configuration files have been installed, then
# require byte-for-byte source env/config/database recovery.
printf '%s\n' 'legacy database' 'selection-publish-row' > "$deployment/database.state"
cp "$deployment/.env" "$test_root/selection-source.env"
cp "$deployment/compose.yaml" "$test_root/selection-source-compose.yaml"
cp "$deployment/generated/config/controller.toml" "$test_root/selection-source-controller.toml"
cp "$deployment/generated/config/relay.toml" "$test_root/selection-source-relay.toml"
cp "$deployment/database.state" "$test_root/selection-source-database.state"
find "$deployment/candidate-env-publish.failed" -maxdepth 0 -delete 2>/dev/null || true
: > "$log"
if env \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_FAIL_CANDIDATE_ENV_PUBLISH=1 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" upgrade \
    "$deployment/generated/lifecycle/upgrade-0.2.15.env" "$failure_migration" \
    > "$test_root/selection-publish-output" 2>&1; then
  echo "candidate environment publication failure unexpectedly succeeded" >&2
  exit 1
fi
test -f "$deployment/candidate-env-publish.failed"
cmp "$test_root/selection-source.env" "$deployment/.env"
cmp "$test_root/selection-source-compose.yaml" "$deployment/compose.yaml"
cmp "$test_root/selection-source-controller.toml" "$deployment/generated/config/controller.toml"
cmp "$test_root/selection-source-relay.toml" "$deployment/generated/config/relay.toml"
cmp "$test_root/selection-source-database.state" "$deployment/database.state"
grep -F 'previous images, configuration, and database restored' "$test_root/selection-publish-output" >/dev/null

# Restore must prove Compose configuration and controller-container absence
# before it removes the managed database volume.
for query_failure in compose-config controller-absence; do
  printf '%s\n' 'pre-migration database' "${query_failure}-row" > "$deployment/database.state"
  : > "$deployment/volume.exists"
  : > "$deployment/controller.container"
  : > "$log"
  query_environment=LANEWAY_TEST_FAIL_COMPOSE_CONFIG_QUERY=1
  [ "$query_failure" != controller-absence ] || \
    query_environment=LANEWAY_TEST_FAIL_CONTROLLER_ABSENCE_QUERY=1
  if env \
    LANEWAY_DEPLOY_DIR="$deployment" \
    LANEWAY_TEST_FAIL_CANDIDATE_START=1 \
    "$query_environment" \
    LANEWAY_TEST_LOG="$log" \
    "$deployment/laneway-control" upgrade \
      "$deployment/generated/lifecycle/upgrade-0.2.15.env" "$failure_migration" \
      > "$test_root/$query_failure-output" 2>&1; then
    echo "$query_failure failure unexpectedly completed the upgrade" >&2
    exit 1
  fi
  if grep -F '<volume> <rm> <laneway-controller-state>' "$log" >/dev/null; then
    echo "$query_failure failure reached destructive volume removal" >&2
    exit 1
  fi
  grep -F 'automatic rollback incomplete' "$test_root/$query_failure-output" >/dev/null
  grep -Fx 'LANEWAY_VERSION=0.2.14' "$deployment/.env" >/dev/null
  # Candidate startup migrated the current volume, but the protected source
  # snapshot remains available because destructive restoration failed closed.
  grep -Fx 'migrated database' "$deployment/database.state" >/dev/null
  assert_source_selection
  retained_query_count=0
  for retained_query in "$deployment/generated/lifecycle"/.release-database-rollback.*; do
    [ -e "$retained_query" ] || continue
    retained_query_count=$((retained_query_count + 1))
    [ -f "$retained_query" ] && [ ! -L "$retained_query" ]
    [ "$(stat -c '%a:%u:%g' "$retained_query")" = 600:0:0 ]
  done
  [ "$retained_query_count" -eq 1 ]
  find "$deployment/generated/lifecycle" -maxdepth 1 -type f \
    -name '.release-database-rollback.*' -delete
done

# A failed directory fsync after pointer rename must restore the exact prior
# pointer and keep it aimed at a complete, checksum-valid generation.
printf '%s\n' 'pre-migration database' 'pointer-fsync-row' > "$deployment/database.state"
: > "$deployment/volume.exists"
: > "$deployment/controller.container"
old_pointer=$(sed -n '1p' "$deployment/generated/lifecycle/previous-release")
find "$deployment/pointer-directory-sync.failed" \
  "$deployment/pointer-directory-sync.count" -maxdepth 0 -delete 2>/dev/null || true
: > "$log"
if env \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_FAIL_POINTER_DIRECTORY_SYNC=1 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" upgrade \
    "$deployment/generated/lifecycle/upgrade-0.2.15.env" "$failure_migration" \
    > "$test_root/pointer-fsync-output" 2>&1; then
  echo "pointer directory fsync failure unexpectedly completed the upgrade" >&2
  exit 1
fi
test -f "$deployment/pointer-directory-sync.failed"
test "$(sed -n '1p' "$deployment/pointer-directory-sync.count")" -eq 3
test "$(sed -n '1p' "$deployment/generated/lifecycle/previous-release")" = "$old_pointer"
test -d "$deployment/generated/lifecycle/$old_pointer"
(cd "$deployment/generated/lifecycle/$old_pointer" && sha256sum -c MANIFEST.sha256 >/dev/null)
grep -Fx 'LANEWAY_VERSION=0.2.14' "$deployment/.env" >/dev/null
grep -Fx 'pre-migration database' "$deployment/database.state" >/dev/null
grep -Fx 'pointer-fsync-row' "$deployment/database.state" >/dev/null
assert_source_selection
grep -F 'previous images, configuration, and database restored' "$test_root/pointer-fsync-output" >/dev/null

printf '%s\n' 'pre-migration database' 'private-row-fixture' > "$deployment/database.state"
: > "$log"
if env \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_FAIL_CANDIDATE_START=1 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" upgrade \
    "$deployment/generated/lifecycle/upgrade-0.2.15.env" "$failure_migration" \
    > "$test_root/failed-upgrade-output" 2>&1; then
  echo "controller startup failure unexpectedly completed the upgrade" >&2
  exit 1
fi
grep -Fx 'LANEWAY_VERSION=0.2.14' "$deployment/.env" >/dev/null
grep -F 'downloads.example.test/old.tar.gz' "$deployment/generated/config/controller.toml" >/dev/null
grep -Fx 'mode = "relay"' "$deployment/generated/config/relay.toml" >/dev/null
grep -Fx 'pre-migration database' "$deployment/database.state" >/dev/null
grep -Fx 'private-row-fixture' "$deployment/database.state" >/dev/null
assert_source_selection
grep -F '<volume> <rm> <laneway-controller-state>' "$log" >/dev/null
grep -F '<-restore> </backups/' "$log" >/dev/null
grep -F 'previous images, configuration, and database restored' "$test_root/failed-upgrade-output" >/dev/null
if grep -F 'private-row-fixture' "$test_root/failed-upgrade-output" "$log" >/dev/null; then
  echo "failed upgrade output exposed database contents" >&2
  exit 1
fi

# Restoration must not depend on a pre-existing controller service container.
find "$deployment/controller.container" -maxdepth 0 -delete
printf '%s\n' 'pre-migration database' 'no-container-row' > "$deployment/database.state"
: > "$log"
if env \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_FAIL_VALIDATE=1 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" upgrade \
    "$deployment/generated/lifecycle/upgrade-0.2.15.env" "$failure_migration" \
    > "$test_root/no-container-output" 2>&1; then
  echo "migrated validation failure without a baseline container unexpectedly succeeded" >&2
  exit 1
fi
grep -Fx 'LANEWAY_VERSION=0.2.14' "$deployment/.env" >/dev/null
grep -Fx 'pre-migration database' "$deployment/database.state" >/dev/null
grep -Fx 'no-container-row' "$deployment/database.state" >/dev/null
assert_source_selection
grep -F 'previous images, configuration, and database restored' "$test_root/no-container-output" >/dev/null
if grep -F 'no-container-row' "$test_root/no-container-output" "$log" >/dev/null; then
  echo "no-container recovery output exposed database contents" >&2
  exit 1
fi
if find "$deployment/generated/lifecycle" -maxdepth 1 -name '.release-database-rollback.*' -print | grep .; then
  echo "successful automatic rollback retained a plaintext database snapshot" >&2
  exit 1
fi
if find "$deployment/generated/backups" -mindepth 1 -maxdepth 1 -print | grep .; then
  echo "control-plane lifecycle left plaintext database staging files" >&2
  exit 1
fi

printf '%s\n' 'pre-migration database' 'private-row-fixture' > "$deployment/database.state"
: > "$log"
if env \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_FAIL_CANDIDATE_START=1 \
  LANEWAY_TEST_FOREIGN_CONTROLLER_MOUNT=1 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" upgrade \
    "$deployment/generated/lifecycle/upgrade-0.2.15.env" "$failure_migration" \
    > "$test_root/rejected-rollback-output" 2>&1; then
  echo "unsafe controller mount unexpectedly completed the upgrade" >&2
  exit 1
fi
grep -Fx 'LANEWAY_VERSION=0.2.14' "$deployment/.env" >/dev/null
grep -Fx 'migrated database' "$deployment/database.state" >/dev/null
assert_source_selection
grep -F 'automatic rollback incomplete' "$test_root/rejected-rollback-output" >/dev/null
grep -F 'protected database snapshot retained' "$test_root/rejected-rollback-output" >/dev/null
if grep -F '<volume> <rm> <laneway-controller-state>' "$log" >/dev/null; then
  echo "unsafe controller mount reached destructive volume replacement" >&2
  exit 1
fi
retained_count=0
for retained in "$deployment/generated/lifecycle"/.release-database-rollback.*; do
  [ -e "$retained" ] || continue
  retained_count=$((retained_count + 1))
  [ -f "$retained" ] && [ ! -L "$retained" ]
  [ "$(stat -c '%a:%u:%g' "$retained")" = 600:0:0 ]
done
[ "$retained_count" -eq 1 ] || {
  echo "unsafe rollback did not retain exactly one protected database snapshot" >&2
  exit 1
}
if find "$deployment/generated/backups" -mindepth 1 -maxdepth 1 -print | grep .; then
  echo "rejected database rollback left controller-writable staging files" >&2
  exit 1
fi
if grep -F 'private-row-fixture' "$test_root/rejected-rollback-output" "$log" >/dev/null; then
  echo "rejected rollback output exposed database contents" >&2
  exit 1
fi

# Cleanup failures after a healthy pointer commit are warnings: they must not
# make the caller roll a committed release back or report the upgrade failed.
find "$deployment/generated/lifecycle" -maxdepth 1 -type f \
  -name '.release-database-rollback.*' -delete
printf '%s\n' 'pre-migration database' 'post-commit-row' > "$deployment/database.state"
: > "$deployment/volume.exists"
: > "$deployment/controller.container"
old_pointer=$(sed -n '1p' "$deployment/generated/lifecycle/previous-release")
find "$deployment/post-commit-cleanup.failed" \
  "$deployment/committed-step-log-cleanup.failed" -maxdepth 0 -delete 2>/dev/null || true
: > "$log"
env \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_TEST_FAIL_POST_COMMIT_CLEANUP=1 \
  LANEWAY_TEST_FAIL_COMMITTED_STEP_LOG_CLEANUP=1 \
  LANEWAY_TEST_OLD_POINTER="$old_pointer" \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" upgrade \
    "$deployment/generated/lifecycle/upgrade-0.2.15.env" "$failure_migration" \
    > "$test_root/post-commit-cleanup-output" 2>&1
test -f "$deployment/post-commit-cleanup.failed"
test -f "$deployment/committed-step-log-cleanup.failed"
grep -Fx 'LANEWAY_VERSION=0.2.15' "$deployment/.env" >/dev/null
grep -Fx 'migrated database' "$deployment/database.state" >/dev/null
assert_candidate_selection
new_pointer=$(sed -n '1p' "$deployment/generated/lifecycle/previous-release")
test "$new_pointer" != "$old_pointer"
test "$(wc -l < "$deployment/generated/lifecycle/previous-release")" -eq 1
test -d "$deployment/generated/lifecycle/$new_pointer"
(cd "$deployment/generated/lifecycle/$new_pointer" && sha256sum -c MANIFEST.sha256 >/dev/null)
grep -F 'completed operation log was retained' "$test_root/post-commit-cleanup-output" >/dev/null
grep -F 'committed release retained temporary configuration state' "$test_root/post-commit-cleanup-output" >/dev/null
grep -F 'control-plane upgrade complete' "$test_root/post-commit-cleanup-output" >/dev/null

# The public update entry point keeps one owner marker from verified-package
# installation through the nested borrower activation and post-activation
# public-health handoff. An ordinary concurrent lifecycle call is rejected at
# both boundaries, while the authorized nested `upgrade` reaches its own
# candidate validation without deleting the owner's marker.
update_deployment=$test_root/update-lock-deployment
update_assets=$test_root/update-assets
update_package=$test_root/update-package/laneway
update_bin=$test_root/update-bin
mkdir -p "$update_deployment/generated/lifecycle" "$update_deployment/generated/config" "$update_assets" \
  "$update_package/bin" "$update_package/deploy/compose" "$update_bin"
chmod 0700 "$update_deployment/generated/lifecycle"
cp "$release_fixture_dir/v0.2.54/release.env" "$update_deployment/.env"
sed -i 's/^LANEWAY_VERSION=.*/LANEWAY_VERSION=0.2.55/' "$update_deployment/.env"
chmod 0600 "$update_deployment/.env"
cp "$release_fixture_dir/v0.2.54/compose.yaml" "$update_deployment/compose.yaml"
cat > "$update_deployment/generated/config/controller.toml" <<'EOF'
# LANE_TEST_INITIAL_NETWORK_INSPECTION=exact
mode = "controller"
[controller]
listen = "127.0.0.1:9443"
certificate = "/run/laneway-secrets/controller.crt"
private_key = "/run/laneway-secrets/controller.key"
[controller.initial_network]
network_id = "000102030405060708090a0b0c0d0e0f"
name = "production"
ipv4_pool = "100.96.0.0/16"
[bootstrap]
network_id = "000102030405060708090a0b0c0d0e0f"
EOF
cat > "$update_deployment/generated/config/relay.toml" <<'EOF'
mode = "relay"
EOF
cp "$repo_dir/deploy/compose/laneway-control" "$update_deployment/laneway-control"
chmod 0444 "$update_deployment/generated/config/controller.toml" \
  "$update_deployment/generated/config/relay.toml"
chmod 0755 "$update_deployment/laneway-control"
update_system_command=$system_command
ln -sf "$update_deployment/laneway-control" "$update_system_command"
printf '%s\n' 0.2.56 > "$update_package/VERSION"
printf '%s\n' laneway-control-upgrade-preflight-v1 > "$update_package/CONTROL-PLANE-UPGRADE-PREFLIGHT"
cat > "$update_package/bin/laneway" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$update_package/deploy/compose/upgrade-control-plane.sh" <<'EOF'
#!/bin/sh
set -eu
[ "${LANEWAY_UPGRADE_PREFLIGHT_ONLY:-}" = true ]
[ "${LANEWAY_LIFECYCLE_LOCK_ROLE:-}" = observer ]
marker=$LANEWAY_DEPLOY_DIR/generated/lifecycle/operator.lock/$LANEWAY_LIFECYCLE_LOCK_TOKEN
[ -f "$marker" ] && [ ! -L "$marker" ]
[ "$(stat -c '%a:%u:%g:%h' "$marker")" = 600:0:0:1 ]
[ "$(wc -l < "$marker")" -eq 3 ]
[ "$(sed -n '1p' "$marker")" = version=1 ]
[ "$(sed -n '2p' "$marker")" = "deployment=$LANEWAY_DEPLOY_DIR" ]
[ "$(sed -n '3p' "$marker")" = "token=$LANEWAY_LIFECYCLE_LOCK_TOKEN" ]
printf '%s\n' "$LANEWAY_LIFECYCLE_LOCK_TOKEN" > "$LANEWAY_TEST_UPDATE_OBSERVER_TOKEN"
printf '%s\n' update-preflight-lock-held >> "$LANEWAY_TEST_LOG"
[ "${LANEWAY_TEST_UPDATE_PREFLIGHT_FAIL:-0}" = 0 ]
EOF
chmod 0755 "$update_package/bin/laneway" "$update_package/deploy/compose/upgrade-control-plane.sh"
case "$(uname -m)" in
  x86_64|amd64) update_architecture=amd64 ;;
  aarch64|arm64) update_architecture=arm64 ;;
  *) echo "unsupported update-lock test architecture" >&2; exit 1 ;;
esac
update_asset=laneway_linux_${update_architecture}.tar.gz
cat > "$update_assets/bootstrap-artifacts.toml" <<'EOF'
[[bootstrap.artifacts]]
os = "linux"
arch = "amd64"
[[bootstrap.artifacts]]
os = "linux"
arch = "arm64"
[[bootstrap.artifacts]]
os = "darwin"
arch = "amd64"
[[bootstrap.artifacts]]
os = "darwin"
arch = "arm64"
EOF
: > "$update_assets/checksums.sigstore.json"

cat > "$update_bin/curl" <<'EOF'
#!/bin/sh
set -eu
printf 'update-curl <%s>\n' "$*" >> "$LANEWAY_TEST_LOG"
case " $* " in
  *'/releases/latest?'*) printf '%s\n' https://github.com/Doout/laneway/releases/tag/v0.2.56; exit 0 ;;
esac
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output=$2; shift 2 ;;
    *) url=$1; shift ;;
  esac
done
[ -n "$output" ] && [ -n "$url" ]
case "$url" in
  https://github.com/Doout/laneway/releases/download/v0.2.56/*) ;;
  *) echo "unexpected update URL: $url" >&2; exit 1 ;;
esac
cp "$LANEWAY_TEST_UPDATE_ASSETS/${url##*/}" "$output"
EOF
cat > "$update_package/install.sh" <<'EOF'
#!/bin/sh
set -eu
[ "${LANEWAY_LIFECYCLE_LOCK_ROLE:-}" = owner ]
[ "${LANEWAY_UPGRADE_PREFLIGHT_ONLY+x}" != x ]
marker=$LANEWAY_DEPLOY_DIR/generated/lifecycle/operator.lock/$LANEWAY_LIFECYCLE_LOCK_TOKEN
[ -f "$marker" ] && [ ! -L "$marker" ]
[ "$(stat -c '%a:%u:%g:%h' "$marker")" = 600:0:0:1 ]
[ "$(sed -n '3p' "$marker")" = "token=$LANEWAY_LIFECYCLE_LOCK_TOKEN" ]
[ "$(sed -n '1p' "$LANEWAY_TEST_UPDATE_OBSERVER_TOKEN")" = "$LANEWAY_LIFECYCLE_LOCK_TOKEN" ]
printf '%s\n' update-install-lock-held >> "$LANEWAY_TEST_LOG"
install -D -m 0755 "$LANEWAY_TEST_UPDATE_UPGRADER" \
  /usr/local/share/laneway/deploy/compose/upgrade-control-plane.sh
EOF
chmod 0755 "$update_package/install.sh"
(
  cd "$test_root/update-package"
  tar -czf "$update_assets/$update_asset" laneway
)
cp "$test_root/image-digests.txt" "$update_assets/image-digests.txt"
(
  cd "$update_assets"
  sha256sum "$update_asset" bootstrap-artifacts.toml image-digests.txt > checksums.txt
)
cat > "$test_root/update-upgrader.sh" <<'EOF'
#!/bin/sh
set -eu
[ "${LANEWAY_LIFECYCLE_LOCK_ROLE:-}" = owner ]
token=$LANEWAY_LIFECYCLE_LOCK_TOKEN
marker=$LANEWAY_DEPLOY_DIR/generated/lifecycle/operator.lock/$token
[ -f "$marker" ] && [ ! -L "$marker" ]
[ "$(stat -c '%a:%u:%g:%h' "$marker")" = 600:0:0:1 ]
[ "$(sed -n '2p' "$marker")" = "deployment=$LANEWAY_DEPLOY_DIR" ]
[ "$(sed -n '1p' "$LANEWAY_TEST_UPDATE_OBSERVER_TOKEN")" = "$token" ]
[ "$LANEWAY_AUTHENTICATED_COSIGN_BIN" = /usr/local/libexec/laneway/cosign-v3.1.3 ]
[ "$LANEWAY_AUTHENTICATED_RELEASE_BASE_URL" = https://github.com/Doout/laneway/releases/download/v0.2.56 ]
[ "$(stat -c '%a:%u:%g:%h' "$LANEWAY_AUTHENTICATED_IMAGE_DIGESTS_FILE")" = 600:0:0:1 ]
# Mirror the production upgrader's sanitized environment at the borrow boundary.
unset LANEWAY_AUTHENTICATED_COSIGN_BIN LANEWAY_AUTHENTICATED_RELEASE_BASE_URL \
  LANEWAY_AUTHENTICATED_IMAGE_DIGESTS_FILE
cleanup_owner() {
  [ ! -e "$marker" ] || find "$marker" -maxdepth 0 -delete
  [ ! -d "$LANEWAY_DEPLOY_DIR/generated/lifecycle/operator.lock" ] || \
    rmdir "$LANEWAY_DEPLOY_DIR/generated/lifecycle/operator.lock"
}
trap cleanup_owner EXIT HUP INT TERM

if env -u LANEWAY_LIFECYCLE_LOCK_TOKEN -u LANEWAY_LIFECYCLE_LOCK_ROLE \
  "$LANEWAY_DEPLOY_DIR/laneway-control" backup concurrent.age >/dev/null 2>&1; then
  echo "concurrent lifecycle operation entered during update handoff" >&2
  exit 1
fi
printf '%s\n' update-owner-lock-held >> "$LANEWAY_TEST_LOG"
owner_marker_checksum=$(sha256sum "$marker")
owner_marker_checksum=${owner_marker_checksum%% *}

borrower_output=$LANEWAY_DEPLOY_DIR/generated/lifecycle/borrower.output
if LANEWAY_LIFECYCLE_LOCK_ROLE=borrower \
  "$LANEWAY_DEPLOY_DIR/laneway-control" upgrade "$LANEWAY_DEPLOY_DIR/missing-candidate.env" \
    > "$borrower_output" 2>&1; then
  echo "borrower fixture unexpectedly activated a missing candidate" >&2
  exit 1
fi
if ! grep -F 'release environment must be a regular, non-symlink file:' \
  "$borrower_output" "$LANEWAY_DEPLOY_DIR"/generated/lifecycle/.operation-step.* >/dev/null; then
  cat "$borrower_output" >&2
  exit 1
fi
[ -f "$marker" ] && [ ! -L "$marker" ]
[ "$(stat -c '%a:%u:%g:%h' "$marker")" = 600:0:0:1 ]
borrower_marker_checksum=$(sha256sum "$marker")
borrower_marker_checksum=${borrower_marker_checksum%% *}
[ "$borrower_marker_checksum" = "$owner_marker_checksum" ]
printf '%s\n' update-borrower-lock-held >> "$LANEWAY_TEST_LOG"

if env -u LANEWAY_LIFECYCLE_LOCK_TOKEN -u LANEWAY_LIFECYCLE_LOCK_ROLE \
  "$LANEWAY_DEPLOY_DIR/laneway-control" backup concurrent.age >/dev/null 2>&1; then
  echo "concurrent lifecycle operation entered before public health completed" >&2
  exit 1
fi
[ -f "$marker" ]
printf '%s\n' update-public-health-lock-held >> "$LANEWAY_TEST_LOG"
EOF
chmod 0755 "$update_bin/curl" "$test_root/update-upgrader.sh"
mv "$fake_bin/curl" "$test_root/upgrade-curl"
install -m 0755 "$update_bin/curl" "$fake_bin/curl"

# A verified package that fails its own configuration preflight must not install
# host tools, publish candidate state, or strand the owner lock.
update_observer_token=$test_root/update-observer-token
cp "$update_deployment/.env" "$test_root/update-before.env"
cp "$update_deployment/compose.yaml" "$test_root/update-before-compose.yaml"
cp "$update_deployment/generated/config/controller.toml" "$test_root/update-before-controller.toml"
cp "$update_deployment/generated/config/relay.toml" "$test_root/update-before-relay.toml"
: > "$log"
if env \
  LANEWAY_DEPLOY_DIR="$update_deployment" \
  LANEWAY_TEST_UPDATE_ASSETS="$update_assets" \
  LANEWAY_TEST_UPDATE_OBSERVER_TOKEN="$update_observer_token" \
  LANEWAY_TEST_UPDATE_PREFLIGHT_FAIL=1 \
  LANEWAY_TEST_UPDATE_UPGRADER="$test_root/update-upgrader.sh" \
  LANEWAY_TEST_LOG="$log" \
  "$update_deployment/laneway-control" update > "$test_root/update-preflight-failure.output" 2>&1; then
  echo "update accepted a verified package that failed local preflight" >&2
  exit 1
fi
grep -Fx update-preflight-lock-held "$log" >/dev/null
test -s "$update_observer_token"
if grep -Fx update-install-lock-held "$log" >/dev/null; then
  echo "failed verified-package preflight installed host tools" >&2
  exit 1
fi
if grep -E '^update-(owner|borrower|public-health)-lock-held$' "$log" >/dev/null; then
  echo "failed verified-package preflight activated the installed upgrader" >&2
  exit 1
fi
cmp "$test_root/update-before.env" "$update_deployment/.env"
cmp "$test_root/update-before-compose.yaml" "$update_deployment/compose.yaml"
cmp "$test_root/update-before-controller.toml" "$update_deployment/generated/config/controller.toml"
cmp "$test_root/update-before-relay.toml" "$update_deployment/generated/config/relay.toml"
test ! -e "$update_deployment/generated/lifecycle/bootstrap-artifacts-0.2.56.toml"
test ! -e "$update_deployment/generated/lifecycle/operator.lock"

: > "$update_observer_token"
: > "$log"
env \
  LANEWAY_DEPLOY_DIR="$update_deployment" \
  LANEWAY_TEST_UPDATE_ASSETS="$update_assets" \
  LANEWAY_TEST_UPDATE_OBSERVER_TOKEN="$update_observer_token" \
  LANEWAY_TEST_UPDATE_UPGRADER="$test_root/update-upgrader.sh" \
  LANEWAY_TEST_LOG="$log" \
  "$update_deployment/laneway-control" update > "$test_root/update-lock.output" 2>&1 || {
  cat "$test_root/update-lock.output" "$log" >&2
  exit 1
}
grep -Fx update-install-lock-held "$log" >/dev/null
grep -Fx update-preflight-lock-held "$log" >/dev/null
grep -Fx update-owner-lock-held "$log" >/dev/null
grep -Fx update-borrower-lock-held "$log" >/dev/null
grep -Fx update-public-health-lock-held "$log" >/dev/null
preflight_line=$(grep -nFx update-preflight-lock-held "$log" | cut -d: -f1)
install_line=$(grep -nFx update-install-lock-held "$log" | cut -d: -f1)
owner_line=$(grep -nFx update-owner-lock-held "$log" | cut -d: -f1)
[ "$preflight_line" -lt "$install_line" ] && [ "$install_line" -lt "$owner_line" ]
test ! -e "$update_deployment/generated/lifecycle/operator.lock"

# Saved real-tag selections exercise rollback across both legacy image
# repository boundaries. Cosign runs in strict legacy image repository mode:
# every verified reference must be the repository/digest pair expected by the
# saved release, and a post-rollback Connector invite must use that same image.
assert_saved_release_rollback() {
  fixture_tag=$1
  fixture_version=${fixture_tag#v}
  fixture_dir=$release_fixture_dir/$fixture_tag
  legacy_deployment=$test_root/saved-$fixture_version
  legacy_generation=$legacy_deployment/generated/lifecycle/.previous-release.fixture
  legacy_expected_refs=$test_root/saved-$fixture_version.cosign-refs
  legacy_output=$test_root/saved-$fixture_version.rollback-output
  invite_output=$test_root/saved-$fixture_version.invite-output

  mkdir -p "$legacy_deployment/generated/lifecycle" "$legacy_deployment/generated/config" \
    "$legacy_deployment/generated/backups" "$legacy_deployment/generated/pki" \
    "$legacy_generation/files"
  chmod 0700 "$legacy_deployment/generated/lifecycle" "$legacy_generation" "$legacy_generation/files"
  cp "$release_fixture_dir/v0.2.54/release.env" "$legacy_deployment/.env"
  sed -i 's/^LANEWAY_VERSION=.*/LANEWAY_VERSION=0.2.55/' "$legacy_deployment/.env"
  chmod 0600 "$legacy_deployment/.env"
  cp "$release_fixture_dir/v0.2.54/compose.yaml" "$legacy_deployment/compose.yaml"
  cp "$repo_dir/deploy/compose/laneway-control" "$legacy_deployment/laneway-control"
  chmod 0755 "$legacy_deployment/laneway-control"
  printf '%s\n' 'mode = "controller"' > "$legacy_deployment/generated/config/controller.toml"
  printf '%s\n' 'mode = "relay"' > "$legacy_deployment/generated/config/relay.toml"
  printf '%s\n' 'current database' > "$legacy_deployment/database.state"
  printf '%s\n' 'fixture CA' > "$legacy_deployment/generated/pki/ca.crt"
  cat > "$legacy_deployment/recovery.sh" <<'EOF'
#!/bin/sh
printf 'recovery <%s> <%s>\n' "$1" "$2" >> "$LANEWAY_TEST_LOG"
EOF
  cat > "$legacy_deployment/validate.sh" <<'EOF'
#!/bin/sh
printf 'validate\n' >> "$LANEWAY_TEST_LOG"
EOF
  chmod 0755 "$legacy_deployment/recovery.sh" "$legacy_deployment/validate.sh"

  cp "$fixture_dir/release.env" "$legacy_generation/release.env"
  cp "$fixture_dir/compose.yaml" "$legacy_generation/files/compose.yaml"
  printf '%s\n' 'mode = "controller"' > "$legacy_generation/files/controller.toml"
  printf '%s\n' 'mode = "relay"' > "$legacy_generation/files/relay.toml"
  printf '%s\n' "saved $fixture_tag database" > "$legacy_generation/database.db"
  chmod 0600 "$legacy_generation/release.env" "$legacy_generation/database.db" \
    "$legacy_generation/files/compose.yaml" "$legacy_generation/files/controller.toml" \
    "$legacy_generation/files/relay.toml"
  (
    cd "$legacy_generation"
    sha256sum database.db files/compose.yaml files/controller.toml files/relay.toml release.env > MANIFEST.sha256
    chmod 0600 MANIFEST.sha256
  )
  printf '%s\n' .previous-release.fixture > "$legacy_deployment/generated/lifecycle/previous-release"
  chmod 0600 "$legacy_deployment/generated/lifecycle/previous-release"
  : > "$legacy_deployment/volume.exists"
  : > "$legacy_deployment/controller.container"

  controller_digest=$(sed -n 's/^LANEWAY_CONTROLLER_IMAGE_DIGEST=//p' "$fixture_dir/release.env")
  relay_digest=$(sed -n 's/^LANEWAY_RELAY_IMAGE_DIGEST=//p' "$fixture_dir/release.env")
  admin_digest=$(sed -n 's/^LANEWAY_ADMIN_IMAGE_DIGEST=//p' "$fixture_dir/release.env")
  connector_digest=$(sed -n 's/^LANEWAY_CONNECTOR_IMAGE_DIGEST=//p' "$fixture_dir/release.env")
  exit_digest=$(sed -n 's/^LANEWAY_EXIT_NODE_IMAGE_DIGEST=//p' "$fixture_dir/release.env")
  {
    printf 'ghcr.io/doout/laneway-controller@%s\n' "$controller_digest"
    printf 'ghcr.io/doout/laneway-relay@%s\n' "$relay_digest"
    printf 'ghcr.io/doout/laneway-admin@%s\n' "$admin_digest"
    case "$fixture_tag" in
      v0.2.17)
        printf 'ghcr.io/doout/laneway-exit-node@%s\n' "$exit_digest"
        expected_connector_reference=ghcr.io/doout/laneway-exit-node:$fixture_version@$exit_digest
        ;;
      v0.2.18|v0.2.53)
        printf 'ghcr.io/doout/laneway-connector@%s\n' "$exit_digest"
        expected_connector_reference=ghcr.io/doout/laneway-connector:$fixture_version@$exit_digest
        ;;
      v0.2.54)
        printf 'ghcr.io/doout/lane-edge@%s\n' "$connector_digest"
        printf 'ghcr.io/doout/laneway-exit-node@%s\n' "$exit_digest"
        expected_connector_reference=ghcr.io/doout/lane-edge:$fixture_version@$connector_digest
        ;;
      *) exit 1 ;;
    esac
  } > "$legacy_expected_refs"

  : > "$log"
  env \
    LANEWAY_DEPLOY_DIR="$legacy_deployment" \
    LANEWAY_TEST_STRICT_COSIGN_REFS="$legacy_expected_refs" \
    LANEWAY_TEST_ALLOW_NEW_BACKUP=1 \
    LANEWAY_TEST_LOG="$log" \
    "$legacy_deployment/laneway-control" rollback > "$legacy_output"
  cmp "$fixture_dir/release.env" "$legacy_deployment/.env"
  cmp "$fixture_dir/compose.yaml" "$legacy_deployment/compose.yaml"
  grep -Fx "saved $fixture_tag database" "$legacy_deployment/database.state" >/dev/null
  test "$(grep -c '^cosign <verify>' "$log")" -eq "$(wc -l < "$legacy_expected_refs")"
  while IFS= read -r expected_reference; do
    grep -F "<$expected_reference>" "$log" >/dev/null
  done < "$legacy_expected_refs"

  : > "$log"
  env \
    LANEWAY_DEPLOY_DIR="$legacy_deployment" \
    LANEWAY_TEST_LOG="$log" \
    "$legacy_deployment/laneway-control" invite --name saved --docker --connector > "$invite_output"
  grep -F "'$expected_connector_reference'" "$invite_output" >/dev/null
  grep -F '<controller> <enrollment-token> <issue>' "$log" >/dev/null
  test ! -e "$legacy_deployment/generated/lifecycle/operator.lock"
}

install -m 0755 "$test_root/upgrade-curl" "$fake_bin/curl"

for saved_tag in v0.2.17 v0.2.18 v0.2.53 v0.2.54; do
  assert_saved_release_rollback "$saved_tag"
done

echo "control-plane upgrade, transactional database recovery, and injected failure-window integration test passed"
