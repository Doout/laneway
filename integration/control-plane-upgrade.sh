#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d)
trap 'find "$test_root" -depth -delete' EXIT HUP INT TERM
test_real_find=$(command -v find)
test_real_mktemp=$(command -v mktemp)
test_real_mv=$(command -v mv)
test_real_sync=$(command -v sync)
export test_real_find test_real_mktemp test_real_mv test_real_sync
package_dir=$test_root/package
compose_source=$package_dir/deploy/compose
deployment=$test_root/laneway
fake_bin=$test_root/bin
log=$test_root/calls.log
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
  sha256sum bootstrap-artifacts.toml > checksums.txt
)
: > "$test_root/checksums.sigstore.json"
cat > "$fake_bin/curl" <<'EOF'
#!/bin/sh
set -eu
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
case "${url##*/}" in
  bootstrap-artifacts.toml) cp "$LANEWAY_TEST_ARTIFACTS" "$output" ;;
  checksums.txt) cp "$LANEWAY_TEST_CHECKSUMS" "$output" ;;
  checksums.sigstore.json) cp "$LANEWAY_TEST_SIGNATURE" "$output" ;;
  *) cp "$LANEWAY_TEST_DIGESTS" "$output" ;;
esac
EOF
cat > "$fake_bin/docker" <<'EOF'
#!/bin/sh
set -eu
printf 'docker' >> "$LANEWAY_TEST_LOG"
printf ' <%s>' "$@" >> "$LANEWAY_TEST_LOG"
printf '\n' >> "$LANEWAY_TEST_LOG"
volume_marker=$LANEWAY_DEPLOY_DIR/volume.exists
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
printf 'cosign' >> "$LANEWAY_TEST_LOG"
printf ' <%s>' "$@" >> "$LANEWAY_TEST_LOG"
printf '\n' >> "$LANEWAY_TEST_LOG"
case " $* " in
  *"laneway-relay@"*) [ "${LANEWAY_TEST_FAIL_RELAY_SIGNATURE:-0}" = 0 ] || exit 1 ;;
esac
EOF
cat > "$fake_bin/jq" <<'EOF'
#!/bin/sh
set -eu
input=$(cat)
case "$input" in
  *'"type":"volume"'*'"source":"controller-state"'*) printf '%s\n' laneway-controller-state ;;
  *) exit 0 ;;
esac
EOF
cat > "$fake_bin/find" <<'EOF'
#!/bin/sh
set -eu
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
  "$fake_bin/find" "$fake_bin/mktemp" "$fake_bin/mv" "$fake_bin/sync"
: > "$deployment/volume.exists"
: > "$deployment/controller.container"

source_selection=$test_root/source-selection
mkdir -p "$source_selection"
cp "$deployment/.env" "$source_selection/release.env"
cp "$deployment/compose.yaml" "$source_selection/compose.yaml"
cp "$deployment/generated/config/controller.toml" "$source_selection/controller.toml"
cp "$deployment/generated/config/relay.toml" "$source_selection/relay.toml"

assert_source_selection() {
  cmp "$source_selection/release.env" "$deployment/.env"
  cmp "$source_selection/compose.yaml" "$deployment/compose.yaml"
  cmp "$source_selection/controller.toml" "$deployment/generated/config/controller.toml"
  cmp "$source_selection/relay.toml" "$deployment/generated/config/relay.toml"
}

system_command=$test_root/sbin/laneway-control
mkdir -p "$(dirname "$system_command")"
env PATH="$fake_bin:$PATH" \
  LANEWAY_VERSION=v9.9.9 \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_CONTROL_COMMAND="$system_command" \
  LANEWAY_RELEASE_BASE_URL=https://release.invalid/v0.2.15 \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
  LANEWAY_TEST_ARTIFACTS="$test_root/bootstrap-artifacts.toml" \
  LANEWAY_TEST_CHECKSUMS="$test_root/checksums.txt" \
  LANEWAY_TEST_SIGNATURE="$test_root/checksums.sigstore.json" \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_LOG="$log" \
  "$compose_source/upgrade-control-plane.sh" > "$test_root/output"

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
grep -F 'docker <compose>' "$log" >/dev/null
grep -E '<-f> <.*/migration/compose.yaml> <pull>' "$log" >/dev/null
grep -F 'cosign <verify>' "$log" >/dev/null
grep -F 'host networking remain unchanged' "$test_root/output" >/dev/null
grep -F '✓ Verify signed container images' "$test_root/output" >/dev/null
grep -F '✓ Create protected pre-migration database snapshot' "$test_root/output" >/dev/null
test ! -e "$deployment/generated/backups/.lane-release-stale.db"
test ! -L "$deployment/generated/backups/.lane-release-stale-link"
grep -F '✓ Start controller and relay' "$test_root/output" >/dev/null
grep -Fx '[bootstrap]' "$deployment/generated/config/controller.toml" >/dev/null
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
env PATH="$fake_bin:$PATH" \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
  LANEWAY_TEST_ALLOW_NEW_BACKUP=1 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" rollback > "$test_root/rollback-output"
grep -Fx 'LANEWAY_VERSION=0.2.14' "$deployment/.env" >/dev/null
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
restore_line=$(grep -nF '<-restore> </backups/' "$log" | head -n 1 | cut -d: -f1)
start_line=$(grep -nF '<up> <-d> <--wait> <controller> <relay>' "$log" | head -n 1 | cut -d: -f1)
[ -n "$restore_line" ] && [ -n "$start_line" ] && [ "$restore_line" -lt "$start_line" ]
previous_generation_name=$(sed -n '1p' "$deployment/generated/lifecycle/previous-release")
previous_generation=$deployment/generated/lifecycle/$previous_generation_name
(cd "$previous_generation" && sha256sum -c MANIFEST.sha256 >/dev/null)

# Exit running-state discovery must fail before the first mutating stop.
printf '%s\n' 'legacy database' 'exit-state-row' > "$deployment/database.state"
: > "$log"
if env PATH="$fake_bin:$PATH" \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
  LANEWAY_TEST_FAIL_EXIT_STATE_QUERY=1 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" upgrade \
    "$deployment/generated/lifecycle/upgrade-0.2.15.env" \
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
if env PATH="$fake_bin:$PATH" \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
  LANEWAY_TEST_FAIL_RELAY_SIGNATURE=1 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" upgrade \
    "$deployment/generated/lifecycle/upgrade-0.2.15.env" \
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
if env PATH="$fake_bin:$PATH" \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
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
if env PATH="$fake_bin:$PATH" \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
  LANEWAY_TEST_SIGNAL_DURING_STOP=1 \
  LANEWAY_TEST_FAIL_START_VERSION=0.2.14 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" upgrade \
    "$deployment/generated/lifecycle/upgrade-0.2.15.env" \
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
if env PATH="$fake_bin:$PATH" \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
  LANEWAY_TEST_FAIL_POST_STOP_STEP_LOG=1 \
  LANEWAY_TEST_LOG="$log" \
  "$deployment/laneway-control" upgrade \
    "$deployment/generated/lifecycle/upgrade-0.2.15.env" \
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
if env PATH="$fake_bin:$PATH" \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
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
if env PATH="$fake_bin:$PATH" \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
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
if env PATH="$fake_bin:$PATH" \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
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
if env PATH="$fake_bin:$PATH" \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
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
  if env PATH="$fake_bin:$PATH" \
    LANEWAY_DEPLOY_DIR="$deployment" \
    LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
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
if env PATH="$fake_bin:$PATH" \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
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
if env PATH="$fake_bin:$PATH" \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
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
if env PATH="$fake_bin:$PATH" \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
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
if env PATH="$fake_bin:$PATH" \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
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
env PATH="$fake_bin:$PATH" \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
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

echo "control-plane upgrade, transactional database recovery, and injected failure-window integration test passed"
