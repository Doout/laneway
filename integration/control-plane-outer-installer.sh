#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
if [ "${LANEWAY_OUTER_TEST_IN_CONTAINER:-0}" != 1 ]; then
  command -v docker >/dev/null 2>&1 || {
    echo "outer installer integration requires Docker" >&2
    exit 1
  }
  exec docker run --rm --network none \
    -e LANEWAY_OUTER_TEST_IN_CONTAINER=1 \
    -v "$repo_dir:/workspace:ro" ubuntu:24.04 \
    /bin/sh /workspace/integration/control-plane-outer-installer.sh
fi
repo_dir=/workspace

[ "$(id -u)" -eq 0 ] || {
  echo "outer control-plane installer integration must run as root" >&2
  exit 1
}
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH \
  DOCKER_CONFIG DOCKER_DEFAULT_PLATFORM TAR_OPTIONS COSIGN_YES COSIGN_REPOSITORY \
  SIGSTORE_ROOT_FILE TUF_MIRROR COMPOSE_PROJECT_NAME COMPOSE_FILE \
  CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR LANEWAY_REPOSITORY \
  LANEWAY_COSIGN_BIN LANEWAY_CHECKSUM_SIGNATURE_VERIFIED \
  LANEWAY_AUTHENTICATED_RELEASE_BASE_URL LANEWAY_AUTHENTICATED_COSIGN_BIN \
  LANEWAY_BOOTSTRAP_ARTIFACTS_FILE LANEWAY_LIFECYCLE_LOCK_TOKEN \
  LANEWAY_LIFECYCLE_LOCK_ROLE LANEWAY_UPGRADE_PREFLIGHT_ONLY \
  LANEWAY_CONTROL_COMMAND LANEWAY_COMMAND

test_root=$(mktemp -d)
trap 'find "$test_root" -depth -delete' EXIT HUP INT TERM
fixture=$test_root/fixture
legacy_fixture=$test_root/legacy-fixture
tampered_fixture=$test_root/tampered-fixture
package_root=$test_root/package
package=$package_root/laneway
trusted_bin=/usr/local/bin
caller_bin=$test_root/caller-bin
deployment=$test_root/deployment
record=$test_root/record
mkdir -p "$fixture" "$package/bin" "$package/deploy/compose" "$caller_bin" \
  "$deployment/generated/config" "$deployment/generated/lifecycle" \
  /usr/local/sbin /usr/local/bin
chmod 0755 /usr/local/sbin /usr/local/bin
chmod 0700 "$deployment" "$deployment/generated" "$deployment/generated/config" \
  "$deployment/generated/lifecycle"
: > "$record"

case "$(uname -m)" in
  x86_64|amd64) architecture=amd64 ;;
  aarch64|arm64) architecture=arm64 ;;
  *) echo "unsupported test architecture" >&2; exit 1 ;;
esac
asset=laneway_linux_${architecture}.tar.gz
printf '%s\n' 9.8.7 > "$package/VERSION"
printf '%s\n' laneway-control-upgrade-preflight-v1 > \
  "$package/CONTROL-PLANE-UPGRADE-PREFLIGHT"

cat > "$package/install.sh" <<'EOF'
#!/bin/sh
set -eu
[ "${LANEWAY_LIFECYCLE_LOCK_ROLE:-}" = owner ]
[ "${ENV+x}${BASH_ENV+x}${CDPATH+x}${IFS+x}" = x ]
[ "${LANEWAY_RELEASE_BASE_URL+x}${LANEWAY_REPOSITORY+x}${LANEWAY_COSIGN_BIN+x}" = "" ]
marker=$LANEWAY_DEPLOY_DIR/generated/lifecycle/operator.lock/$LANEWAY_LIFECYCLE_LOCK_TOKEN
[ -f "$marker" ] && [ ! -L "$marker" ]
printf '%s\n' install >> "$LANEWAY_OUTER_TEST_RECORD"
EOF
cat > "$package/bin/laneway" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$package/deploy/compose/install-control-plane.sh" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$package/deploy/compose/prepare-control-plane.sh" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$package/deploy/compose/upgrade-control-plane.sh" <<'EOF'
#!/bin/sh
set -eu
[ "${LANEWAY_UPGRADE_PREFLIGHT_ONLY:-}" = true ]
[ "${LANEWAY_LIFECYCLE_LOCK_ROLE:-}" = observer ]
[ "${TMPDIR:-}" = /var/tmp ]
[ "${DOCKER_DEFAULT_PLATFORM+x}" != x ]
[ "${ENV+x}${BASH_ENV+x}${CDPATH+x}${IFS+x}" = x ]
[ "${LANEWAY_RELEASE_BASE_URL+x}${LANEWAY_REPOSITORY+x}${LANEWAY_COSIGN_BIN+x}" = "" ]
[ "${LANEWAY_AUTHENTICATED_RELEASE_BASE_URL:-}" = https://release.invalid/v9.8.7 ]
[ -x "${LANEWAY_AUTHENTICATED_COSIGN_BIN:-}" ]
marker=$LANEWAY_DEPLOY_DIR/generated/lifecycle/operator.lock/$LANEWAY_LIFECYCLE_LOCK_TOKEN
[ -f "$marker" ] && [ ! -L "$marker" ]
[ "$(stat -c '%a:%u:%g:%h' "$marker")" = 600:0:0:1 ]
[ "$(sed -n '2p' "$marker")" = "deployment=$LANEWAY_DEPLOY_DIR" ]
[ "$(sed -n '3p' "$marker")" = "token=$LANEWAY_LIFECYCLE_LOCK_TOKEN" ]
printf '%s\n' preflight >> "$LANEWAY_OUTER_TEST_RECORD"
[ "${LANEWAY_OUTER_TEST_BLOCK_PREFLIGHT:-0}" = 0 ] || {
  printf '%s\n' preflight-blocked >> "$LANEWAY_OUTER_TEST_RECORD"
  trap 'exit 143' HUP INT TERM
  while :; do sleep 1; done
}
[ "${LANEWAY_OUTER_TEST_FAIL_PREFLIGHT:-0}" = 0 ]
EOF
cat > "$test_root/final-updater.sh" <<'EOF'
#!/bin/sh
set -eu
[ "${LANEWAY_LIFECYCLE_LOCK_ROLE:-}" = owner ]
[ "${TMPDIR:-}" = /var/tmp ]
[ "${ENV+x}${BASH_ENV+x}${CDPATH+x}${IFS+x}" = x ]
[ "${LANEWAY_RELEASE_BASE_URL+x}${LANEWAY_REPOSITORY+x}${LANEWAY_COSIGN_BIN+x}" = "" ]
[ "${LANEWAY_AUTHENTICATED_RELEASE_BASE_URL:-}" = https://release.invalid/v9.8.7 ]
[ -x /usr/local/libexec/laneway/cosign-v3.1.3 ]
lock=$LANEWAY_DEPLOY_DIR/generated/lifecycle/operator.lock
marker=$lock/$LANEWAY_LIFECYCLE_LOCK_TOKEN
[ -f "$marker" ] && [ ! -L "$marker" ]
printf '%s\n' final >> "$LANEWAY_OUTER_TEST_RECORD"
find "$marker" -maxdepth 0 -delete
rmdir "$lock"
EOF
chmod 0755 "$package/install.sh" "$package/bin/laneway" \
  "$package/deploy/compose/"*.sh "$test_root/final-updater.sh"
(
  cd "$package_root"
  tar -czf "$fixture/$asset" laneway
)
cat > "$fixture/bootstrap-artifacts.toml" <<'EOF'
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
cat > "$fixture/image-digests.txt" <<'EOF'
ghcr.io/doout/laneway-controller@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ghcr.io/doout/laneway-relay@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
ghcr.io/doout/laneway-admin@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
ghcr.io/doout/lane-edge@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
ghcr.io/doout/laneway-exit-node@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
EOF
: > "$fixture/checksums.sigstore.json"

cat > "$fixture/cosign-linux-$architecture" <<'EOF'
#!/bin/sh
set -eu
case "${1:-}" in
  version) printf '%s\n' '{"gitVersion":"v3.1.3"}' ;;
  verify-blob)
    [ "${LANEWAY_OUTER_TEST_COSIGN_FAIL:-0}" = 0 ] || exit 1
    identity=false
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --certificate-identity ]; then
        [ "${2:-}" = "https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/v9.8.7" ]
        identity=true
      fi
      shift
    done
    [ "$identity" = true ]
    ;;
  *) exit 1 ;;
esac
EOF
chmod 0755 "$fixture/cosign-linux-$architecture"
(
  cd "$fixture"
  /usr/bin/sha256sum "$asset" bootstrap-artifacts.toml image-digests.txt > checksums.txt
)

# A signed legacy package without the inert-preflight protocol must never have
# its updater queried or executed to discover whether it is safe.
cp -R "$package_root" "$test_root/legacy-package"
find "$test_root/legacy-package/laneway/CONTROL-PLANE-UPGRADE-PREFLIGHT" \
  -maxdepth 0 -delete
cat > "$test_root/legacy-package/laneway/deploy/compose/upgrade-control-plane.sh" <<'EOF'
#!/bin/sh
printf '%s\n' legacy-updater-invoked >> "$LANEWAY_OUTER_TEST_RECORD"
exit 0
EOF
chmod 0755 "$test_root/legacy-package/laneway/deploy/compose/upgrade-control-plane.sh"
mkdir "$legacy_fixture"
(
  cd "$test_root/legacy-package"
  tar -czf "$legacy_fixture/$asset" laneway
)
cp "$fixture/bootstrap-artifacts.toml" "$fixture/image-digests.txt" \
  "$fixture/checksums.sigstore.json" "$fixture/cosign-linux-$architecture" "$legacy_fixture/"
(
  cd "$legacy_fixture"
  /usr/bin/sha256sum "$asset" bootstrap-artifacts.toml image-digests.txt > checksums.txt
)

cp -R "$fixture" "$tampered_fixture"
printf '%s\n' \
  'ghcr.io/doout/laneway-controller@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' \
  > "$tampered_fixture/image-digests.txt"

# Install deterministic command doubles only inside this disposable container.
# The production script still resolves its normal fixed, protected root PATH.
cat > "$trusted_bin/curl" <<'EOF'
#!/bin/sh
set -eu
[ "${1:-}" = --disable ] || exit 91
printf '%s\n' curl >> "$LANEWAY_OUTER_TEST_RECORD"
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
[ -n "$output" ] && [ -n "$url" ]
cp "$LANEWAY_OUTER_TEST_FIXTURE/${url##*/}" "$output"
EOF
cat > "$trusted_bin/sha256sum" <<'EOF'
#!/bin/sh
set -eu
if [ "${1:-}" = -c ] && [ "${2:-}" = - ]; then
  IFS=' ' read -r expected candidate
  candidate=${candidate# }
  case "$candidate" in */cosign-v3.1.3) exit 0 ;; esac
  printf '%s  %s\n' "$expected" "$candidate" | /usr/bin/sha256sum -c -
  exit
fi
exec /usr/bin/sha256sum "$@"
EOF
cat > "$trusted_bin/docker" <<'EOF'
#!/bin/sh
set -eu
[ "${DOCKER_CONFIG:-}" = /root/.docker ] && [ "${HOME:-}" = /root ]
[ "${1:-}" = --context ] && [ "${2:-}" = default ]
printf '%s\n' docker >> "$LANEWAY_OUTER_TEST_RECORD"
shift 2
case "$1 ${2:-}" in
  'compose version') exit 0 ;;
  'version --format') printf '%s\n' 29.5.2 ;;
  *) exit 1 ;;
esac
EOF
for command_name in age getent ss; do
  cat > "$trusted_bin/$command_name" <<'EOF'
#!/bin/sh
exit 0
EOF
done
cat > "$trusted_bin/sh" <<'EOF'
#!/bin/sh
set -eu
case "${1:-}" in
  /usr/local/share/laneway/deploy/compose/upgrade-control-plane.sh)
    shift
    exec /bin/sh "$LANEWAY_OUTER_TEST_FINAL_UPDATER" "$@"
    ;;
  *) exec /bin/sh "$@" ;;
esac
EOF
chmod 0755 "$trusted_bin/curl" "$trusted_bin/sha256sum" "$trusted_bin/docker" \
  "$trusted_bin/age" "$trusted_bin/getent" "$trusted_bin/ss" "$trusted_bin/sh"

for command_name in curl tar cosign docker env sed uname stat; do
  cat > "$caller_bin/$command_name" <<'EOF'
#!/bin/sh
printf '%s\n' caller-path-tool >> "$LANEWAY_OUTER_TEST_RECORD"
exit 99
EOF
done
chmod 0755 "$caller_bin/"*

run_outer() {
  /usr/bin/env PATH="$caller_bin:/usr/bin:/bin" LANEWAY_VERSION=9.8.7 \
    LANEWAY_NONINTERACTIVE=true LANEWAY_DEPLOY_DIR="$deployment" \
    LANEWAY_RELEASE_BASE_URL=https://release.invalid/v9.8.7 \
    LANEWAY_OUTER_TEST_FIXTURE="$fixture" LANEWAY_OUTER_TEST_RECORD="$record" \
    LANEWAY_OUTER_TEST_FINAL_UPDATER="$test_root/final-updater.sh" \
    "$@" /bin/sh "$repo_dir/install.sh" --upgrade-control-plane
}

run_outer_production() {
  /usr/bin/env PATH="$caller_bin:/usr/bin:/bin" LANEWAY_VERSION=9.8.7 \
    LANEWAY_NONINTERACTIVE=true LANEWAY_DEPLOY_DIR="$deployment" \
    LANEWAY_RELEASE_BASE_URL=https://release.invalid/v9.8.7 \
    LANEWAY_OUTER_TEST_FIXTURE="$fixture" LANEWAY_OUTER_TEST_RECORD="$record" \
    LANEWAY_OUTER_TEST_FINAL_UPDATER="$test_root/final-updater.sh" \
    /bin/sh "$repo_dir/install.sh" --upgrade-control-plane --production
}

start_blocked_outer() {
  exec /usr/bin/env PATH="$caller_bin:/usr/bin:/bin" LANEWAY_VERSION=9.8.7 \
    LANEWAY_NONINTERACTIVE=true LANEWAY_DEPLOY_DIR="$deployment" \
    LANEWAY_RELEASE_BASE_URL=https://release.invalid/v9.8.7 \
    LANEWAY_OUTER_TEST_FIXTURE="$fixture" LANEWAY_OUTER_TEST_RECORD="$record" \
    LANEWAY_OUTER_TEST_FINAL_UPDATER="$test_root/final-updater.sh" \
    LANEWAY_OUTER_TEST_BLOCK_PREFLIGHT=1 \
    /bin/sh "$repo_dir/install.sh" --upgrade-control-plane
}

run_root_client() {
  /usr/bin/env PATH="$caller_bin:/usr/bin:/bin" LANEWAY_VERSION=9.8.7 \
    LANEWAY_OUTER_TEST_FIXTURE="$fixture" LANEWAY_OUTER_TEST_RECORD="$record" \
    "$@" /bin/sh "$repo_dir/install.sh" --client
}

temporary_tree_snapshot() {
  find /var/tmp -maxdepth 1 -type d -name 'laneway-install.*' -print | LC_ALL=C sort
}

# Privileged process-control inputs are rejected before Docker, curl, archive,
# package installation, temporary creation, or lifecycle state changes.
for hostile_key in DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY \
  DOCKER_CERT_PATH DOCKER_CONFIG COMPOSE_PROJECT_NAME COMPOSE_FILE TAR_OPTIONS \
  COSIGN_REPOSITORY SIGSTORE_ROOT_FILE TUF_MIRROR CURL_CA_BUNDLE SSL_CERT_FILE \
  SSL_CERT_DIR LANEWAY_REPOSITORY LANEWAY_COSIGN_BIN \
  LANEWAY_CHECKSUM_SIGNATURE_VERIFIED LANEWAY_AUTHENTICATED_RELEASE_BASE_URL \
  LANEWAY_AUTHENTICATED_COSIGN_BIN LANEWAY_BOOTSTRAP_ARTIFACTS_FILE \
  LANEWAY_LIFECYCLE_LOCK_TOKEN LANEWAY_LIFECYCLE_LOCK_ROLE \
  LANEWAY_UPGRADE_PREFLIGHT_ONLY LANEWAY_CONTROL_COMMAND LANEWAY_COMMAND; do
  : > "$record"
  temporary_before=$(temporary_tree_snapshot)
  if run_outer "$hostile_key=hostile" >/dev/null 2> "$test_root/$hostile_key.err"; then
    echo "outer installer accepted hostile $hostile_key" >&2
    exit 1
  fi
  test ! -s "$record"
  test ! -e "$deployment/generated/lifecycle/operator.lock"
  test "$(temporary_tree_snapshot)" = "$temporary_before"
done

# The unsigned Linux client channel cannot accept a caller-selected repository
# or mirror because its downloaded package executes with root privileges.
for release_key in LANEWAY_REPOSITORY LANEWAY_RELEASE_BASE_URL; do
  : > "$record"
  temporary_before=$(temporary_tree_snapshot)
  if run_root_client "$release_key=https://attacker.invalid" >/dev/null \
    2> "$test_root/client-$release_key.err"; then
    echo "root client installer accepted hostile $release_key" >&2
    exit 1
  fi
  test ! -s "$record"
  test "$(temporary_tree_snapshot)" = "$temporary_before"
done

# Caller PATH, HOME, TMPDIR, and Docker platform selection cannot redirect any
# privileged executable, plugin, temporary tree, or daemon target.
hostile_tmp=$test_root/hostile-tmp
hostile_home=$test_root/hostile-home
mkdir "$hostile_tmp"
mkdir -p "$hostile_home/.docker/cli-plugins"
cat > "$hostile_home/.docker/cli-plugins/docker-compose" <<'EOF'
#!/bin/sh
printf '%s\n' hostile-docker-plugin >> "$LANEWAY_OUTER_TEST_RECORD"
exit 1
EOF
chmod 0755 "$hostile_home/.docker/cli-plugins/docker-compose"
: > "$record"
temporary_before=$(temporary_tree_snapshot)
run_outer TMPDIR="$hostile_tmp" HOME="$hostile_home" \
  DOCKER_DEFAULT_PLATFORM=linux/386 >/dev/null
if grep -Eq '^(caller-path-tool|hostile-docker-plugin)$' "$record"; then
  echo "outer installer executed a caller-controlled tool or Docker plugin" >&2
  exit 1
fi
test "$(grep -c '^preflight$' "$record")" -eq 1
test "$(grep -c '^install$' "$record")" -eq 1
test "$(grep -c '^final$' "$record")" -eq 1
test ! -e "$deployment/generated/lifecycle/operator.lock"
test "$(temporary_tree_snapshot)" = "$temporary_before"

# Both documented upgrade option forms parse and complete the same handoff.
: > "$record"
run_outer_production >/dev/null
test "$(grep -c '^preflight$' "$record")" -eq 1
test "$(grep -c '^install$' "$record")" -eq 1
test "$(grep -c '^final$' "$record")" -eq 1

# Signature verification is mandatory even outside the production profile.
: > "$record"
temporary_before=$(temporary_tree_snapshot)
if run_outer LANEWAY_OUTER_TEST_COSIGN_FAIL=1 >/dev/null 2> "$test_root/signature.err"; then
  echo "outer installer accepted an unverifiable release" >&2
  exit 1
fi
if grep -Eq '^(preflight|install|final)$' "$record"; then
  echo "outer installer mutated tools after signature failure" >&2
  exit 1
fi
test ! -e "$deployment/generated/lifecycle/operator.lock"
test "$(temporary_tree_snapshot)" = "$temporary_before"

# Candidate preflight failure occurs under the lock, before package install,
# and both the lock and verified temporary tree are cleaned.
: > "$record"
temporary_before=$(temporary_tree_snapshot)
if run_outer LANEWAY_OUTER_TEST_FAIL_PREFLIGHT=1 >/dev/null 2> "$test_root/preflight.err"; then
  echo "outer installer accepted a failing candidate preflight" >&2
  exit 1
fi
grep -Fx preflight "$record" >/dev/null
if grep -Eq '^(install|final)$' "$record"; then
  echo "outer installer mutated tools after preflight failure" >&2
  exit 1
fi
test ! -e "$deployment/generated/lifecycle/operator.lock"
test "$(temporary_tree_snapshot)" = "$temporary_before"

# Cancellation reaches the complete candidate process group. No child may
# continue into package/final mutation, and outer cleanup removes the lock and
# verified temporary tree promptly.
: > "$record"
temporary_before=$(temporary_tree_snapshot)
start_blocked_outer > "$test_root/signal.out" 2> "$test_root/signal.err" &
outer_pid=$!
attempt=0
while ! grep -Fx preflight-blocked "$record" >/dev/null 2>&1; do
  kill -0 "$outer_pid" 2>/dev/null || {
    echo "outer installer exited before the signal regression reached preflight" >&2
    exit 1
  }
  attempt=$((attempt + 1))
  [ "$attempt" -lt 100 ] || {
    echo "outer installer did not reach the blocking preflight" >&2
    kill -TERM "$outer_pid" 2>/dev/null || true
    exit 1
  }
  sleep 0.05
done
kill -TERM "$outer_pid"
attempt=0
while kill -0 "$outer_pid" 2>/dev/null; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 100 ] || {
    echo "outer installer did not terminate promptly after TERM" >&2
    kill -KILL "$outer_pid" 2>/dev/null || true
    exit 1
  }
  sleep 0.05
done
set +e
wait "$outer_pid"
signal_status=$?
set -e
[ "$signal_status" -ne 0 ] || {
  echo "signal-interrupted outer installer reported success" >&2
  exit 1
}
sleep 0.1
if grep -Eq '^(install|final)$' "$record"; then
  echo "signal-interrupted child continued into privileged mutation" >&2
  exit 1
fi
test ! -e "$deployment/generated/lifecycle/operator.lock"
test "$(temporary_tree_snapshot)" = "$temporary_before"

# A legacy package without the authenticated protocol marker is inert: its
# updater is never executed to probe for support.
: > "$record"
temporary_before=$(temporary_tree_snapshot)
if run_outer LANEWAY_OUTER_TEST_FIXTURE="$legacy_fixture" >/dev/null \
  2> "$test_root/legacy.err"; then
  echo "outer installer accepted a legacy updater without the protocol marker" >&2
  exit 1
fi
if grep -Eq '^(legacy-updater-invoked|preflight|install|final)$' "$record"; then
  echo "outer installer invoked or installed a legacy updater" >&2
  exit 1
fi
test ! -e "$deployment/generated/lifecycle/operator.lock"
test "$(temporary_tree_snapshot)" = "$temporary_before"

# Mirror-supplied image digests must match the authenticated checksum before
# candidate code or package installation runs.
: > "$record"
temporary_before=$(temporary_tree_snapshot)
if run_outer LANEWAY_OUTER_TEST_FIXTURE="$tampered_fixture" >/dev/null \
  2> "$test_root/digest.err"; then
  echo "outer installer accepted tampered image digest metadata" >&2
  exit 1
fi
if grep -Eq '^(preflight|install|final)$' "$record"; then
  echo "outer installer mutated tools after digest metadata failure" >&2
  exit 1
fi
test ! -e "$deployment/generated/lifecycle/operator.lock"
test "$(temporary_tree_snapshot)" = "$temporary_before"

# Root-owned but replaceable path ancestors cannot anchor a lifecycle handoff.
unsafe_parent=$test_root/unsafe-parent
unsafe_deployment=$unsafe_parent/deployment
mkdir -p "$unsafe_deployment/generated/lifecycle"
chmod 0777 "$unsafe_parent"
chmod 0700 "$unsafe_deployment" "$unsafe_deployment/generated" \
  "$unsafe_deployment/generated/lifecycle"
: > "$record"
if run_outer LANEWAY_DEPLOY_DIR="$unsafe_deployment" >/dev/null \
  2> "$test_root/unsafe-ancestor.err"; then
  echo "outer installer accepted a replaceable deployment ancestor" >&2
  exit 1
fi
if grep -Eq '^(preflight|install|final)$' "$record"; then
  echo "outer installer mutated tools under a replaceable ancestor" >&2
  exit 1
fi
test ! -e "$unsafe_deployment/generated/lifecycle/operator.lock"

# A concurrent lifecycle lock is rejected before remote or package mutation.
mkdir "$deployment/generated/lifecycle/operator.lock"
chmod 0700 "$deployment/generated/lifecycle/operator.lock"
: > "$record"
if run_outer >/dev/null 2> "$test_root/concurrent.err"; then
  echo "outer installer accepted a concurrent lifecycle operation" >&2
  exit 1
fi
test ! -s "$record"
test -d "$deployment/generated/lifecycle/operator.lock"
rmdir "$deployment/generated/lifecycle/operator.lock"

echo "outer control-plane installer trust, preflight, lock, and cleanup contract is valid"
