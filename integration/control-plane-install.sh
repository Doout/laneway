#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d)
cleanup() {
  if [ -L /usr/local/sbin/laneway-control ]; then
    case "$(readlink /usr/local/sbin/laneway-control)" in "$test_root"/*) find /usr/local/sbin/laneway-control -maxdepth 0 -delete ;; esac
  fi
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
printf '0.2.8\n' > "$test_root/package/VERSION"
cp "$repo_dir/deploy/compose/install-control-plane.sh" "$source_dir/install-control-plane.sh"
cp "$repo_dir/deploy/compose/verify-rust-release.sh" "$source_dir/verify-rust-release.sh"
for name in compose.yaml compose.rust.yaml recovery.sh validate.sh README.md; do
  printf 'fixture %s\n' "$name" > "$source_dir/$name"
done
cat > "$source_dir/laneway-control" <<'EOF'
#!/bin/sh
printf 'lane %s\n' "$*" >> "$LANEWAY_TEST_LOG"
case "$1" in
  backup)
    grep -Fx LANEWAY_CONTROL_RUNTIME=rust "$(dirname "$0")/.env" >/dev/null || exit 1
    mkdir -p "$(dirname "$0")/generated/recovery"
    printf 'encrypted recovery fixture\n' > "$(dirname "$0")/generated/recovery/$2"
    ;;
  *) exit 1 ;;
esac
EOF
cat > "$source_dir/preflight.sh" <<'EOF'
#!/bin/sh
test "$1" = --rust
EOF
cat > "$source_dir/prepare.sh" <<'EOF'
#!/bin/sh
set -eu
test -d "$1"
test "$LANEWAY_BOOTSTRAP_ARTIFACTS_FILE" = "$PWD/release-metadata/bootstrap-artifacts.toml"
test -s "$LANEWAY_BOOTSTRAP_ARTIFACTS_FILE"
printf 'stage pki\n' >> "$LANEWAY_TEST_LOG"
EOF
cat > "$source_dir/prepare-rust.py" <<'EOF'
import os, pathlib, sys
assert sys.argv[1:] == ["--release-metadata", str(pathlib.Path.cwd() / "release-metadata")]
assert (pathlib.Path(sys.argv[2]) / "checksums.sigstore.json").is_file()
with open(os.environ["LANEWAY_TEST_LOG"], "a") as log:
    log.write("stage rust\n")
EOF
cat > "$source_dir/bootstrap.sh" <<'EOF'
#!/bin/sh
set -eu
test "$#" -eq 1
test "$1" = --rust
printf 'bootstrap %s\n' "$1" >> "$LANEWAY_TEST_LOG"
EOF
cat > "$source_dir/prepare-control-plane.sh" <<'EOF'
#!/bin/sh
output=$1
mkdir -p "$output/control-plane-input"
for name in ca.crt intermediate-chain.crt intermediate.key; do
  printf 'generated %s\n' "$name" > "$output/control-plane-input/$name"
done
printf '%s\n' age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq > "$output/control-plane-input/recovery-recipient.txt"
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

cat > "$mock_bin/docker" <<'EOF'
#!/bin/sh
test "$1" = compose
test "$2" = version
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
exit 0
EOF
cat > "$mock_bin/getent" <<'EOF'
#!/bin/sh
test "$1" = ahosts
printf '203.0.113.10 STREAM %s\n' "$2"
EOF
cat > "$mock_bin/cosign" <<'EOF'
#!/bin/sh
printf 'cosign %s\n' "$*" >> "$LANEWAY_TEST_LOG"
identity=https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/v0.2.8
case "$1" in
  verify-blob)
    test "$5" = "$identity" && test "$(cat "$3")" = fixture-signature
    ;;
  verify)
    test "$3" = "$identity" || exit 1
    [ "${LANEWAY_TEST_COSIGN_FAIL:-0}" = 0 ]
    ;;
  *) exit 1 ;;
esac
EOF
cat > "$mock_bin/curl" <<'EOF'
#!/bin/sh
destination=
asset=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) destination=$2; shift 2 ;;
    https://release.invalid/v0.2.8/*) asset=${1##*/}; shift ;;
    *) shift ;;
  esac
done
test -n "$destination"
test -n "$asset"
cp "$(dirname "$LANEWAY_TEST_DIGESTS")/$asset" "$destination"
if [ "$asset" = image-digests.txt ] && [ "${LANEWAY_TEST_TAMPER:-0}" = 1 ]; then
  printf '\ntampered\n' >> "$destination"
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

cat > "$test_root/image-digests.txt" <<'EOF'
ghcr.io/doout/laneway-admin@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ghcr.io/doout/laneway-controller-rust@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
ghcr.io/doout/lane-edge-rust@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
ghcr.io/doout/laneway-exit-node-rust@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
ghcr.io/doout/laneway-relay-rust@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
EOF
printf 'fixture-signature\n' > "$test_root/checksums.sigstore.json"
printf 'fixture-artifacts\n' > "$test_root/bootstrap-artifacts.toml"
(cd "$test_root" && sha256sum image-digests.txt bootstrap-artifacts.toml > checksums.txt)
printf '0\n' > "$counter_file"

recipient=age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
env \
  PATH="$mock_bin:$PATH" \
  LANEWAY_NONINTERACTIVE=true \
  LANEWAY_VERSION=0.2.8 \
  LANEWAY_DOMAIN=lane.example.test \
  LANEWAY_DEPLOY_DIR="$destination" \
  LANEWAY_BACKUP_RECIPIENT="$recipient" \
  LANEWAY_ISSUER_DIR="$issuer_dir" \
  LANEWAY_CONFIRM=deploy \
  LANEWAY_RELEASE_BASE_URL=https://release.invalid/v0.2.8 \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  LANEWAY_INSTALLER_ANSWERS_FILE="$answers_file" \
  "$source_dir/install-control-plane.sh" >/dev/null

test "$(stat -c %a "$destination")" = 700
test "$(stat -c %a "$destination/.env")" = 600
grep -Fx 'LANEWAY_VERSION=0.2.8' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_INSTALL_PROFILE=quick' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_CONTROL_RUNTIME=rust' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_RUST_VERSION=0.2.8' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_RUST_CONTROLLER_IMAGE_DIGEST=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_RUST_CONNECTOR_IMAGE_DIGEST=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_RUST_EXIT_NODE_IMAGE_DIGEST=sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' "$destination/.env" >/dev/null
if grep -E '^LANEWAY_(CONTROLLER|RELAY|CONNECTOR|EXIT_NODE)_IMAGE_DIGEST=' "$destination/.env"; then
  echo "fresh installer pinned a Go runtime" >&2
  exit 1
fi
grep -Fx 'LANEWAY_CONTROLLER_SERVER_NAME=lane.example.test' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_RELAY_PUBLIC_ENDPOINT=lane.example.test:4433' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_NETWORK_ID=000102030405060708090a0b0c0d0e0f' "$destination/.env" >/dev/null
test "$(grep -c '^cosign verify ' "$log_file")" -eq 5
test "$(grep -c '^cosign verify-blob ' "$log_file")" -eq 1
grep -Fx "stage pki" "$log_file" >/dev/null
grep -Fx "stage rust" "$log_file" >/dev/null
grep -Fx "bootstrap --rust" "$log_file" >/dev/null
grep -E '^lane backup initial-recovery-[0-9]{8}T[0-9]{6}Z\.age$' "$log_file" >/dev/null
test "$(stat -c %a "$answers_file")" = 600
grep -Fx 'LANEWAY_DOMAIN=lane.example.test' "$answers_file" >/dev/null
grep -Fx 'LANEWAY_CONTROLLER_PORT=8443' "$answers_file" >/dev/null
grep -Fx "LANEWAY_PREPARED_INPUT_DIR=$issuer_dir" "$answers_file" >/dev/null
test -f "$destination/PRODUCTION-CHECKLIST.md"
grep -F 'laneway-control readiness' "$destination/PRODUCTION-CHECKLIST.md" >/dev/null
test "$(stat -c %a "$destination/release-metadata")" = 700
test "$(stat -c %a "$destination/release-metadata/image-digests.txt")" = 600
test -x "$destination/laneway-control"
test -L "$destination/lane"
test "$(readlink "$destination/lane")" = laneway-control
test "$(readlink /usr/local/sbin/laneway-control)" = "$destination/laneway-control"
find /usr/local/sbin/laneway-control -maxdepth 0 -delete

remembered_cancel=$test_root/remembered-cancel
printf '0\n' > "$counter_file"
if env \
  PATH="$mock_bin:$PATH" \
  LANEWAY_NONINTERACTIVE=true \
  LANEWAY_VERSION=0.2.8 \
  LANEWAY_DEPLOY_DIR="$remembered_cancel" \
  LANEWAY_CONFIRM=no \
  LANEWAY_RELEASE_BASE_URL=https://release.invalid/v0.2.8 \
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
  LANEWAY_RELEASE_BASE_URL=https://release.invalid/v0.2.8 \
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
grep -F 'Release checksum and container image signatures: **verified**' "$automatic/PRODUCTION-CHECKLIST.md" >/dev/null
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
  LANEWAY_RELEASE_BASE_URL=https://release.invalid/v0.2.8 \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  LANEWAY_TEST_COSIGN_FAIL=1 \
  LANEWAY_INSTALLER_ANSWERS_FILE="$test_root/production-installer-state/answers" \
  "$source_dir/install-control-plane.sh" >/dev/null 2>"$test_root/production.err"; then
  echo "production installer accepted failed image signatures" >&2
  exit 1
fi
grep -F 'Rust release signature verification failed' "$test_root/production.err" >/dev/null
test ! -e "$production_failed"
test ! -e /usr/local/sbin/laneway-control

tampered=$test_root/tampered
if env \
  PATH="$mock_bin:$PATH" LANEWAY_NONINTERACTIVE=true LANEWAY_VERSION=0.2.8 \
  LANEWAY_DOMAIN=lane.example.test LANEWAY_DEPLOY_DIR="$tampered" LANEWAY_CONFIRM=deploy \
  LANEWAY_ISSUER_DIR="$issuer_dir" LANEWAY_BACKUP_RECIPIENT="$recipient" \
  LANEWAY_RELEASE_BASE_URL=https://release.invalid/v0.2.8 LANEWAY_TEST_TAMPER=1 \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" LANEWAY_TEST_LOG="$log_file" \
  LANEWAY_INSTALLER_ANSWERS_FILE="$test_root/tampered-answers" \
  "$source_dir/install-control-plane.sh" >/dev/null 2>"$test_root/tampered.err"; then
  echo "quick installer accepted tampered release metadata" >&2
  exit 1
fi
grep -F 'image-digests.txt differs from its signed checksum' "$test_root/tampered.err" >/dev/null
test ! -e "$tampered"
test ! -e "$test_root/tampered-answers"

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
  LANEWAY_RELEASE_BASE_URL=https://release.invalid/v0.2.8 \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  LANEWAY_INSTALLER_ANSWERS_FILE="$test_root/cancelled-installer-state/answers" \
  "$source_dir/install-control-plane.sh" >/dev/null 2>&1; then
  echo "installer accepted a deployment without explicit confirmation" >&2
  exit 1
fi
test ! -e "$cancelled"

echo "Interactive control-plane installer contract is valid"
