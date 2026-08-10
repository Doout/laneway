#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d)
trap 'find "$test_root" -depth -delete' EXIT HUP INT TERM
package_dir=$test_root/package
compose_source=$package_dir/deploy/compose
deployment=$test_root/laneway
fake_bin=$test_root/bin
log=$test_root/calls.log
mkdir -p "$compose_source" "$deployment/generated/lifecycle" "$deployment/generated/config" "$fake_bin"
cp "$repo_dir/deploy/compose/upgrade-control-plane.sh" "$repo_dir/deploy/compose/laneway-control" "$compose_source/"
cp "$repo_dir/deploy/compose/compose.yaml" "$compose_source/compose.yaml"
printf '0.2.15\n' > "$package_dir/VERSION"
: > "$deployment/compose.yaml"
cat > "$deployment/generated/config/controller.toml" <<'EOF'
mode = "controller"
EOF
cat > "$deployment/generated/config/relay.toml" <<'EOF'
mode = "relay"
EOF
chmod 0444 "$deployment/generated/config/controller.toml" "$deployment/generated/config/relay.toml"
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
printf 'recovery <%s> <%s>\n' "$1" "$2" >> "$LANEWAY_TEST_LOG"
EOF
cat > "$deployment/validate.sh" <<'EOF'
#!/bin/sh
printf 'validate\n' >> "$LANEWAY_TEST_LOG"
EOF
chmod 0755 "$deployment/lane" "$deployment/recovery.sh" "$deployment/validate.sh"

cat > "$test_root/image-digests.txt" <<'EOF'
ghcr.io/doout/laneway-controller@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ghcr.io/doout/laneway-relay@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
ghcr.io/doout/laneway-admin@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
ghcr.io/doout/laneway-connector@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
EOF
cat > "$fake_bin/curl" <<'EOF'
#!/bin/sh
set -eu
case " $* " in
  *" /.well-known/laneway/bootstrap.json "*|*"https://lane.example.test/.well-known/laneway/bootstrap.json"*)
    printf '%s\n' '{"network_id":"000102030405060708090a0b0c0d0e0f"}'
    exit 0
    ;;
esac
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then output=$2; shift 2; continue; fi
  shift
done
cp "$LANEWAY_TEST_DIGESTS" "$output"
EOF
cat > "$fake_bin/docker" <<'EOF'
#!/bin/sh
set -eu
printf 'docker' >> "$LANEWAY_TEST_LOG"
printf ' <%s>' "$@" >> "$LANEWAY_TEST_LOG"
printf '\n' >> "$LANEWAY_TEST_LOG"
case " $* " in
  *" compose version "*) exit 0 ;;
  *" ps --status running -q exit-node "*) exit 0 ;;
esac
EOF
cat > "$fake_bin/cosign" <<'EOF'
#!/bin/sh
printf 'cosign' >> "$LANEWAY_TEST_LOG"
printf ' <%s>' "$@" >> "$LANEWAY_TEST_LOG"
printf '\n' >> "$LANEWAY_TEST_LOG"
EOF
chmod 0755 "$fake_bin/curl" "$fake_bin/docker" "$fake_bin/cosign"

system_command=$test_root/sbin/laneway-control
mkdir -p "$(dirname "$system_command")"
env PATH="$fake_bin:$PATH" \
  LANEWAY_VERSION=v9.9.9 \
  LANEWAY_DEPLOY_DIR="$deployment" \
  LANEWAY_CONTROL_COMMAND="$system_command" \
  LANEWAY_RELEASE_BASE_URL=https://release.invalid/v0.2.15 \
  LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_LOG="$log" \
  "$compose_source/upgrade-control-plane.sh" > "$test_root/output"

grep -Fx 'LANEWAY_VERSION=0.2.15' "$deployment/.env" >/dev/null
grep -Fx 'LANEWAY_CONTROLLER_IMAGE_DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$deployment/.env" >/dev/null
test -x "$deployment/laneway-control"
test -L "$deployment/lane"
test "$(readlink "$deployment/lane")" = laneway-control
test -x "$deployment/generated/lifecycle/lane-before-0.2.15"
test -L "$system_command"
test "$(readlink "$system_command")" = "$deployment/laneway-control"
grep -F 'recovery <backup> <pre-upgrade-' "$log" >/dev/null
grep -F 'docker <compose>' "$log" >/dev/null
grep -F 'cosign <verify>' "$log" >/dev/null
grep -F 'host networking are unchanged' "$test_root/output" >/dev/null

echo "control-plane upgrade integration test passed"
