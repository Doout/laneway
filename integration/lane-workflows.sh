#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d)
trap 'find "$test_dir" -depth -delete' EXIT HUP INT TERM
compose_dir=$test_dir/compose
fake_bin=$test_dir/bin
log=$test_dir/calls.log
mkdir -p "$compose_dir/generated/backups" "$fake_bin"
cp "$repo_dir/deploy/compose/laneway-control" "$repo_dir/deploy/compose/preflight.sh" "$compose_dir/"
chmod 0755 "$compose_dir/laneway-control"
chmod 0755 "$compose_dir/preflight.sh"
ln -s "$compose_dir/laneway-control" "$test_dir/laneway-control"
: > "$compose_dir/compose.yaml"
: > "$log"

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
cat > "$compose_dir/recovery.sh" <<'EOF'
#!/bin/sh
set -eu
printf 'recovery' >> "$LANE_TEST_LOG"
printf ' <%s>' "$@" >> "$LANE_TEST_LOG"
printf '\n' >> "$LANE_TEST_LOG"
EOF
cat > "$fake_bin/docker" <<'EOF'
#!/bin/sh
set -eu
printf 'docker' >> "$LANE_TEST_LOG"
printf ' <%s>' "$@" >> "$LANE_TEST_LOG"
printf '\n' >> "$LANE_TEST_LOG"
if [ "${1:-} ${2:-}" = "version --format" ]; then printf '26.1.0\n'; exit 0; fi
case " $* " in
  *" ps --all --quiet "*) [ "${LANE_TEST_OWNED_STACK:-0}" = 0 ] || printf 'owned-id\n' ;;
  *" ps --status running -q controller "*) [ "${LANE_TEST_CONTROLLER_RUNNING:-0}" = 0 ] || printf 'controller-id\n' ;;
  *" ps --status running -q exit-node "*) [ "${LANE_TEST_EXIT_RUNNING:-0}" = 0 ] || printf 'exit-id\n' ;;
  *" ps -q controller "*) printf 'controller-id\n' ;;
  *" ps -q relay "*) printf 'relay-id\n' ;;
  *" ps -q exit-node "*) [ "${LANE_TEST_EXIT_RUNNING:-0}" = 0 ] || printf 'exit-id\n' ;;
  *" inspect --format "*) printf '%s\n' "${LANE_TEST_HEALTH:-healthy}" ;;
  *" exec -T --user 65532:65532 exit-node "*) printf 'carrier=direct-wireguard limiter=healthy\n' ;;
  *" up -d --wait controller relay "*) [ "${LANE_TEST_FAIL_UP:-0}" = 0 ] || exit 1 ;;
esac
EOF
cat > "$fake_bin/laneway" <<'EOF'
#!/bin/sh
set -eu
printf 'laneway' >> "$LANE_TEST_LOG"
printf ' <%s>' "$@" >> "$LANE_TEST_LOG"
printf '\n' >> "$LANE_TEST_LOG"
case " $* " in
  *" controller enrollment-token issue "*) printf '%s\n' '{' '  "token_id": "000102030405060708090a0b0c0d0e0f",' '  "enrollment_token": "single_use_secret",' '  "expires_at_unix_seconds": 2000000000' '}' ;;
esac
EOF
cat > "$fake_bin/getent" <<'EOF'
#!/bin/sh
[ "${LANE_TEST_DNS_FAIL:-0}" = 0 ]
EOF
cat > "$fake_bin/ss" <<'EOF'
#!/bin/sh
[ "${LANE_TEST_PORT_BUSY:-0}" = 0 ] || printf 'foreign-listener\n'
EOF
cat > "$fake_bin/cosign" <<'EOF'
#!/bin/sh
set -eu
printf 'cosign' >> "$LANE_TEST_LOG"
printf ' <%s>' "$@" >> "$LANE_TEST_LOG"
printf '\n' >> "$LANE_TEST_LOG"
[ "${LANE_TEST_COSIGN_FAIL:-0}" = 0 ]
EOF
cat > "$fake_bin/age" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "$compose_dir/validate.sh" "$compose_dir/bootstrap.sh" "$compose_dir/recovery.sh" "$fake_bin/docker" "$fake_bin/laneway" "$fake_bin/cosign" "$fake_bin/getent" "$fake_bin/ss" "$fake_bin/age"

write_env() {
  path=$1; version=$2; digit=$3
  cat > "$path" <<EOF
LANEWAY_VERSION=$version
LANEWAY_INSTALL_PROFILE=quick
LANEWAY_CONTROLLER_IMAGE_DIGEST=sha256:$(printf "%064d" "$digit")
LANEWAY_RELAY_IMAGE_DIGEST=sha256:$(printf "%064d" "$digit")
LANEWAY_ADMIN_IMAGE_DIGEST=sha256:$(printf "%064d" "$digit")
LANEWAY_EXIT_NODE_IMAGE_DIGEST=sha256:$(printf "%064d" "$digit")
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
LANEWAY_RELAY_PUBLIC_ENDPOINT=lane.example.test:4433
LANEWAY_BACKUP_RECIPIENT=age1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
  chmod 0600 "$path"
}

write_env "$compose_dir/.env" 1.0.0 1
candidate=$test_dir/candidate.env
write_env "$candidate" 1.1.0 2
export PATH="$fake_bin:$PATH" LANE_TEST_LOG="$log" LANEWAY_COMMAND="$fake_bin/laneway"

"$compose_dir/laneway-control" init
[ "$(grep -c '^cosign ' "$log")" -eq 4 ]
pull_line=$(grep -n '<pull>' "$log" | tail -1 | cut -d: -f1)
bootstrap_line=$(grep -n '^bootstrap$' "$log" | tail -1 | cut -d: -f1)
[ "$pull_line" -lt "$bootstrap_line" ] || { echo "init bootstrapped before verified pull" >&2; exit 1; }
: > "$log"

LANE_TEST_COSIGN_FAIL=1 "$compose_dir/laneway-control" init >/dev/null 2>"$test_dir/quick-warning.err"
grep -F 'image signatures were not verified during quick install' "$test_dir/quick-warning.err" >/dev/null
: > "$log"

LANE_TEST_DNS_FAIL=1; export LANE_TEST_DNS_FAIL
if "$compose_dir/preflight.sh" >/dev/null 2>&1; then echo "preflight accepted failed DNS" >&2; exit 1; fi
LANE_TEST_DNS_FAIL=0; export LANE_TEST_DNS_FAIL
LANE_TEST_PORT_BUSY=1; export LANE_TEST_PORT_BUSY
if "$compose_dir/preflight.sh" >/dev/null 2>&1; then echo "preflight accepted a foreign listener" >&2; exit 1; fi
LANE_TEST_OWNED_STACK=1; export LANE_TEST_OWNED_STACK
"$compose_dir/preflight.sh" >/dev/null
LANE_TEST_PORT_BUSY=0 LANE_TEST_OWNED_STACK=0
export LANE_TEST_PORT_BUSY LANE_TEST_OWNED_STACK

mkdir -p "$compose_dir/generated/config"
printf '%s\n' 'packet_rate_bits_per_second = 2000000' 'packet_burst_bytes = 65536' > "$compose_dir/generated/config/relay.toml"
: > "$compose_dir/generated/config/exit-node.toml"
LANE_TEST_EXIT_RUNNING=1; export LANE_TEST_EXIT_RUNNING

status_output=$("$test_dir/laneway-control" status)
printf '%s\n' "$status_output" | grep -F 'controller=healthy' >/dev/null
printf '%s\n' "$status_output" | grep -F 'relay=healthy' >/dev/null
printf '%s\n' "$status_output" | grep -F 'relay-limiter=configured rate_bits_per_second=2000000 burst_bytes=65536' >/dev/null
printf '%s\n' "$status_output" | grep -F 'carrier=direct-wireguard limiter=healthy' >/dev/null
grep -F '<ps>' "$log" >/dev/null
LANE_TEST_HEALTH=unhealthy; export LANE_TEST_HEALTH
if "$compose_dir/laneway-control" status >/dev/null 2>&1; then echo "status accepted an unhealthy required service" >&2; exit 1; fi
LANE_TEST_HEALTH=healthy; export LANE_TEST_HEALTH

mkdir -p "$compose_dir/generated/recovery"
printf 'encrypted backup\n' > "$compose_dir/generated/recovery/initial.age"
if sudo env PATH="$PATH" LANE_TEST_LOG="$log" LANE_TEST_EXIT_RUNNING=1 \
  LANE_TEST_COSIGN_FAIL=1 "$compose_dir/laneway-control" production-check >/dev/null 2>&1; then
  echo "production-check accepted failed image signatures" >&2
  exit 1
fi
test ! -e "$compose_dir/generated/lifecycle/production-verified"
sudo env PATH="$PATH" LANE_TEST_LOG="$log" LANE_TEST_EXIT_RUNNING=1 \
  "$compose_dir/laneway-control" production-check >/dev/null
test "$(stat -c %a "$compose_dir/generated/lifecycle/production-verified")" = 600
sudo grep -Fx 'profile=quick' "$compose_dir/generated/lifecycle/production-verified" >/dev/null

"$compose_dir/laneway-control" backup manual.age
grep -F 'recovery <backup> <manual.age>' "$log" >/dev/null
mkdir "$compose_dir/generated/lifecycle/operator.lock"
if "$compose_dir/laneway-control" backup locked.age >/dev/null 2>&1; then
  echo "lane accepted a concurrent lifecycle operation" >&2
  exit 1
fi
rmdir "$compose_dir/generated/lifecycle/operator.lock"

mkdir -p "$compose_dir/generated/pki" "$compose_dir/generated/secrets"
printf '%s\n' '-----BEGIN CERTIFICATE-----' 'fixture' '-----END CERTIFICATE-----' > "$compose_dir/generated/pki/ca.crt"
printf '%s\n' 'fixture-admin-token' > "$compose_dir/generated/secrets/admin.token"

"$compose_dir/laneway-control" invite --name laptop --ephemeral --session-lifetime 2h
grep -F '<--class> <ephemeral>' "$log" >/dev/null
grep -F "<--controller> <https://127.0.0.1:8443>" "$log" >/dev/null
grep -F "<--admin-token-file> <$compose_dir/generated/secrets/admin.token>" "$log" >/dev/null
if grep -F '<--profile> <tools>' "$log" >/dev/null; then
  echo "invite used the Docker admin image" >&2
  exit 1
fi

"$compose_dir/laneway-control" user-token --name remembered-laptop
grep -F '<--requested-name> <remembered-laptop>' "$log" >/dev/null
grep -F '<--class> <remembered>' "$log" >/dev/null

connector_command=$test_dir/connector-command.sh
"$compose_dir/laneway-control" invite --name egress-one --ephemeral --session-lifetime 2h --docker --connector > "$connector_command"
sh -n "$connector_command"
grep -F 'docker run -d' "$connector_command" >/dev/null
grep -F -- "--name 'laneway-connector-egress-one'" "$connector_command" >/dev/null
grep -F -- "--volume 'laneway-connector-egress-one-state:/var/lib/laneway'" "$connector_command" >/dev/null
grep -F -- "--env 'LANEWAY_ENROLLMENT_TOKEN=single_use_secret'" "$connector_command" >/dev/null
grep -F 'ghcr.io/doout/laneway-connector:1.0.0@sha256:' "$connector_command" >/dev/null
grep -F -- '--cap-drop ALL' "$connector_command" >/dev/null
grep -F -- '--cap-add NET_ADMIN' "$connector_command" >/dev/null
grep -F -- '--device /dev/net/tun:/dev/net/tun' "$connector_command" >/dev/null
if grep -F -- '--security-opt no-new-privileges' "$connector_command" >/dev/null; then
  echo "Connector command blocked its non-root capability launcher" >&2
  exit 1
fi
grep -F '<--exit-node>' "$log" >/dev/null
grep -F '<--requested-name> <egress-one>' "$log" >/dev/null

identity=$test_dir/identity.txt
bundle=$test_dir/recovery.age
: > "$identity"; : > "$bundle"
"$compose_dir/laneway-control" restore "$bundle" --identity "$identity"
grep -F "recovery <restore> <$bundle> <$identity>" "$log" >/dev/null

: > "$log"
"$compose_dir/laneway-control" upgrade "$candidate"
grep -F 'LANEWAY_VERSION=1.1.0' "$compose_dir/.env" >/dev/null
grep -F 'LANEWAY_VERSION=1.0.0' "$compose_dir/generated/lifecycle/previous.env" >/dev/null
[ "$(grep -c '^cosign ' "$log")" -eq 4 ]
pull_line=$(grep -n '<pull>' "$log" | tail -1 | cut -d: -f1)
stop_line=$(grep -n '<stop>' "$log" | tail -1 | cut -d: -f1)
[ "$pull_line" -lt "$stop_line" ] || { echo "upgrade stopped services before pull" >&2; exit 1; }

identity_change=$test_dir/identity-change.env
write_env "$identity_change" 1.2.0 3
sed -i 's/^LANEWAY_NETWORK_ID=.*/LANEWAY_NETWORK_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' "$identity_change"
if "$compose_dir/laneway-control" upgrade "$identity_change" >/dev/null 2>&1; then
  echo "upgrade accepted a changed network identity" >&2
  exit 1
fi

"$compose_dir/laneway-control" rollback
grep -F 'LANEWAY_VERSION=1.0.0' "$compose_dir/.env" >/dev/null

write_env "$candidate" 1.2.0 3
LANE_TEST_FAIL_UP=1
export LANE_TEST_FAIL_UP
if "$compose_dir/laneway-control" upgrade "$candidate" >/dev/null 2>&1; then
  echo "failed readiness was reported as success" >&2
  exit 1
fi
grep -F 'LANEWAY_VERSION=1.0.0' "$compose_dir/.env" >/dev/null

update_assets=$test_dir/update-assets
update_package=$test_dir/update-package/laneway
update_tmp=$test_dir/update-tmp
mkdir -p "$update_assets" "$update_package/deploy/compose" "$update_tmp"
printf '%s\n' '1.1.0' > "$update_package/VERSION"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$update_package/install.sh"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$update_package/deploy/compose/upgrade-control-plane.sh"
tar -C "$test_dir/update-package" -czf "$update_assets/laneway_linux_amd64.tar.gz" laneway
(
  cd "$update_assets"
  sha256sum laneway_linux_amd64.tar.gz > checksums.txt
)
: > "$update_assets/checksums.sigstore.json"
cat > "$fake_bin/curl" <<'EOF'
#!/bin/sh
set -eu
case " $* " in
  *"releases/latest"*)
    printf '%s' "https://github.com/Doout/laneway/releases/tag/${LANE_TEST_LATEST_TAG:-v1.1.0}"
    exit 0
    ;;
esac
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o|--output) output=$2; shift 2 ;;
    --write-out) shift 2 ;;
    --*) shift ;;
    *) url=$1; shift ;;
  esac
done
[ -n "$output" ] && [ -n "$url" ]
cp "$LANE_TEST_UPDATE_ASSETS/${url##*/}" "$output"
EOF
cat > "$fake_bin/env" <<'EOF'
#!/bin/sh
set -eu
printf 'update-env' >> "$LANE_TEST_LOG"
printf ' <%s>' "$@" >> "$LANE_TEST_LOG"
printf '\n' >> "$LANE_TEST_LOG"
EOF
chmod 0755 "$fake_bin/curl" "$fake_bin/env"
: > "$log"
current_output=$(sudo /usr/bin/env PATH="$PATH" LANE_TEST_LOG="$log" \
  LANE_TEST_LATEST_TAG=v1.0.0 "$compose_dir/laneway-control" update)
printf '%s\n' "$current_output" | grep -F 'already current (v1.0.0)' >/dev/null
if grep -E 'update-env|verify-blob' "$log" >/dev/null; then
  echo "already-current update performed package work" >&2
  exit 1
fi
: > "$log"
update_output=$(sudo /usr/bin/env PATH="$PATH" LANE_TEST_LOG="$log" \
  LANE_TEST_UPDATE_ASSETS="$update_assets" LANEWAY_COSIGN_BIN="$fake_bin/cosign" \
  LANEWAY_RELEASE_BASE_URL=https://fixture.invalid/v1.1.0 TMPDIR="$update_tmp" \
  "$compose_dir/laneway-control" update)
printf '%s\n' "$update_output" | grep -F "detected Docker Compose deployment at $compose_dir" >/dev/null
printf '%s\n' "$update_output" | grep -F 'updating from v1.0.0 to v1.1.0' >/dev/null
grep -F 'verify-blob' "$log" >/dev/null
grep -F '<PREFIX=/usr/local>' "$log" >/dev/null
grep -F "<LANEWAY_DEPLOY_DIR=$compose_dir>" "$log" >/dev/null
test ! -e "$compose_dir/generated/lifecycle/operator.lock"

echo "Lane lifecycle workflows are fail-closed and recoverable"
