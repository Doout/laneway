#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d)
trap 'find "$test_dir" -depth -delete' EXIT HUP INT TERM
compose_dir=$test_dir/compose
fake_bin=$test_dir/bin
log=$test_dir/calls.log
mkdir -p "$compose_dir/generated/backups" "$compose_dir/generated/config" "$fake_bin"
cp "$repo_dir/deploy/compose/laneway-control" "$repo_dir/deploy/compose/preflight.sh" "$compose_dir/"
chmod 0755 "$compose_dir/laneway-control"
chmod 0755 "$compose_dir/preflight.sh"
ln -s "$compose_dir/laneway-control" "$test_dir/laneway-control"
: > "$compose_dir/compose.yaml"
: > "$compose_dir/generated/config/controller.toml"
: > "$compose_dir/generated/config/relay.toml"
printf '%s\n' workflow-database > "$compose_dir/database.state"
: > "$compose_dir/volume.exists"
: > "$compose_dir/controller.container"
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
docker_real_find=$(PATH=/usr/bin:/bin command -v find)
if [ "${1:-} ${2:-}" = "version --format" ]; then printf '26.1.0\n'; exit 0; fi
if [ "${1:-} ${2:-}" = "container inspect" ]; then exit 1; fi
if [ "${1:-} ${2:-}" = "volume inspect" ]; then [ -f "$LANEWAY_DEPLOY_DIR/volume.exists" ]; exit; fi
if [ "${1:-} ${2:-}" = "volume rm" ]; then
  "$docker_real_find" "$LANEWAY_DEPLOY_DIR/volume.exists" "$LANEWAY_DEPLOY_DIR/database.state" -maxdepth 0 -delete
  exit 0
fi
case " $* " in
  *" config --format json "*) printf '%s\n' '{"services":{"controller":{"volumes":[{"type":"volume","source":"controller-state","target":"/var/lib/laneway-controller"}]}},"volumes":{"controller-state":{"name":"laneway-controller-state"}}}' ;;
  *" ps -a -q controller "*)
    [ ! -f "$LANEWAY_DEPLOY_DIR/controller.container" ] || printf 'controller-id\n'
    exit 0
    ;;
  *" rm -s -f controller "*) "$docker_real_find" "$LANEWAY_DEPLOY_DIR/controller.container" -maxdepth 0 -delete 2>/dev/null || true ;;
  *" run --rm --no-deps controller "*" -backup /backups/"*)
    name=${*##* /backups/}; name=${name%% *}
    cp "$LANEWAY_DEPLOY_DIR/database.state" "$LANEWAY_DEPLOY_DIR/generated/backups/$name"
    chmod 0600 "$LANEWAY_DEPLOY_DIR/generated/backups/$name"
    chown 65532:65532 "$LANEWAY_DEPLOY_DIR/generated/backups/$name"
    ;;
  *" run --rm --no-deps controller "*" -restore /backups/"*)
    name=${*##* /backups/}; name=${name%% *}
    [ ! -e "$LANEWAY_DEPLOY_DIR/database.state" ]
    cp "$LANEWAY_DEPLOY_DIR/generated/backups/$name" "$LANEWAY_DEPLOY_DIR/database.state"
    : > "$LANEWAY_DEPLOY_DIR/volume.exists"
    ;;
  *" connector bootstrap-activate "*) cat >/dev/null ;;
  *" ps --all --quiet "*) [ "${LANE_TEST_OWNED_STACK:-0}" = 0 ] || printf 'owned-id\n' ;;
  *" ps --status running -q controller "*) [ "${LANE_TEST_CONTROLLER_RUNNING:-0}" = 0 ] || printf 'controller-id\n' ;;
  *" ps --status running -q exit-node "*) [ "${LANE_TEST_EXIT_RUNNING:-0}" = 0 ] || printf 'exit-id\n' ;;
  *" ps -q controller "*) printf 'controller-id\n' ;;
  *" ps -q relay "*) printf 'relay-id\n' ;;
  *" ps -q exit-node "*) [ "${LANE_TEST_EXIT_RUNNING:-0}" = 0 ] || printf 'exit-id\n' ;;
  *" inspect --format "*) printf '%s\n' "${LANE_TEST_HEALTH:-healthy}" ;;
  *" exec -T --user 65532:65532 exit-node "*) printf 'carrier=direct-wireguard limiter=healthy\n' ;;
  *" up -d --wait controller relay "*) [ "${LANE_TEST_FAIL_UP:-0}" = 0 ] || exit 1; : > "$LANEWAY_DEPLOY_DIR/controller.container" ;;
esac
EOF
cat > "$fake_bin/jq" <<'EOF'
#!/bin/sh
set -eu
cat >/dev/null
printf '%s\n' laneway-controller-state
EOF
cat > "$fake_bin/laneway" <<'EOF'
#!/bin/sh
set -eu
printf 'laneway' >> "$LANE_TEST_LOG"
printf ' <%s>' "$@" >> "$LANE_TEST_LOG"
printf '\n' >> "$LANE_TEST_LOG"
case " $* " in
  *" connector bootstrap-seal "*)
    envelope_file=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --out) envelope_file=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    test -n "$envelope_file"
    cat >/dev/null
    printf '%s\n' 'encrypted_bootstrap_envelope' > "$envelope_file"
    chmod 0600 "$envelope_file"
    printf '%s\n' 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk'
    ;;
  *" controller bootstrap-bundle create "*)
    [ "${LANE_TEST_BOOTSTRAP_BUNDLE_FAIL:-0}" = 0 ] || exit 1
    payload_file=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --payload-file) payload_file=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    test -n "$payload_file"
    cp "$payload_file" "$LANE_TEST_BOOTSTRAP_CAPTURE"
    printf '%s\n' '{' \
      '  "bundle_id": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",' \
      '  "public_path": "/.well-known/laneway/bootstrap/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",' \
      '  "expires_at_unix_seconds": 2000000000' '}'
    ;;
  *" controller enrollment-token issue "*) printf '%s\n' '{' '  "token_id": "000102030405060708090a0b0c0d0e0f",' '  "enrollment_token": "single_use_secret",' '  "expires_at_unix_seconds": 2000000000' '}' ;;
  *" controller overview "*) printf '%s\n' '' 'Active enrollment inventory (11111111111111111111111111111111)' 'NAME       ROLE       OVERLAY       FORWARDING' 'ibmcloud   connector  100.96.0.12  10.240.64.6/32 (nat)' ;;
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
chmod 0755 "$compose_dir/validate.sh" "$compose_dir/bootstrap.sh" "$compose_dir/recovery.sh" "$fake_bin/docker" "$fake_bin/laneway" "$fake_bin/cosign" "$fake_bin/getent" "$fake_bin/ss" "$fake_bin/age" "$fake_bin/jq"

write_env() {
  path=$1; version=$2; digit=$3
  cat > "$path" <<EOF
LANEWAY_VERSION=$version
LANEWAY_INSTALL_PROFILE=quick
LANEWAY_CONTROLLER_IMAGE_DIGEST=sha256:$(printf "%064d" "$digit")
LANEWAY_RELAY_IMAGE_DIGEST=sha256:$(printf "%064d" "$digit")
LANEWAY_ADMIN_IMAGE_DIGEST=sha256:$(printf "%064d" "$digit")
LANEWAY_CONNECTOR_IMAGE_DIGEST=sha256:$(printf "%064d" "$digit")
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
export PATH="$fake_bin:$PATH" LANE_TEST_LOG="$log" LANEWAY_COMMAND="$fake_bin/laneway" LANEWAY_DEPLOY_DIR="$compose_dir"
export LANE_TEST_BOOTSTRAP_CAPTURE="$test_dir/bootstrap-payload.sh"

"$compose_dir/laneway-control" init
[ "$(grep -c '^cosign ' "$log")" -eq 5 ]
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
printf '%s\n' "$status_output" | grep -F 'Active enrollment inventory' >/dev/null
printf '%s\n' "$status_output" | grep -F 'ibmcloud   connector' >/dev/null
grep -F '<ps>' "$log" >/dev/null
LANE_TEST_HEALTH=unhealthy; export LANE_TEST_HEALTH
if "$compose_dir/laneway-control" status >/dev/null 2>&1; then echo "status accepted an unhealthy required service" >&2; exit 1; fi
LANE_TEST_HEALTH=healthy; export LANE_TEST_HEALTH

mkdir -p "$compose_dir/generated/recovery"
printf 'encrypted backup\n' > "$compose_dir/generated/recovery/initial.age"
if sudo env PATH="$PATH" LANEWAY_COMMAND="$fake_bin/laneway" LANE_TEST_LOG="$log" LANE_TEST_EXIT_RUNNING=0 \
  LANE_TEST_COSIGN_FAIL=1 "$compose_dir/laneway-control" production-check >/dev/null 2>&1; then
  echo "production-check accepted failed image signatures" >&2
  exit 1
fi
test ! -e "$compose_dir/generated/lifecycle/production-verified"
sudo env PATH="$PATH" LANEWAY_COMMAND="$fake_bin/laneway" LANE_TEST_LOG="$log" LANE_TEST_EXIT_RUNNING=0 \
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

shared_exit_token=$test_dir/shared-exit-token
shared_exit_instructions=$test_dir/shared-exit-instructions
"$compose_dir/laneway-control" invite --name borrowed-egress --shared-host-exit > "$shared_exit_token" 2> "$shared_exit_instructions"
grep -Fx 'single_use_secret' "$shared_exit_token" >/dev/null
grep -F '<--class> <ephemeral>' "$log" >/dev/null
grep -F '<--session-lifetime> <8h>' "$log" >/dev/null
grep -F '<--exit-node>' "$log" >/dev/null
grep -F "releases/download/v1.0.0/ephemeral-exit-bootstrap.sh" "$shared_exit_instructions" >/dev/null
grep -F -- "--authority 'lane.example.test:8443' --name 'borrowed-egress' --max-runtime '8h'" "$shared_exit_instructions" >/dev/null
if grep -F 'single_use_secret' "$shared_exit_instructions" >/dev/null; then
  echo "shared-host Exit invitation leaked into its bootstrap command" >&2
  exit 1
fi

"$compose_dir/laneway-control" user-token --name remembered-laptop
grep -F '<--requested-name> <remembered-laptop>' "$log" >/dev/null
grep -F '<--class> <remembered>' "$log" >/dev/null

"$compose_dir/laneway-control" route add --connector ibmcloud --to 10.240.64.6 --allow remembered-laptop
grep -F '<controller> <route> <assign>' "$log" >/dev/null
grep -F '<--connector> <ibmcloud>' "$log" >/dev/null
grep -F '<--to> <10.240.64.6>' "$log" >/dev/null
grep -F '<--allow> <remembered-laptop>' "$log" >/dev/null
grep -F "<--admin-token-file> <$compose_dir/generated/secrets/admin.token>" "$log" >/dev/null

connector_command=$test_dir/connector-command.sh
"$compose_dir/laneway-control" invite --name egress-one --ephemeral --session-lifetime 2h --docker --connector > "$connector_command"
sh -n "$connector_command"
grep -F 'docker run -d' "$connector_command" >/dev/null
grep -F -- "--name 'laneway-connector-egress-one'" "$connector_command" >/dev/null
grep -F -- "--volume 'laneway-connector-egress-one-state:/var/lib/laneway'" "$connector_command" >/dev/null
setup_token=$(sed -n "s/.*--env 'SETUP_TOKEN=\(st1\.[A-Za-z0-9+\/=]*\)'.*/\1/p" "$connector_command")
[ -n "$setup_token" ] || { echo "Connector command has no setup token" >&2; exit 1; }
printf '%s' "${setup_token#st1.}" | base64 -d > "$test_dir/setup-token.txt"
grep -Fx 'egress-one' "$test_dir/setup-token.txt" >/dev/null
grep -Fx 'single_use_secret' "$test_dir/setup-token.txt" >/dev/null
grep -Fx 'https://lane.example.test:8443' "$test_dir/setup-token.txt" >/dev/null
grep -F 'ghcr.io/doout/lane-edge:1.0.0@sha256:' "$connector_command" >/dev/null
grep -F -- '--cap-drop ALL' "$connector_command" >/dev/null
grep -F -- '--security-opt no-new-privileges:true' "$connector_command" >/dev/null
if grep -E -- '--cap-add|--device|--sysctl|--publish|LANEWAY_(ENROLLMENT|NETWORK|CONTROLLER|RELAY|CA_)' "$connector_command" >/dev/null; then
  echo "userspace Connector command exposed privileged networking or expanded bootstrap metadata" >&2
  exit 1
fi
grep -F '<--connector>' "$log" >/dev/null
grep -F '<--requested-name> <egress-one>' "$log" >/dev/null

bootstrap_command=$test_dir/bootstrap-command.sh
bootstrap_stderr=$test_dir/bootstrap-command.err
"$compose_dir/laneway-control" invite --name office --docker --connector --bootstrap > "$bootstrap_command" 2> "$bootstrap_stderr"
grep -F "curl --fail --silent --show-error --proto '=https' --tlsv1.3 'https://lane.example.test/.well-known/laneway/bootstrap/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'" "$bootstrap_command" >/dev/null
grep -F "| sudo bash -s -- 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk'" "$bootstrap_command" >/dev/null
grep -F 'expires in 10 minutes and is consumed by the first download' "$bootstrap_stderr" >/dev/null
test ! -e "$compose_dir/generated/lifecycle/operator.lock"
if LANE_TEST_BOOTSTRAP_BUNDLE_FAIL=1 "$compose_dir/laneway-control" invite \
  --name failed-office --docker --connector --bootstrap >/dev/null 2>&1; then
  echo "failed encrypted bootstrap was reported as successful" >&2
  exit 1
fi
test ! -e "$compose_dir/generated/lifecycle/operator.lock"
bash -n "$LANE_TEST_BOOTSTRAP_CAPTURE"
grep -F 'connector bootstrap-activate --envelope-file /run/laneway-bootstrap/envelope' "$LANE_TEST_BOOTSTRAP_CAPTURE" >/dev/null
grep -F 'docker run -d' "$LANE_TEST_BOOTSTRAP_CAPTURE" >/dev/null
grep -F -- '--pull never' "$LANE_TEST_BOOTSTRAP_CAPTURE" >/dev/null
grep -F -- '--cap-drop ALL' "$LANE_TEST_BOOTSTRAP_CAPTURE" >/dev/null
grep -F -- '--security-opt no-new-privileges:true' "$LANE_TEST_BOOTSTRAP_CAPTURE" >/dev/null
grep -F 'encrypted_bootstrap_envelope' "$LANE_TEST_BOOTSTRAP_CAPTURE" >/dev/null
if grep -E 'single_use_secret|SETUP_TOKEN|kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk' "$LANE_TEST_BOOTSTRAP_CAPTURE" >/dev/null; then
  echo "encrypted bootstrap wrapper exposed its enrollment token or decryption key" >&2
  exit 1
fi
if grep -F 'single_use_secret' "$bootstrap_command" >/dev/null; then
  echo "bootstrap curl command exposed its enrollment token" >&2
  exit 1
fi
bootstrap_runtime_log=$test_dir/bootstrap-runtime.log
: > "$bootstrap_runtime_log"
env PATH="$fake_bin:$PATH" LANE_TEST_LOG="$bootstrap_runtime_log" \
  bash "$LANE_TEST_BOOTSTRAP_CAPTURE" kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk >/dev/null
[ "$(grep -c '^docker <run>' "$bootstrap_runtime_log")" -eq 2 ]
grep -F '<connector> <bootstrap-activate>' "$bootstrap_runtime_log" >/dev/null
final_run=$(grep '^docker <run>' "$bootstrap_runtime_log" | tail -1)
if printf '%s\n' "$final_run" | grep -E 'SETUP_TOKEN|bootstrap|envelope|--env' >/dev/null; then
  echo "final Connector redeployment retained bootstrap metadata" >&2
  exit 1
fi
if grep -E 'single_use_secret|kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk' "$bootstrap_runtime_log" >/dev/null; then
  echo "bootstrap execution exposed the enrollment token or key in Docker arguments" >&2
  exit 1
fi
if "$compose_dir/laneway-control" invite --name invalid --docker --connector --bootstrap --expires-in 20m >/dev/null 2>&1; then
  echo "bootstrap accepted a caller-controlled lifetime" >&2
  exit 1
fi
test ! -e "$compose_dir/generated/lifecycle/operator.lock"

identity=$test_dir/identity.txt
bundle=$test_dir/recovery.age
: > "$identity"; : > "$bundle"
"$compose_dir/laneway-control" restore "$bundle" --identity "$identity"
grep -F "recovery <restore> <$bundle> <$identity>" "$log" >/dev/null

: > "$log"
sudo chown 0:0 "$compose_dir/generated/lifecycle"
sudo chmod 0700 "$compose_dir/generated/lifecycle" "$compose_dir/generated/backups"
sudo env PATH="$PATH" LANEWAY_COMMAND="$fake_bin/laneway" LANE_TEST_LOG="$log" \
  LANEWAY_DEPLOY_DIR="$compose_dir" "$compose_dir/laneway-control" upgrade "$candidate"
sudo grep -F 'LANEWAY_VERSION=1.1.0' "$compose_dir/.env" >/dev/null
previous_generation_name=$(sudo sed -n '1p' "$compose_dir/generated/lifecycle/previous-release")
previous_generation=$compose_dir/generated/lifecycle/$previous_generation_name
sudo sh -c 'cd "$1" && sha256sum -c MANIFEST.sha256 >/dev/null' sh "$previous_generation"
sudo grep -F 'LANEWAY_VERSION=1.0.0' "$previous_generation/release.env" >/dev/null
[ "$(grep -c '^cosign ' "$log")" -eq 5 ]
pull_line=$(grep -n '<pull>' "$log" | tail -1 | cut -d: -f1)
stop_line=$(grep -n '<stop>' "$log" | tail -1 | cut -d: -f1)
[ "$pull_line" -lt "$stop_line" ] || { echo "upgrade stopped services before pull" >&2; exit 1; }

identity_change=$test_dir/identity-change.env
write_env "$identity_change" 1.2.0 3
sed -i 's/^LANEWAY_NETWORK_ID=.*/LANEWAY_NETWORK_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' "$identity_change"
if sudo env PATH="$PATH" LANEWAY_COMMAND="$fake_bin/laneway" LANE_TEST_LOG="$log" \
  LANEWAY_DEPLOY_DIR="$compose_dir" "$compose_dir/laneway-control" upgrade "$identity_change" \
  >/dev/null 2>&1; then
  echo "upgrade accepted a changed network identity" >&2
  exit 1
fi

if ! rollback_output=$(sudo env PATH="$PATH" LANEWAY_COMMAND="$fake_bin/laneway" LANE_TEST_LOG="$log" \
  LANEWAY_DEPLOY_DIR="$compose_dir" "$compose_dir/laneway-control" rollback 2>&1); then
  printf '%s\n' "$rollback_output" >&2
  cat "$log" >&2
  echo "rollback workflow failed" >&2
  exit 1
fi
sudo grep -F 'LANEWAY_VERSION=1.0.0' "$compose_dir/.env" >/dev/null

write_env "$candidate" 1.2.0 3
LANE_TEST_FAIL_UP=1
export LANE_TEST_FAIL_UP
if sudo env PATH="$PATH" LANEWAY_COMMAND="$fake_bin/laneway" LANE_TEST_LOG="$log" \
  LANEWAY_DEPLOY_DIR="$compose_dir" LANE_TEST_FAIL_UP=1 \
  "$compose_dir/laneway-control" upgrade "$candidate" >/dev/null 2>&1; then
  echo "failed readiness was reported as success" >&2
  exit 1
fi
sudo grep -F 'LANEWAY_VERSION=1.0.0' "$compose_dir/.env" >/dev/null
sudo chown -R "$(id -u):$(id -g)" "$test_dir"

update_assets=$test_dir/update-assets
update_package=$test_dir/update-package/laneway
update_tmp=$test_dir/update-tmp
mkdir -p "$update_assets" "$update_package/deploy/compose" "$update_tmp"
printf '%s\n' '1.1.0' > "$update_package/VERSION"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$update_package/install.sh"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$update_package/deploy/compose/upgrade-control-plane.sh"
case "$(uname -m)" in
  x86_64|amd64) update_arch=amd64 ;;
  aarch64|arm64) update_arch=arm64 ;;
  *) echo "unsupported update test architecture" >&2; exit 1 ;;
esac
update_asset=laneway_linux_${update_arch}.tar.gz
tar -C "$test_dir/update-package" -czf "$update_assets/$update_asset" laneway
cat > "$update_assets/bootstrap-artifacts.toml" <<'EOF'
[[bootstrap.artifacts]]
[[bootstrap.artifacts]]
[[bootstrap.artifacts]]
[[bootstrap.artifacts]]
EOF
(
  cd "$update_assets"
  sha256sum bootstrap-artifacts.toml "$update_asset" > checksums.txt
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
printf '%s\n' "$update_output" | grep -F 'Laneway control-plane update' >/dev/null
printf '%s\n' "$update_output" | grep -F "Deployment: $compose_dir" >/dev/null
printf '%s\n' "$update_output" | grep -F 'Version:    v1.0.0 -> v1.1.0' >/dev/null
grep -F 'verify-blob' "$log" >/dev/null
grep -F '<PREFIX=/usr/local>' "$log" >/dev/null
grep -F "<LANEWAY_DEPLOY_DIR=$compose_dir>" "$log" >/dev/null
grep -F "<LANEWAY_BOOTSTRAP_ARTIFACTS_FILE=$compose_dir/generated/lifecycle/bootstrap-artifacts-1.1.0.toml>" "$log" >/dev/null
grep -F '✓ Download and verify signed release' <<EOF >/dev/null
$update_output
EOF
grep -F '✓ Install control-plane tools' <<EOF >/dev/null
$update_output
EOF
test -f "$compose_dir/generated/lifecycle/bootstrap-artifacts-1.1.0.toml"
test ! -e "$compose_dir/generated/lifecycle/operator.lock"

echo "Lane lifecycle workflows are fail-closed and recoverable"
