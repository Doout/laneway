#!/usr/bin/env bash
# Run the actual packaged initializer with real Docker and recovery on a lab.
# Release downloads, signature verification, public DNS and the host bridge worker are fixtures.
set -euo pipefail
trap 'printf "fresh installer test failed at line %s\n" "$LINENO" >&2' ERR
marker=/run/.laneway-isolated-compose-lab
if [[ $(id -u) != 0 || ! -f "$marker" || -L "$marker" ||
      $(stat -c '%u:%a' "$marker") != 0:600 || -n ${DOCKER_HOST:-} || -n ${DOCKER_CONTEXT:-} ]]; then
  echo 'Run as root on a marked disposable Docker VM with a local Docker socket.' >&2
  exit 2
fi
dispatch_test=false
if [[ -n ${LANEWAY_INSTALLED_DISPATCH_TEST:-} || -n ${LANEWAY_DISPATCH_PROBE:-} ]]; then
  if [[ ! -x ${LANEWAY_INSTALLED_DISPATCH_TEST:-} || ! -x ${LANEWAY_DISPATCH_PROBE:-} ]]; then
    echo 'Set both LANEWAY_INSTALLED_DISPATCH_TEST and LANEWAY_DISPATCH_PROBE to executable lab binaries.' >&2
    exit 2
  fi
  dispatch_test=true
fi
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
control_link=/usr/local/sbin/laneway-control
[[ ! -e "$control_link" && ! -L "$control_link" ]]
controller_image=laneway-rust-controller:fresh-init-lab
relay_image=laneway-rust-relay:0.0.9100-lab
admin_image=laneway-go-admin:compose-cutover-lab
for image in "$controller_image" "$relay_image" "$admin_image"; do docker image inspect "$image" >/dev/null; done

work=$(mktemp -d /tmp/laneway-fresh-installer.XXXXXX)
project=laneway-install-${work##*.}
project=${project,,}
fixture_source=laneway-rust-update-$(openssl rand -hex 10)
package="$work/package"
destination="$work/deploy"
source_dir="$package/deploy/compose"
mkdir -p "$source_dir" "$package/bin" "$work/release" "$work/bin"
cp -R "$root/deploy/twingate-gateway" "$package/deploy/"
for file in compose.yaml compose.rust.yaml bootstrap.sh install-control-plane.sh laneway-control \
  preflight.sh prepare.sh prepare-control-plane.sh prepare-rust.py recovery.sh validate.sh verify-rust-release.sh README.md; do
  cp "$root/deploy/compose/$file" "$source_dir/"
done
compose() {
  docker compose --project-directory "$destination" --project-name "$project" --env-file "$destination/.env" \
    -f "$destination/compose.yaml" -f "$destination/compose.rust.yaml" "$@"
}
fixture_owned=false
admin_source=
cleanup() {
  local result=$?
  if [[ $(readlink "$control_link" 2>/dev/null) == "$destination/laneway-control" ]]; then
    unlink "$control_link"
  fi
  [[ -z "$admin_source" ]] || docker rm "$admin_source" >/dev/null 2>&1 || true
  if "$fixture_owned" && [[ -f "$destination/.env" ]]; then
    if (( result != 0 )); then compose logs --no-color --tail=25 controller relay >&2 || true; fi
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    while IFS= read -r volume; do
      [[ -z $volume ]] || /usr/bin/docker volume rm "$volume" >/dev/null 2>&1 || true
    done < <(/usr/bin/docker volume ls -q --filter "label=com.docker.compose.project=$project")
  fi
  find "$work" -depth -delete
}
trap cleanup EXIT
for role in controller-state relay-public-certs exit-node-state; do
  if docker volume inspect "$project-$role" >/dev/null 2>&1; then exit 2; fi
done
if docker volume inspect "$fixture_source" >/dev/null 2>&1; then exit 2; fi
test -z "$(docker ps -aq --filter "label=com.docker.compose.project=$project")"
fixture_owned=true

sed -i -e "s/name: laneway-/name: $project-/" \
  -e "s|^    image: ghcr.io/doout/laneway-admin:.*|    image: $admin_image|" \
  -e '/^    driver: bridge$/a\    internal: true' "$source_dir/compose.yaml"
sed -i -e "s|^    image: ghcr.io/doout/laneway-controller-rust:.*|    image: $controller_image|" \
  -e "s|^    image: ghcr.io/doout/laneway-relay-rust:.*|    image: $relay_image|" \
  -e "s|^        source: .*LANEWAY_GATEWAY_SPOOL.*|        source: $work/gateway-spool|" \
  -e "s|:-laneway-controller-state}|:-$fixture_source}|" "$source_dir/compose.rust.yaml"

# Stage only the operator CLI and Compose files via the real archive installer.
admin_source=$(docker create --network none "$admin_image")
docker cp "$admin_source:/usr/local/bin/laneway" "$package/bin/laneway"
docker rm "$admin_source" >/dev/null
admin_source=
printf '%s\n' 0.0.9104 > "$package/VERSION"
cp "$root/scripts/install-package.sh" "$package/install.sh"
DESTDIR="$work/staged" sh "$package/install.sh" --control-tools
tool_dir="$work/staged/usr/local"
worker_dir="$tool_dir/share/laneway/deploy/twingate-gateway"
diff -r "$package/deploy/twingate-gateway" "$worker_dir"
# Exercise packaged initialization without installing a machine-wide bridge service on the lab host.
mkdir -p "$work/gateway-spool"
cat > "$worker_dir/install.sh" <<'EOF'
#!/bin/sh
set -eu
command -v "$LANEWAY_COSIGN_BIN" >/dev/null
touch "$LANEWAY_INSTALLER_FIXTURE/worker-invoked"
EOF
test ! -e "$tool_dir/sbin"
test ! -e "$tool_dir/lib/systemd"
export PATH="$work/bin:$tool_dir/bin:$PATH"
export LANEWAY_INSTALLER_FIXTURE="$work"
export LANEWAY_COMMAND="$tool_dir/bin/laneway"

for repository in laneway-admin laneway-controller-rust laneway-relay-rust laneway-exit-node-rust lane-edge-rust; do
  printf 'ghcr.io/doout/%s@sha256:%064d\n' "$repository" 1
done > "$work/release/image-digests.txt"
for platform in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
  printf '[[bootstrap.artifacts]]\nos = "%s"\narch = "%s"\nurl = "https://github.com/Doout/laneway/releases/download/v0.0.9104/laneway_%s.tar.gz"\nsha256 = "%064d"\nsize_bytes = 123\n' \
    "${platform%_*}" "${platform#*_}" "$platform" 1
done > "$work/release/bootstrap-artifacts.toml"
(cd "$work/release" && sha256sum image-digests.txt bootstrap-artifacts.toml > checksums.txt)
printf '%s\n' installer-fixture > "$work/release/checksums.sigstore.json"
cat > "$work/bin/curl" <<'EOF'
#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
  case "$1" in
    https://release.invalid/v0.0.91[0-9][0-9]/*) asset=${1##*/}; tag=${1%/*}; tag=${tag##*/}; shift ;;
    -o) output=$2; shift 2 ;;
    *) shift ;;
  esac
done
directory=$LANEWAY_INSTALLER_FIXTURE/release
[ "$tag" = v0.0.9104 ] || directory=$LANEWAY_INSTALLER_FIXTURE/release-$tag
cp "$directory/$asset" "$output"
EOF
cat > "$work/bin/cosign" <<'EOF'
#!/bin/sh
set -eu
case "$1" in
  verify-blob) identity=$5; test "$(cat "$3")" = installer-fixture ;;
  verify) identity=$3 ;;
  *) exit 1 ;;
esac
tag=${identity##*/}
test "$identity" = "https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/$tag"
directory=$LANEWAY_INSTALLER_FIXTURE/release
[ "$tag" = v0.0.9104 ] || directory=$LANEWAY_INSTALLER_FIXTURE/release-$tag
[ "$1" = verify-blob ] || grep -Fxq "$6" "$directory/image-digests.txt"
EOF
cat > "$work/bin/getent" <<'EOF'
#!/bin/sh
if [ "$1:$2" = ahosts:installer.fresh.test ]; then
  printf '%s\n' '127.0.0.1 STREAM installer.fresh.test'
else
  exec /usr/bin/getent "$@"
fi
EOF
chmod 0700 "$work/bin/"*
export COMPOSE_PROJECT_NAME="$project"
env LANEWAY_NONINTERACTIVE=true LANEWAY_CONFIRM=deploy LANEWAY_PRODUCTION_MODE=true \
  LANEWAY_DOMAIN=installer.fresh.test LANEWAY_BIND_ADDRESS=127.0.0.1 LANEWAY_DEPLOY_DIR="$destination" \
  LANEWAY_INSTALLER_ANSWERS_FILE="$work/installer/answers" LANEWAY_RECOVERY_KIT_DIR="$work/recovery-kit" \
  LANEWAY_RELEASE_BASE_URL=https://release.invalid/v0.0.9104 \
  sh "$tool_dir/share/laneway/deploy/compose/install-control-plane.sh"

[[ $(readlink "$control_link") == "$destination/laneway-control" ]]
grep -Fxq LANEWAY_CONTROL_RUNTIME=rust "$destination/.env"
if grep -q '^LANEWAY_GATEWAY_SPOOL=' "$destination/.env"; then
  test -f "$work/worker-invoked"
fi
test "$(compose exec -T controller /usr/local/bin/laneway-controller --version)" = 0.0.9104
test "$(compose exec -T relay /usr/local/bin/laneway-relay --version)" = 0.0.9100
test "$(docker ps --filter "label=com.docker.compose.project=$project" --format '{{.Image}}' | LC_ALL=C sort)" = \
  "$(printf '%s\n' "$controller_image" "$relay_image" | LC_ALL=C sort)"
controller_pid=$(docker inspect --format '{{.State.Pid}}' "$(compose ps -q controller)")
nsenter -t "$controller_pid" -n "$control_link" status > "$work/status"
grep -Fxq controller=healthy "$work/status"
grep -Fxq relay=healthy "$work/status"
# The network namespace keeps the private API available without sharing ports.
nsenter -t "$controller_pid" -n "$control_link" invite --name fixture-exit --shared-host-exit \
  > "$work/invitation" 2> "$work/instructions"
grep -Fq -- '--runtime rust' "$work/instructions"
nsenter -t "$controller_pid" -n "$control_link" invite --name fixture-connector --docker --connector > "$work/connector"
bundle_id=$(sed -n "s|.*\\.well-known/laneway/bootstrap/\\([A-Za-z0-9_-]\\{43\\}\\)'.*|\\1|p" "$work/connector")
[[ $bundle_id =~ ^[A-Za-z0-9_-]{43}$ ]]
controller_port=$(sed -n 's/^LANEWAY_CONTROLLER_PORT=//p' "$destination/.env")
nsenter -t "$controller_pid" -n /usr/bin/curl --fail --silent --show-error \
  --resolve "installer.fresh.test:$controller_port:127.0.0.1" \
  --cacert "$destination/generated/pki/ca.crt" \
  --cert "$destination/generated/pki/relay.crt" --key "$destination/generated/pki/relay.key" \
  "https://installer.fresh.test:$controller_port/v1/bootstrap-bundles/$bundle_id" > "$work/connector-bootstrap.sh"
bash -n "$work/connector-bootstrap.sh"
grep -Fq "ghcr.io/doout/lane-edge-rust:0.0.9104@sha256:$(printf '%064d' 1)" "$work/connector-bootstrap.sh"
grep -Fq 'connector bootstrap-activate' "$work/connector-bootstrap.sh"
if grep -Eq 'SETUP_TOKEN|--health-cmd' "$work/connector-bootstrap.sh"; then
  echo 'Rust Connector bootstrap added an enrollment secret or a shell health check' >&2
  exit 1
fi
test ! -e "$work/recovery-kit/control-plane-input"
bundle=$(find "$work/recovery-kit" -maxdepth 1 -name 'initial-recovery-*.age' -type f)
test -s "$bundle"
age --decrypt -i "$work/recovery-kit/laneway-recovery.identity" "$bundle" |
  tar -xOf - FORMAT | grep -Fxq 'LANEWAY_RECOVERY_VERSION=2'
echo 'PASS: the default installer staged only host tools, started Rust, and produced an encrypted initial recovery bundle.'

# Orchestration uses real local containers, Compose, named volumes, and
# SQLite/age. Translate fixture image references only: no registry or signing
# infrastructure is needed. A deliberately broken controller triggers recovery.
for tag in v0.0.9105 v0.0.9106; do
  release="$work/release-$tag"
  mkdir "$release"
  cp "$work/release/"{checksums.sigstore.json,image-digests.txt} "$release/"
  sed "s/v0.0.9104/$tag/g" "$work/release/bootstrap-artifacts.toml" > "$release/bootstrap-artifacts.toml"
  (cd "$release" && sha256sum image-digests.txt bootstrap-artifacts.toml > checksums.txt)
done
docker_fixture=$(docker volume inspect --format '{{.Mountpoint}}' "$fixture_source")
# Use the VM's actual loopback port for the authenticated health check. The
# original install ran isolated from external networks; no public DNS or ACME
# verification is part of this fixture.
compose down
sed -i '/^    internal: true$/d' "$destination/compose.yaml"
# Use a temporary local certificate, not ACME, to check the relay's HTTPS
# connection through a controller restart.
openssl req -quiet -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -subj /CN=installer.fresh.test -addext subjectAltName=DNS:installer.fresh.test \
  -keyout "$destination/generated/pki/public.key" -out "$destination/generated/pki/public.crt"
chown 65532:65532 "$destination/generated/pki/public.key"
chmod 0400 "$destination/generated/pki/public.key"
sed -i '/^cache_dir = "\/var\/lib\/laneway-public"$/d' "$destination/generated/config/relay.rust.toml"
printf '\ncertificate = "/run/laneway-secrets/public.crt"\nprivate_key = "/run/laneway-secrets/public.key"\n' \
  >> "$destination/generated/config/relay.rust.toml"
sed -i '/^  relay:$/,/^  exit-node:$/ { /    volumes:$/a\      - ./generated/pki/public.crt:/run/laneway-secrets/public.crt:ro\n      - ./generated/pki/public.key:/run/laneway-secrets/public.key:ro
}' "$destination/compose.rust.yaml"
compose up --detach --wait controller relay
if [[ $dispatch_test == true ]]; then
  LANEWAY_INSTALLED_DISPATCH_DEPLOY="$destination" "$LANEWAY_INSTALLED_DISPATCH_TEST" \
    -test.run '^TestRustInstalledDispatch$' -test.v -test.timeout 90s
fi

export LANEWAY_UPDATE_TEST_PROJECT="$project" LANEWAY_UPDATE_TEST_DEPLOY="$destination"
cat > "$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
envfile=$LANEWAY_UPDATE_TEST_DEPLOY/.env
action=
for ((i=1; i<=$#; i++)); do
  arg=${!i}
  case "$arg" in
    --env-file) next=$((i+1)); envfile=${!next} ;;
    config|pull|up) [[ $1 != compose ]] || action=$arg ;;
  esac
done
version=$(sed -n 's/^LANEWAY_RUST_VERSION=//p' "$envfile")
digest="sha256:$(printf '%064d' 1)"
if [[ $1 == compose && $action == config && " $* " == *' --profile tools '* && " $* " == *' --format json '* ]]; then
  /usr/bin/docker "$@" | jq --arg v "$version" --arg d "$digest" --arg bad "${LANEWAY_ROTATION_TEST_WRONG_PLAN:-}" '
    .services.controller.image = ("ghcr.io/doout/laneway-controller-rust:" + $v + "@" + $d) |
    .services.relay.image = ("ghcr.io/doout/laneway-relay-rust:" + $v + "@" + $d) |
    .services["exit-node"].image = ("ghcr.io/doout/laneway-exit-node-rust:" + $v + "@" + $d) |
    .services.admin.image = ("ghcr.io/doout/laneway-admin:" + $v + "@" + $d) |
    if $bad == "1" then .services.controller.image = "unexpected-image" else . end'
elif [[ $1 == compose && $action == pull ]]; then
  /usr/bin/docker image inspect laneway-rust-controller:fresh-init-lab laneway-rust-relay:0.0.9100-lab \
    laneway-go-admin:compose-cutover-lab >/dev/null
elif [[ $1 == compose && $action == up && $version == 0.0.9106 ]]; then
  # Use real Compose but inject an incompatible controller start command.
  broken="$LANEWAY_UPDATE_TEST_DEPLOY/.broken-controller.yaml"
  printf 'services:\n  controller:\n    command: [incompatible-test-command]\n' > "$broken"
  args=()
  for arg; do
    if [[ $arg == up ]]; then args+=(-f "$broken"); fi
    args+=("$arg")
  done
  exec /usr/bin/docker "${args[@]}"
elif [[ $1 == inspect && ${2:-} == --type && ${3:-} == container ]]; then
  /usr/bin/docker "$@" | jq --arg v "$version" --arg d "$digest" --arg project "$LANEWAY_UPDATE_TEST_PROJECT" '
    map(if .Config.Labels["com.docker.compose.project"] == $project and
      (.Config.Image == "laneway-rust-controller:fresh-init-lab" or .Config.Image == "laneway-rust-relay:0.0.9100-lab")
      then .Config.Image = ("ghcr.io/doout/laneway-" + .Config.Labels["com.docker.compose.service"] + "-rust:" + $v + "@" + $d)
      else . end)'
else
  exec /usr/bin/docker "$@"
fi
EOF
chmod 0700 "$work/bin/docker"
/usr/bin/docker compose --project-directory "$destination" --env-file "$destination/.env" \
  -f "$destination/compose.yaml" -f "$destination/compose.rust.yaml" config --quiet
count_invitations() {
  python3 -c 'import sqlite3, sys; print(sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True).execute("SELECT count(*) FROM enrollment_tokens").fetchone()[0])' "$1/controller.db"
}
invitations=$(count_invitations "$docker_fixture")
(( invitations > 0 ))
LANEWAY_RELEASE_BASE_URL=https://release.invalid/v0.0.9105 "$control_link" update v0.0.9105
active_volume=$(compose config --format json | jq -er '.volumes["controller-state"].name')
[[ $active_volume != "$fixture_source" && $active_volume == laneway-rust-update-* ]]
active_database=$(docker volume inspect --format '{{.Mountpoint}}' "$active_volume")
test "$(count_invitations "$active_database")" = "$invitations"
grep -Fxq LANEWAY_RUST_VERSION=0.0.9105 "$destination/.env"
grep -Fq /v0.0.9105/ "$destination/generated/config/bootstrap.rust.json"
test -s "$docker_fixture/controller.db"
bundle=$(find "$destination/generated/recovery" -maxdepth 1 -name 'pre-rust-update-*.age' -type f)
age --decrypt -i "$work/recovery-kit/laneway-recovery.identity" "$bundle" |
  tar -xOf - FORMAT | grep -Fxq 'LANEWAY_RECOVERY_VERSION=2'
if LANEWAY_RELEASE_BASE_URL=https://release.invalid/v0.0.9106 "$control_link" update v0.0.9106 > "$work/failure" 2>&1; then
  echo 'broken fixture was not rejected' >&2
  exit 1
fi
grep -F 'the previous Rust release and its original controller state are back online' "$work/failure"
test "$(compose config --format json | jq -er '.volumes["controller-state"].name')" = "$active_volume"
test "$(count_invitations "$active_database")" = "$invitations"
grep -Fxq LANEWAY_RUST_VERSION=0.0.9105 "$destination/.env"
grep -Fq /v0.0.9105/ "$destination/generated/config/bootstrap.rust.json"
"$control_link" status > "$work/restored-status"
grep -Fxq controller=healthy "$work/restored-status"
"$control_link" update v0.0.9105 | grep -Fq 'already current'
if "$control_link" update v0.0.9104 > "$work/downgrade" 2>&1; then exit 1; fi
grep -Fq 'would downgrade' "$work/downgrade"
echo 'PASS: signed-release fixture updated the real Rust services, preserved state, and recovered from a broken candidate.'

export LANEWAY_ROTATION_TEST_CLI="$LANEWAY_COMMAND"
cat > "$work/bin/rotation-operator" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${LANEWAY_ROTATION_TEST_FAILURE:-}: $* " in
  new-auth:*' root-token authentication-check --expect accepted '*'/new.token ') exit 1 ;;
  complete:*' root-token rotation-complete '*) exit 1 ;;
esac
exec "$LANEWAY_ROTATION_TEST_CLI" "$@"
EOF
bash -n "$work/bin/rotation-operator"
chmod 0700 "$work/bin/rotation-operator"
rotation_dir=$destination/generated/lifecycle/administrator-root-token-rotation
root_credential=$destination/generated/secrets/admin.token
install -m 0600 "$root_credential" "$work/previous.token"
previous_controller=$(compose ps -q controller)
previous_relay=$(compose ps -q relay)
network_id=$(sed -n 's/^LANEWAY_NETWORK_ID=//p' "$destination/.env")
controller_id=$(sed -n 's/^LANEWAY_CONTROLLER_SERVICE_ID=//p' "$destination/.env")
relay_port=$(sed -n 's/^LANEWAY_RELAY_TCP_PORT=//p' "$destination/.env")
verify_root() {
  "$LANEWAY_ROTATION_TEST_CLI" controller administrator root-token authentication-check \
    --expect "$1" --admin-token-file "$2" --controller "https://127.0.0.1:$controller_port" \
    --ca "$destination/generated/pki/ca.crt" --server-name installer.fresh.test \
    --controller-network-id "$network_id" --controller-service-id "$controller_id"
}
verify_relay() {
  /usr/bin/curl --noproxy '*' --fail --silent --show-error --max-time 5 \
    --resolve "installer.fresh.test:$relay_port:127.0.0.1" --cacert "$destination/generated/pki/public.crt" \
    "https://installer.fresh.test:$relay_port/.well-known/laneway/bootstrap.json" |
    jq -e --arg network "$network_id" --arg controller "$controller_id" \
      '.network_id == $network and .controller.service_id == $controller' >/dev/null
}
verify_root accepted "$work/previous.token"
verify_relay
if LANEWAY_ROTATION_TEST_WRONG_PLAN=1 "$control_link" administrator root-token rotate >"$work/rotation-invalid" 2>&1; then
  echo 'rotation accepted an unpinned Compose controller' >&2
  exit 1
fi
grep -Fq 'rotation requires the installed, pinned Rust controller' "$work/rotation-invalid"
cmp -s "$work/previous.token" "$root_credential"
test ! -e "$rotation_dir"
test "$(compose ps -q controller)" = "$previous_controller"

if ! "$control_link" administrator root-token rotate >"$work/rotation-success" 2>&1; then
  grep -E '^(laneway-control:|Error:) ' "$work/rotation-success" >&2 || true
  echo 'initial Rust root-token rotation did not complete' >&2
  exit 1
fi
grep -Fq 'Administrator root token rotated' "$work/rotation-success"
if cmp -s "$work/previous.token" "$root_credential"; then
  echo 'rotation did not replace the root credential' >&2
  exit 1
fi
test "$(compose ps -q controller)" != "$previous_controller"
test "$(compose ps -q relay)" = "$previous_relay"
verify_root rejected "$work/previous.token"
verify_root accepted "$root_credential"
verify_relay
test ! -e "$rotation_dir"
install -m 0600 "$root_credential" "$work/current.token"

if LANEWAY_COMMAND="$work/bin/rotation-operator" LANEWAY_ROTATION_TEST_FAILURE=new-auth \
  "$control_link" administrator root-token rotate >"$work/rotation-rolled-back" 2>&1; then
  echo 'rotation accepted without proving the replacement credential' >&2
  exit 1
fi
grep -Fq 'the prior credential was restored and verified' "$work/rotation-rolled-back"
cmp -s "$work/current.token" "$root_credential"
verify_root accepted "$root_credential"
verify_relay
test ! -e "$rotation_dir"

if LANEWAY_COMMAND="$work/bin/rotation-operator" LANEWAY_ROTATION_TEST_FAILURE=complete \
  "$control_link" administrator root-token rotate >"$work/rotation-pending" 2>&1; then
  echo 'rotation reported success while completion was unconfirmed' >&2
  exit 1
fi
grep -Fxq 'phase=committed_pending_complete' "$rotation_dir/state"
verify_root rejected "$work/current.token"
verify_root accepted "$root_credential"
install -m 0600 "$root_credential" "$work/committed.token"
"$control_link" administrator root-token rotate >"$work/rotation-resumed" 2>&1
grep -Fq 'Administrator root token rotated' "$work/rotation-resumed"
cmp -s "$work/committed.token" "$root_credential"
verify_relay
test "$(compose ps -q relay)" = "$previous_relay"
test "$(count_invitations "$active_database")" = "$invitations"
test ! -e "$rotation_dir"
python3 - "$active_database/controller.db" <<'PY'
import sqlite3
import sys

db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
markers = db.execute("SELECT count(*), count(completed_at) FROM administrator_root_token_rotations").fetchone()
assert markers == (3, 2), markers
events = dict(db.execute("SELECT action, count(*) FROM audit_events WHERE action LIKE 'administrator.root_token.rotate.%' GROUP BY action"))
assert events == {"administrator.root_token.rotate.begin": 3, "administrator.root_token.rotate.complete": 2}, events
PY
for secret in "$work/previous.token" "$work/current.token" "$work/committed.token"; do
  if grep -Fqf "$secret" "$work/rotation-"*; then
    echo 'rotation logged protected credential material' >&2
    exit 1
  fi
done
echo 'PASS: the Rust controller rotated its root token, rolled back a failed proof, and resumed a committed rotation without replacing the relay.'
