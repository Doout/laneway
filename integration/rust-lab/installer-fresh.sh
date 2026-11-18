#!/usr/bin/env bash
# Run the actual packaged initializer with real Docker and recovery on a lab.
# Only release download/signature verification and public DNS are fixtures.
set -euo pipefail
marker=/run/.laneway-isolated-compose-lab
if [[ $(id -u) != 0 || ! -f "$marker" || -L "$marker" ||
      $(stat -c '%u:%a' "$marker") != 0:600 || -n ${DOCKER_HOST:-} || -n ${DOCKER_CONTEXT:-} ]]; then
  echo 'Run as root on a marked disposable Docker VM with a local Docker socket.' >&2
  exit 2
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
package="$work/package"
destination="$work/deploy"
source_dir="$package/deploy/compose"
mkdir -p "$source_dir" "$package/bin" "$work/release" "$work/bin"
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
  fi
  find "$work" -depth -delete
}
trap cleanup EXIT
for role in controller-state relay-public-certs exit-node-state; do
  if docker volume inspect "$project-$role" >/dev/null 2>&1; then exit 2; fi
done
test -z "$(docker ps -aq --filter "label=com.docker.compose.project=$project")"
fixture_owned=true

sed -i -e "s/name: laneway-/name: $project-/" \
  -e "s|^    image: ghcr.io/doout/laneway-admin:.*|    image: $admin_image|" \
  -e '/^    driver: bridge$/a\    internal: true' "$source_dir/compose.yaml"
sed -i -e "s|^    image: ghcr.io/doout/laneway-controller-rust:.*|    image: $controller_image|" \
  -e "s|^    image: ghcr.io/doout/laneway-relay-rust:.*|    image: $relay_image|" "$source_dir/compose.rust.yaml"

# Stage only the operator CLI and Compose files via the real archive installer.
admin_source=$(docker create --network none "$admin_image")
docker cp "$admin_source:/usr/local/bin/laneway" "$package/bin/laneway"
docker rm "$admin_source" >/dev/null
admin_source=
printf '%s\n' 0.0.9104 > "$package/VERSION"
cp "$root/scripts/install-package.sh" "$package/install.sh"
DESTDIR="$work/staged" sh "$package/install.sh" --control-tools
tool_dir="$work/staged/usr/local"
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
    https://release.invalid/v0.0.9104/*) asset=${1##*/}; shift ;;
    -o) output=$2; shift 2 ;;
    *) shift ;;
  esac
done
cp "$LANEWAY_INSTALLER_FIXTURE/release/$asset" "$output"
EOF
cat > "$work/bin/cosign" <<'EOF'
#!/bin/sh
set -eu
identity=https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/v0.0.9104
case "$1" in
  verify-blob) test "$5" = "$identity" && test "$(cat "$3")" = installer-fixture ;;
  verify) test "$3" = "$identity" && grep -Fxq "$6" "$LANEWAY_INSTALLER_FIXTURE/release/image-digests.txt" ;;
  *) exit 1 ;;
esac
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
