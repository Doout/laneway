#!/usr/bin/env bash
# Bring up the packaged Compose files from empty state on an isolated Docker VM.
set -euo pipefail
marker=/run/.laneway-isolated-compose-lab
if [[ $(id -u) != 0 || ! -f "$marker" || -L "$marker" ||
      $(stat -c '%u:%a' "$marker") != 0:600 || -n ${DOCKER_HOST:-} || -n ${DOCKER_CONTEXT:-} ]]; then
  echo 'Run only as root on a marked disposable Docker VM using its local socket.' >&2
  exit 2
fi
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
controller_image=${LANEWAY_TEST_FRESH_CONTROLLER_IMAGE:-laneway-rust-controller:fresh-init-lab}
relay_image=${LANEWAY_TEST_FRESH_RELAY_IMAGE:-laneway-rust-relay:0.0.9100-lab}
admin_image=laneway-go-admin:compose-cutover-lab
for image in "$controller_image" "$relay_image" "$admin_image"; do docker image inspect "$image" >/dev/null; done

work=$(mktemp -d /tmp/laneway-compose-fresh.XXXXXX)
project=laneway-fresh-${work##*.}
project=${project,,}
base="$work/deploy"
mkdir "$base" "$work/bin" "$work/issuer"
for file in compose.yaml compose.rust.yaml bootstrap.sh prepare.sh prepare-rust.py recovery.sh validate.sh; do
  cp "$root/deploy/compose/$file" "$base/"
done
cd "$base"
compose() {
  docker compose --project-name "$project" --env-file .env -f compose.yaml -f compose.rust.yaml "$@"
}
compose_owned=false
restore_base="$work/restore"
restore_project="$project-restore"
restore_owned=false
restore_compose() (
  cd "$restore_base"
  docker compose --project-name "$restore_project" --env-file .env -f compose.yaml -f compose.rust.yaml "$@"
)
cleanup() {
  local result=$?
  if "$restore_owned"; then restore_compose down --volumes --remove-orphans >/dev/null 2>&1 || true; fi
  if "$compose_owned"; then
    if (( result != 0 )); then compose logs --no-color --tail=25 controller relay >&2 || true; fi
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  find "$work" -depth -delete
}
trap cleanup EXIT
case "$controller_image:$relay_image" in *[!A-Za-z0-9_.:/@-]*) exit 2 ;; esac
sed -i -e "s/name: laneway-/name: $project-/" \
  -e "s|^    image: ghcr.io/doout/laneway-admin:.*|    image: $admin_image|" \
  -e '/^    driver: bridge$/a\    internal: true' compose.yaml
sed -i -e "s|^    image: ghcr.io/doout/laneway-controller-rust:.*|    image: $controller_image|" \
  -e "s|^    image: ghcr.io/doout/laneway-relay-rust:.*|    image: $relay_image|" compose.rust.yaml
for role in controller-state relay-public-certs exit-node-state; do
  if docker volume inspect "$project-$role" >/dev/null 2>&1; then exit 2; fi
done
test -z "$(docker ps -aq --filter "label=com.docker.compose.project=$project")"
compose_owned=true

export LANEWAY_LAB_FIXTURE_DIR="$work"
export LANEWAY_LAB_ADMIN_IMAGE="$admin_image"
cat > "$work/bin/laneway" <<'EOF'
#!/bin/sh
exec docker run --rm --pull never --network none --user 0:0 \
  -v "$LANEWAY_LAB_FIXTURE_DIR:$LANEWAY_LAB_FIXTURE_DIR" -w "$PWD" "$LANEWAY_LAB_ADMIN_IMAGE" "$@"
EOF
chmod 0700 "$work/bin/laneway"
export PATH="$work/bin:$PATH"
name=compose-fresh.test
network=71000000000000000000000000000201
controller=71000000000000000000000000000202
relay=71000000000000000000000000000203
digest=sha256:$(printf '1%.0s' {1..64})
age-keygen -o "$work/recovery.identity" 2>"$work/age.out"
recipient=$(age-keygen -y "$work/recovery.identity")
cat > .env <<EOF
LANEWAY_VERSION=0.0.9104
LANEWAY_RUST_VERSION=0.0.9104
LANEWAY_ADMIN_IMAGE_DIGEST=$digest
LANEWAY_RUST_CONTROLLER_IMAGE_DIGEST=$digest
LANEWAY_RUST_RELAY_IMAGE_DIGEST=$digest
LANEWAY_RUST_EXIT_NODE_IMAGE_DIGEST=$digest
LANEWAY_BIND_ADDRESS=127.0.0.1
LANEWAY_CONTROLLER_PORT=18444
LANEWAY_RELAY_TCP_PORT=18445
LANEWAY_RELAY_QUIC_PORT=18446
LANEWAY_CONTROLLER_SERVER_NAME=$name
LANEWAY_NETWORK_ID=$network
LANEWAY_CONTROLLER_SERVICE_ID=$controller
LANEWAY_RELAY_SERVICE_ID=$relay
LANEWAY_NETWORK_NAME=fresh
LANEWAY_IPV4_POOL=100.115.36.0/24
LANEWAY_RELAY_PUBLIC_ENDPOINT=$name:18446
LANEWAY_BACKUP_RECIPIENT=$recipient
EOF
laneway pki init --out-dir "$work/offline" >/dev/null
laneway pki intermediate --ca-cert "$work/offline/ca.crt" --ca-key "$work/offline/ca.key" \
  --out-cert "$work/issuer/intermediate-chain.crt" --out-key "$work/issuer/intermediate.key" >/dev/null
cp "$work/offline/ca.crt" "$work/issuer/"
for platform in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
  printf '\n[[bootstrap.artifacts]]\nos = "%s"\narch = "%s"\nurl = "https://release.test/%s"\nsha256 = "%s"\nsize_bytes = 123\n' \
    "${platform%_*}" "${platform#*_}" "$platform" "${digest#sha256:}"
done > "$work/bootstrap-artifacts.toml"
LANEWAY_BOOTSTRAP_ARTIFACTS_FILE="$work/bootstrap-artifacts.toml" ./prepare.sh "$work/issuer"
python3 prepare-rust.py --lab

openssl req -quiet -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -subj "/CN=$name" -addext "subjectAltName=DNS:$name" \
  -keyout generated/pki/public.key -out generated/pki/public.crt
chmod 0400 generated/pki/public.key
chown 65532:65532 generated/pki/public.key
sed -i '/^cache_dir = "\/var\/lib\/laneway-public"$/d' generated/config/relay.rust.toml
printf '\ncertificate = "/run/laneway-secrets/public.crt"\nprivate_key = "/run/laneway-secrets/public.key"\n' >> generated/config/relay.rust.toml
sed -i '/^  relay:$/,/^  exit-node:$/ { /    volumes:$/a\      - ./generated/pki/public.crt:/run/laneway-secrets/public.crt:ro\n      - ./generated/pki/public.key:/run/laneway-secrets/public.key:ro
}' compose.rust.yaml

env COMPOSE_PROJECT_NAME="$project" LANEWAY_RUST_VERSION=ignored ./bootstrap.sh --rust
test "$(compose exec -T controller /usr/local/bin/laneway-controller --version)" = 0.0.9104
test "$(compose exec -T controller /usr/local/bin/laneway-controller inventory networks /var/lib/laneway-controller/controller.db |
  jq -r '.networks[0].name')" = fresh
relay_address=$(docker inspect --format "{{(index .NetworkSettings.Networks \"${project}_control\").IPAddress}}" \
  "$(compose ps -q relay)")
[[ "$relay_address" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
public=(curl --noproxy '*' --fail --silent --show-error --max-time 5 --cacert generated/pki/public.crt
  --resolve "$name:8443:$relay_address")
"${public[@]}" "https://$name:8443/.well-known/laneway/bootstrap.json" |
  jq -e --arg network "$network" --arg controller "$controller" --arg relay "$relay" \
    '.network_id == $network and .controller.service_id == $controller and .relays[0].service_id == $relay' >/dev/null
"${public[@]}" "https://$name:8443/overview" | grep -F '<title>Laneway</title>' >/dev/null
if env COMPOSE_PROJECT_NAME="$project" ./bootstrap.sh --rust; then
  echo 'fresh bootstrap accepted an existing deployment' >&2
  exit 1
fi
env COMPOSE_PROJECT_NAME="$project" ./recovery.sh --rust backup fresh.age
mkdir "$restore_base"
for role in controller-state relay-public-certs exit-node-state; do
  if docker volume inspect "$restore_project-$role" >/dev/null 2>&1; then exit 2; fi
done
test -z "$(docker ps -aq --filter "label=com.docker.compose.project=$restore_project")"
sed "s/$project-/$restore_project-/g" compose.yaml >"$restore_base/compose.yaml"
cp compose.rust.yaml recovery.sh validate.sh "$restore_base/"
restore_owned=true
env COMPOSE_PROJECT_NAME="$restore_project" "$restore_base/recovery.sh" --rust restore \
  "$base/generated/recovery/fresh.age" "$work/recovery.identity"
restore_compose run --rm --no-deps controller inventory networks /var/lib/laneway-controller/controller.db |
  jq -e --arg network "$network" '.networks | length == 1 and .[0].network_id == $network' >/dev/null
echo 'PASS: empty state brought up the Rust controller and relay, served discovery and the console, and restored an encrypted backup.'
