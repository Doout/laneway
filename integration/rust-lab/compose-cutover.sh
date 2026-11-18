#!/usr/bin/env bash
# Rehearse an in-place replacement and rollback on a disposable Docker VM.
set -euo pipefail
marker=/run/.laneway-isolated-compose-lab
if [[ $(id -u) != 0 || ! -f "$marker" || -L "$marker" ||
      $(stat -c '%u:%a' "$marker") != 0:600 || -n ${DOCKER_HOST:-} || -n ${DOCKER_CONTEXT:-} ]]; then
  echo "Run only as root on a marked disposable Docker VM using its local socket." >&2
  exit 2
fi
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
for image in laneway-go-{controller,relay,admin}:compose-cutover-lab \
    laneway-rust-controller:compose-cutover-lab laneway-rust-{relay,exit}:0.0.9100-lab; do
  docker image inspect "$image" >/dev/null
done
work=$(mktemp -d /tmp/laneway-compose-cutover.XXXXXX)
project=laneway-cutover-${work##*.}
project=${project,,}
base="$work/deploy"
mkdir -p "$base" "$work/bin" "$work/issuer"
for file in compose.yaml compose.rust.yaml prepare.sh prepare-rust.py verify-rust-release.sh laneway-control; do
  cp "$root/deploy/compose/$file" "$base/"
done
export LANEWAY_LAB_FIXTURE_DIR="$work"
cat > "$work/bin/laneway" <<'EOF'
#!/bin/sh
exec docker run --rm --pull never --network none --user 0:0 \
  -v "$LANEWAY_LAB_FIXTURE_DIR:$LANEWAY_LAB_FIXTURE_DIR" -w "$PWD" \
  laneway-go-admin:compose-cutover-lab "$@"
EOF
chmod 0700 "$work/bin/laneway"
export PATH="$work/bin:$PATH"
cd "$base"

cat > lab.yaml <<EOF
services:
  controller:
    image: laneway-go-controller:compose-cutover-lab
    restart: "no"
  relay:
    image: laneway-go-relay:compose-cutover-lab
    restart: "no"
  admin:
    image: laneway-go-admin:compose-cutover-lab
networks:
  control:
    internal: true
volumes:
  controller-state:
    name: ${project}-controller
  relay-public-certs:
    name: ${project}-relay-public
  exit-node-state:
    name: ${project}-exit
EOF
cat > rust-lab.yaml <<'EOF'
services:
  controller:
    image: laneway-rust-controller:compose-cutover-lab
  relay:
    image: laneway-rust-relay:0.0.9100-lab
    volumes:
      - ./generated/pki/public.crt:/run/laneway-secrets/public.crt:ro
      - ./generated/pki/public.key:/run/laneway-secrets/public.key:ro
  exit-node:
    image: laneway-rust-exit:0.0.9100-lab
EOF
name=laneway-compose.test
network=71000000000000000000000000000011
controller=71000000000000000000000000000012
relay=71000000000000000000000000000013
added=71000000000000000000000000000014
digest=sha256:$(printf '1%.0s' {1..64})
cat > .env <<EOF
LANEWAY_VERSION=0.0.9100
LANEWAY_RUST_VERSION=0.0.9100
LANEWAY_CONTROLLER_IMAGE_DIGEST=$digest
LANEWAY_RELAY_IMAGE_DIGEST=$digest
LANEWAY_ADMIN_IMAGE_DIGEST=$digest
LANEWAY_EXIT_NODE_IMAGE_DIGEST=$digest
LANEWAY_RUST_CONTROLLER_IMAGE_DIGEST=$digest
LANEWAY_RUST_RELAY_IMAGE_DIGEST=$digest
LANEWAY_RUST_EXIT_NODE_IMAGE_DIGEST=$digest
LANEWAY_BIND_ADDRESS=127.0.0.1
LANEWAY_CONTROLLER_PORT=8443
LANEWAY_RELAY_TCP_PORT=18443
LANEWAY_RELAY_QUIC_PORT=0
LANEWAY_CONTROLLER_SERVER_NAME=$name
LANEWAY_NETWORK_ID=$network
LANEWAY_CONTROLLER_SERVICE_ID=$controller
LANEWAY_RELAY_SERVICE_ID=$relay
LANEWAY_RELAY_PUBLIC_ENDPOINT=$name:4433
EOF
base_compose() {
  docker compose --project-name "$project" --env-file "$base/.env" -f compose.yaml -f lab.yaml "${exit_overlay[@]}" "$@"
}
rust_compose() {
  docker compose --project-name "$project" --env-file "$base/.env" \
    -f compose.yaml -f lab.yaml "${exit_overlay[@]}" -f compose.rust.yaml -f rust-lab.yaml "$@"
}
exit_overlay=()
cleanup() {
  result=$?
  if [[ -n ${recovery_project_dir:-} ]]; then
    docker compose --project-directory "$recovery_project_dir" --project-name "$recovery_project_name" \
      --env-file "$base/.env" -f "$recovery_project_dir/compose.yaml" \
      down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  if (( result != 0 )); then
    rust_compose logs --no-color --tail=30 controller relay >&2 || true
  fi
  if (( ${#exit_overlay[@]} )); then clean_compose_exit "$result"; fi
  base_compose --profile exit-node down --volumes --remove-orphans >/dev/null 2>&1 || true
  if [[ ${LANEWAY_KEEP_INTEGRATION_WORK:-0} == 1 ]]; then
    echo "Compose fixture retained in $work" >&2
  else
    find "$work" -depth -delete
  fi
}
trap cleanup EXIT
if [[ ${LANEWAY_TEST_COMPOSE_EXIT:-0} == 1 ]]; then
  source "$root/integration/rust-lab/compose-exit.sh"
  prepare_compose_exit
fi

laneway pki init --out-dir "$work/offline" >/dev/null
laneway pki intermediate --ca-cert "$work/offline/ca.crt" --ca-key "$work/offline/ca.key" \
  --out-cert "$work/issuer/intermediate-chain.crt" --out-key "$work/issuer/intermediate.key" >/dev/null
cp "$work/offline/ca.crt" "$work/issuer/"
for platform in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
  printf '\n[[bootstrap.artifacts]]\nos = "%s"\narch = "%s"\nurl = "https://release.test/%s"\nsha256 = "%s"\nsize_bytes = 123\n' \
    "${platform%_*}" "${platform#*_}" "$platform" "${digest#sha256:}"
done > "$work/bootstrap-artifacts.toml"
LANEWAY_BOOTSTRAP_ARTIFACTS_FILE="$work/bootstrap-artifacts.toml" bash prepare.sh "$work/issuer"
# A fresh Go controller must declare the network during initialization. The
# Rust side will require the database to exist and will not reinitialize it.
printf '\n[controller.initial_network]\nnetwork_id = "%s"\nname = "baseline"\nipv4_pool = "100.115.18.0/24"\n' \
  "$network" >> generated/config/controller.toml
if (( ${#exit_overlay[@]} )); then
  # Publish fixture enrollments to the Go relay before packet assertions.
  sed -i 's/^poll_interval = "30s"$/poll_interval = "1s"/' generated/config/relay.toml
fi
# The isolated fixture exercises signed-release selection without contacting
# GHCR. Publishing verifies the same manifests with the real Cosign verifier.
source "$root/integration/rust-lab/compose-release.sh"
prepare_candidate_release
if prepare_verified_release >"$work/second-prepare.out" 2>&1; then
  echo "prepare replaced existing inputs" >&2
  exit 1
fi
openssl req -quiet -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -subj "/CN=$name" -addext "subjectAltName=DNS:$name" \
  -keyout generated/pki/public.key -out generated/pki/public.crt
chmod 0400 generated/pki/public.key
chown 65532:65532 generated/pki/public.key
chmod 0444 generated/pki/public.crt
# A fixture PEM keeps the test offline; production keeps its existing ACME cache.
sed -i '/^cache_dir = "\/var\/lib\/laneway-public"$/d' generated/config/relay.rust.toml
printf '\ncertificate = "/run/laneway-secrets/public.crt"\nprivate_key = "/run/laneway-secrets/public.key"\n' >> generated/config/relay.rust.toml

auth=(--controller https://controller:8443 --ca /run/laneway-secrets/ca.crt --server-name "$name"
  --controller-network-id "$network" --controller-service-id "$controller" --admin-token-file /run/laneway-secrets/admin.token)
admin() {
  base_compose --profile tools run --rm --no-deps --pull never -T admin controller "$@" "${auth[@]}"
}
assert_network() {
  admin network list --limit 100 | jq -e --arg id "$1" --arg name "$2" \
    'any(.networks[]; .network_id == $id and .name == $name)' >/dev/null
}

echo '==> seed a Go controller and relay'
base_compose up --pull never -d controller --wait --wait-timeout 30
relay_endpoint="$name:4433"
if (( ${#exit_overlay[@]} )); then relay_endpoint=relay:4433; fi
admin relay register --network-id "$network" --service-id "$relay" --name relay --endpoint "$relay_endpoint" >/dev/null
base_compose up --pull never -d relay --wait --wait-timeout 40
assert_network "$network" baseline
if (( ${#exit_overlay[@]} )); then
  enroll_compose_exit
  test_compose_exit base_compose go-baseline 27701
  base_compose --profile exit-node stop exit-node >/dev/null
fi
base_compose stop relay controller >/dev/null

echo '==> check that TCP and UDP network listeners are opt-in'
for address in 0.0.0.0:8443 127.0.0.1:8443; do
  args=()
  if [[ $address == 127.* ]]; then args=(--node-quic --quic-listen 0.0.0.0:8443); fi
  if rust_compose run --rm --no-deps --pull never -T controller serve \
    /var/lib/laneway-controller/controller.db "$address" /run/laneway-secrets/controller.crt \
    /run/laneway-secrets/controller.key "${args[@]}" >"$work/no-opt-in.out" 2>&1; then
    echo "non-loopback listener started without explicit permission" >&2
    exit 1
  fi
  grep -F 'non-loopback listeners require --listen-on-network' "$work/no-opt-in.out"
done
if rust_compose run --rm --no-deps --pull never -T controller serve \
  /var/lib/laneway-controller/controller.db 0.0.0.0:8443 /run/laneway-secrets/controller.crt \
  /run/laneway-secrets/controller.key --listen-on-network >"$work/no-ca.out" 2>&1; then
  echo "network listener started without a node issuer or client CA" >&2
  exit 1
fi
grep -F -- '--listen-on-network requires a node issuer and client CA' "$work/no-ca.out"

echo '==> serve the same volume with Rust'
rust_compose up --pull never -d controller relay --wait --wait-timeout 40
test "$(rust_compose exec -T controller /usr/local/bin/laneway-controller --version)" = 0.0.9100
assert_network "$network" baseline
admin network create --network-id "$added" --name added-in-rust --ipv4-pool 100.115.19.0/24 >/dev/null
assert_network "$added" added-in-rust
if env COMPOSE_PROJECT_NAME="$project" LANEWAY_COSIGN_BIN="$work/bin/compose-cosign" \
  sh ./laneway-control --rust readiness "$work/release" >"$work/wrong-running-image.out" 2>&1; then
  echo 'Rust readiness accepted an unsigned local runtime image' >&2
  exit 1
fi
grep -F 'controller: running container does not use the signed release image' "$work/wrong-running-image.out"
# An internal Docker bridge suppresses published ports. Reach the same
# HTTPS listener through the fixture's bridge address without enabling egress.
relay_address=$(docker inspect --format "{{(index .NetworkSettings.Networks \"${project}_control\").IPAddress}}" \
  "$(rust_compose ps -q relay)")
[[ "$relay_address" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
port=8443
public=(curl --noproxy '*' --fail --silent --show-error --max-time 5 --cacert generated/pki/public.crt
  --resolve "$name:$port:$relay_address")
"${public[@]}" "https://$name:$port/.well-known/laneway/bootstrap.json" |
  jq -e --arg id "$network" --arg controller "$controller" --slurpfile staged generated/config/bootstrap.rust.json '
    .network_id == $id and .controller.service_id == $controller and .artifacts == $staged[0].artifacts
  ' >/dev/null
"${public[@]}" "https://$name:$port/overview" | grep -Fq '<title>Laneway</title>'

if (( ${#exit_overlay[@]} )); then
  test_compose_exit rust_compose rust-cutover 27702
fi

if [[ ${LANEWAY_TEST_RUST_RECOVERY:-0} == 1 ]]; then
  source "$root/integration/rust-lab/compose-recovery.sh"
  check_compose_recovery
fi

echo '==> roll back to Go without a second database writer'
if (( ${#exit_overlay[@]} )); then rust_compose --profile exit-node stop exit-node >/dev/null; fi
rust_compose stop relay controller >/dev/null
base_compose up --pull never -d controller relay --wait --wait-timeout 40
test "$(base_compose exec -T controller /usr/local/bin/laneway -version)" = 0.0.9100
assert_network "$network" baseline
assert_network "$added" added-in-rust
if (( ${#exit_overlay[@]} )); then test_compose_exit base_compose go-rollback 27703; fi
echo 'PASS: Compose kept the existing data, Rust served public HTTPS discovery and console, and Go read the Rust write after rollback.'
