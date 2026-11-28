#!/usr/bin/env bash
# Run the Rust transaction against a disposable Docker network and state volume.
set -euo pipefail
if [[ $# != 2 ]]; then
  printf 'usage: bash %s LOCAL_RUST_CONNECTOR_IMAGE LOCAL_DOCKER_SOCKET\n' "$0" >&2
  exit 2
fi
root="$(cd "$(dirname "$0")/../.." && pwd)"
socket=$2
[[ "$socket" = /*/docker.sock ]] || { echo "expected an absolute local VM Docker socket path" >&2; exit 2; }
socket_gid=$(stat -c '%g' "$socket")
suffix="$(date +%s)-$$"
name="laneway-connector-update-lab-$suffix"
volume="$name-state"
image="ghcr.io/doout/laneway/edge:managed-lab-$suffix"
lab_image=${LANEWAY_RUST_LAB_IMAGE:-laneway-rust-lab:local}
fixture=""
binaries=""
fixture_images=()
cleanup() {
  docker rm --force "$name" "$name-laneway-update-previous" >/dev/null 2>&1 || true
  if [[ -n "$fixture" ]]; then docker rm --force "$fixture" >/dev/null 2>&1 || true; fi
  docker volume rm "$volume" >/dev/null 2>&1 || true
  docker image rm "$image" >/dev/null 2>&1 || true
  for container in "${fixture_images[@]}"; do docker rm "$container" >/dev/null 2>&1 || true; done
  if [[ -n "$binaries" ]]; then find "$binaries" -depth -delete; fi
}
# Guard against cleaning up anything we didn't create.
for existing in "$name" "$name-laneway-update-previous"; do
  if docker container inspect "$existing" >/dev/null 2>&1; then exit 2; fi
done
if docker volume inspect "$volume" >/dev/null 2>&1; then exit 2; fi
if docker image inspect "$image" >/dev/null 2>&1; then exit 2; fi
trap cleanup EXIT
docker tag "$1" "$image"
docker volume create --label laneway.test=managed-connector "$volume" >/dev/null
binaries=$(mktemp -d)
if [[ -n ${LANEWAY_CONNECTOR_FIXTURE_BINARIES:-} ]]; then
  for role in controller relay; do
    install -m 0755 "$LANEWAY_CONNECTOR_FIXTURE_BINARIES/laneway-$role-rs" "$binaries/$role"
  done
else
  for role in controller relay; do
    fixture_image="laneway-connector-fixture-$role:local"
    docker image inspect "$fixture_image" >/dev/null 2>&1 || {
      echo 'Run integration/rust-lab/connector-cutover.sh --prime-cache first.' >&2
      exit 1
    }
    container=$(docker create "$fixture_image" /unused)
    fixture_images+=("$container")
    docker cp "$container:/laneway-$role-rs" "$binaries/$role"
  done
fi
container=$(docker create "$image")
fixture_images+=("$container")
docker cp "$container:/usr/local/bin/lanewayd-rs" "$binaries/laneway"
docker run --rm --cap-drop ALL -v "$root:/src:ro" \
  -v laneway-rust-lab-cache:/usr/local/cargo/registry "$lab_image" \
  cargo fetch --locked --manifest-path rust/Cargo.toml
fixture="$(docker run -d --network none --tmpfs /tmp:exec,size=1g \
  -v "$root:/src:ro" -v "$volume:/state" -v "$binaries:/fixture:ro" \
  "$lab_image" bash /src/integration/rust-lab/connector-cutover.sh --fixture relay-quic)"
for _ in {1..90}; do
  docker logs "$fixture" 2>&1 | grep -q 'connector fixture ready' && break
  [[ "$(docker inspect -f '{{.State.Running}}' "$fixture")" = true ]] || { docker logs "$fixture" >&2; exit 1; }
  sleep 1
done
docker logs "$fixture" 2>&1 | grep -q 'connector fixture ready'
docker run -d --name "$name" --pull never --network "container:$fixture" \
  --restart unless-stopped --user 65532:65532 --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=65532,gid=65532 \
  --tmpfs /run/laneway:rw,noexec,nosuid,nodev,size=4m,mode=0700,uid=65532,gid=65532 \
  --health-interval 1s --health-start-period 1s \
  -e SETUP_TOKEN_FILE=/var/lib/laneway/setup.token -v "$volume:/var/lib/laneway" "$image" >/dev/null
for _ in {1..30}; do
  [[ "$(docker inspect -f '{{.State.Health.Status}}' "$name")" = healthy ]] && break
  sleep 1
done
[[ "$(docker inspect -f '{{.State.Health.Status}}' "$name")" = healthy ]] || { docker logs "$name" >&2; exit 1; }
docker exec "$fixture" rm -- /state/setup.token
identity_bytes() {
  docker exec "$fixture" sh -ec 'cd /state/connector; sha256sum ca.crt node.crt node.key wireguard.key connector.toml'
}
before="$(identity_bytes)"
docker run --rm --network none --cap-drop ALL --tmpfs /tmp:exec,size=1g \
  --group-add "$socket_gid" \
  --mount "type=bind,src=$socket,dst=/var/run/docker.sock,readonly" \
  --mount type=bind,src=/usr/bin/docker,dst=/usr/bin/docker,readonly \
  -v "$root:/src:ro" -v laneway-rust-lab-target:/src/rust/target \
  -v laneway-rust-lab-cache:/usr/local/cargo/registry \
  -e CARGO_INCREMENTAL=0 -e CARGO_PROFILE_DEV_DEBUG=0 \
  -e LANEWAY_MANAGED_CONNECTOR_LAB_NAME="$name" -e LANEWAY_MANAGED_CONNECTOR_LAB_IMAGE="$image" \
  -w /src "$lab_image" \
  cargo test --offline --locked --manifest-path rust/Cargo.toml -p lanewayd-rs --lib \
    live_named_volume_update_and_rollback -- --ignored --nocapture
[[ "$(identity_bytes)" = "$before" ]]
echo 'Managed Connector replaced and rolled back with unchanged identity files.'
