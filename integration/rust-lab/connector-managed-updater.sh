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
image="ghcr.io/doout/lane-edge-rust:managed-lab-$suffix"
lab_image=${LANEWAY_RUST_LAB_IMAGE:-laneway-rust-lab:connector}
fixture=""
cleanup() {
  docker rm --force "$name" "$name-laneway-update-previous" >/dev/null 2>&1 || true
  if [[ -n "$fixture" ]]; then docker rm --force "$fixture" >/dev/null 2>&1 || true; fi
  docker volume rm "$volume" "$name-unused" >/dev/null 2>&1 || true
  docker image rm "$image" >/dev/null 2>&1 || true
}
# Guard against cleaning up anything we didn't create.
for existing in "$name" "$name-laneway-update-previous"; do
  if docker container inspect "$existing" >/dev/null 2>&1; then exit 2; fi
done
for existing in "$volume" "$name-unused"; do
  if docker volume inspect "$existing" >/dev/null 2>&1; then exit 2; fi
done
if docker image inspect "$image" >/dev/null 2>&1; then exit 2; fi
trap cleanup EXIT
docker tag "$1" "$image"
docker volume create --label laneway.test=managed-connector "$volume" >/dev/null
docker volume create --label laneway.test=managed-connector "$name-unused" >/dev/null
fixture="$(docker run -d --network none --tmpfs /tmp:exec,size=1g \
  -v "$root:/src:ro" -v "$volume:/original" -v "$name-unused:/fresh" \
  -v laneway-rust-lab-gomod:/go/pkg/mod -v laneway-rust-lab-gobuild:/gobuild \
  -e GOPROXY=off -e GOCACHE=/gobuild -e GOFLAGS=-buildvcs=false \
  "$lab_image" bash /src/integration/rust-lab/connector-cutover.sh --fixture relay-quic)"
for _ in {1..90}; do
  docker logs "$fixture" 2>&1 | grep -q 'connector cutover fixture ready' && break
  [[ "$(docker inspect -f '{{.State.Running}}' "$fixture")" = true ]] || { docker logs "$fixture" >&2; exit 1; }
  sleep 1
done
docker logs "$fixture" 2>&1 | grep -q 'connector cutover fixture ready'
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
docker exec "$fixture" rm -- /original/setup.token
identity_bytes() {
  docker exec "$fixture" sh -ec 'cd /original/connector; sha256sum ca.crt node.crt node.key wireguard.key connector.toml'
}
before="$(identity_bytes)"
docker run --rm --network none --cap-drop ALL --tmpfs /tmp:exec,size=1g \
  --group-add "$socket_gid" \
  --mount "type=bind,src=$socket,dst=/var/run/docker.sock,readonly" \
  --mount type=bind,src=/usr/bin/docker,dst=/usr/bin/docker,readonly \
  -v "$root:/src:ro" -v laneway-rust-191-target:/src/rust/target \
  -v laneway-rust-lab-cache:/usr/local/cargo/registry \
  -e CARGO_INCREMENTAL=0 -e CARGO_PROFILE_DEV_DEBUG=0 \
  -e LANEWAY_MANAGED_CONNECTOR_LAB_NAME="$name" -e LANEWAY_MANAGED_CONNECTOR_LAB_IMAGE="$image" \
  -w /src laneway-rust-lab:wireguard \
  cargo test --offline --locked --manifest-path rust/Cargo.toml -p lanewayd-rs --lib \
    live_named_volume_update_and_rollback -- --ignored --nocapture
[[ "$(identity_bytes)" = "$before" ]]
echo 'Managed Connector replaced and rolled back with unchanged identity files.'
