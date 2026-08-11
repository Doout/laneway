#!/bin/sh
set -eu

repository=Doout/laneway
image=ghcr.io/doout/lane-edge
container=${1:-}

die() { echo "laneway Connector update: $*" >&2; exit 1; }

if [ "$#" -ne 1 ]; then
  die "usage: update-connector.sh laneway-connector-NAME"
fi
case "$container" in
  laneway-connector-[A-Za-z0-9]* ) ;;
  * ) die "container name must begin with laneway-connector-" ;;
esac
case "$container" in *[!A-Za-z0-9_.-]*) die "container name contains unsafe characters" ;; esac
[ "$(id -u)" -eq 0 ] || die "run this updater as root"

for command in curl docker sha256sum; do
  command -v "$command" >/dev/null 2>&1 || die "$command is required"
done
docker version >/dev/null 2>&1 || die "Docker is unavailable"
docker inspect "$container" >/dev/null 2>&1 || die "container does not exist: $container"

lock_parent=${LANEWAY_LOCK_DIR:-/run/lock}
case "$lock_parent" in /*) ;; *) die "LANEWAY_LOCK_DIR must be absolute" ;; esac
[ -d "$lock_parent" ] || die "update lock directory does not exist: $lock_parent"
lock_dir=$lock_parent/laneway-connector-update-$container
mkdir "$lock_dir" 2>/dev/null || die "another update is already running for $container"
update_dir=
cleanup() {
  find "$update_dir" -depth -delete 2>/dev/null || true
  rmdir "$lock_dir" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
update_dir=$(mktemp -d) || die "could not create a temporary update directory"

cosign_command=
if [ -n "${LANEWAY_COSIGN_BIN:-}" ] && command -v "$LANEWAY_COSIGN_BIN" >/dev/null 2>&1; then
  cosign_command=$LANEWAY_COSIGN_BIN
elif [ -x /usr/local/libexec/laneway/cosign-v3.1.3 ]; then
  cosign_command=/usr/local/libexec/laneway/cosign-v3.1.3
elif command -v cosign >/dev/null 2>&1; then
  cosign_command=cosign
else
  case "$(uname -m)" in
    x86_64) cosign_architecture=amd64; cosign_sha=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 ;;
    aarch64|arm64) cosign_architecture=arm64; cosign_sha=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a ;;
    *) die "no pinned Cosign verifier is available for this architecture" ;;
  esac
  downloaded_cosign=$update_dir/cosign-v3.1.3
  curl --fail --silent --show-error --location \
    "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-$cosign_architecture" \
    --output "$downloaded_cosign" || die "could not download the pinned Cosign verifier"
  printf '%s  %s\n' "$cosign_sha" "$downloaded_cosign" | sha256sum -c - >/dev/null || \
    die "pinned Cosign verifier checksum verification failed"
  chmod 0755 "$downloaded_cosign"
  reported_cosign_version=$("$downloaded_cosign" version --json 2>/dev/null |
    sed -n 's/.*"gitVersion":[[:space:]]*"\([^"]*\)".*/\1/p' | sed -n '1p')
  [ "$reported_cosign_version" = v3.1.3 ] || die "pinned Cosign verifier reported an unexpected version"
  install -d -m 0755 /usr/local/libexec/laneway
  install -m 0755 "$downloaded_cosign" /usr/local/libexec/laneway/cosign-v3.1.3
  cosign_command=/usr/local/libexec/laneway/cosign-v3.1.3
fi

latest_url=$(curl --fail --silent --show-error --location \
  --header 'Cache-Control: no-cache' --header 'Pragma: no-cache' --output /dev/null \
  --write-out '%{url_effective}' \
  "https://github.com/$repository/releases/latest?laneway_cache_bust=$(date +%s)") || \
  die "could not discover the latest stable release"
tag=${latest_url##*/}
printf '%s\n' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || \
  die "latest release has an invalid tag: $tag"
version=${tag#v}
release_url=https://github.com/$repository/releases/download/$tag

for asset in image-digests.txt checksums.txt checksums.sigstore.json; do
  curl --fail --silent --show-error --location "$release_url/$asset" \
    --output "$update_dir/$asset" || die "could not download $asset for $tag"
done

identity="https://github.com/$repository/.github/workflows/release.yml@refs/tags/$tag"
"$cosign_command" verify-blob \
  --bundle "$update_dir/checksums.sigstore.json" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$update_dir/checksums.txt" >/dev/null 2>&1 || \
  die "release checksum signature verification failed"
(
  cd "$update_dir"
  grep -E '  image-digests\.txt$' checksums.txt > selected-checksum.txt
  [ "$(wc -l < selected-checksum.txt)" -eq 1 ]
  sha256sum -c selected-checksum.txt >/dev/null
) || die "image digest manifest checksum verification failed"

connector_digest=$(sed -n \
  's|^ghcr.io/doout/lane-edge@\(sha256:[0-9a-f]*\)$|\1|p' \
  "$update_dir/image-digests.txt")
[ "$(printf '%s\n' "$connector_digest" | wc -l)" -eq 1 ] || \
  die "release contains multiple Connector digests"
printf '%s\n' "$connector_digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || \
  die "release does not contain exactly one valid Connector digest"
target=$image:$version@$connector_digest
"$cosign_command" verify \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$image@$connector_digest" >/dev/null 2>&1 || die "Connector image signature verification failed"

current_ref=$(docker inspect --format '{{.Config.Image}}' "$container")
if [ "$current_ref" = "$target" ]; then
  echo "$container is already current at $tag ($connector_digest)"
  exit 0
fi

mount_line=$(docker inspect --format \
  '{{range .Mounts}}{{if eq .Destination "/var/lib/laneway"}}{{println .Type .Name}}{{end}}{{end}}' \
  "$container")
state_volume=$container-state
[ "$mount_line" = "volume $state_volume" ] || \
  die "container must mount the named volume $state_volume at /var/lib/laneway"
hostname=$(docker inspect --format '{{.Config.Hostname}}' "$container")
[ -n "$hostname" ] || die "container hostname is empty"

echo "Updating $container from $current_ref to $target"
docker pull "$target" >/dev/null

# Refuse to stop the serving Connector until the replacement image proves that
# the durable volume contains the complete identity needed without enrollment.
docker run --rm --pull never \
  --user 65532:65532 --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --volume "$state_volume:/var/lib/laneway:ro" \
  "$target" connector validate --state-dir /var/lib/laneway/connector \
  >/dev/null || die "durable Connector identity is incomplete; existing container was not changed"

previous=$container-previous-$$
docker stop "$container" >/dev/null || die "could not stop $container"
if ! docker rename "$container" "$previous"; then
  docker start "$container" >/dev/null 2>&1 || true
  die "could not preserve the previous container"
fi

rollback() {
  echo "Replacement failed; restoring $current_ref" >&2
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker rename "$previous" "$container" >/dev/null 2>&1 || \
    die "automatic rollback could not restore the previous container name"
  docker start "$container" >/dev/null 2>&1 || \
    die "automatic rollback could not restart the previous container"
  die "replacement did not become healthy; previous Connector restored"
}

if ! docker run -d \
  --name "$container" \
  --hostname "$hostname" \
  --restart unless-stopped \
  --pull never \
  --user 65532:65532 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=65532,gid=65532 \
  --tmpfs /run/laneway:rw,noexec,nosuid,nodev,size=4m,mode=0700,uid=65532,gid=65532 \
  --volume "$state_volume:/var/lib/laneway" \
  --health-cmd '/usr/local/bin/laneway-healthcheck -unix /run/laneway/lanewayd.sock' \
  --health-interval 10s \
  --health-timeout 3s \
  --health-retries 6 \
  --health-start-period 15s \
  "$target" >/dev/null; then
  rollback
fi

attempt=0
health=starting
while [ "$attempt" -lt 24 ]; do
  health=$(docker inspect --format \
    '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' \
    "$container" 2>/dev/null || echo missing)
  [ "$health" != healthy ] || break
  running=$(docker inspect --format '{{.State.Running}}' "$container" 2>/dev/null || echo false)
  [ "$running" = true ] || break
  attempt=$((attempt + 1))
  sleep 5
done
if [ "$health" != healthy ]; then
  docker logs --tail 100 "$container" >&2 2>/dev/null || true
  rollback
fi

docker rm "$previous" >/dev/null || die "updated successfully but could not remove $previous"
echo "$container updated successfully to $tag ($connector_digest)"
