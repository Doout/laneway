#!/bin/sh
set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$(printf ' \t\n_'); IFS=${IFS%_}
export PATH
unset ENV BASH_ENV CDPATH
umask 077

repository=Doout/laneway
image=ghcr.io/doout/lane-edge
container=${1:-}

die() { echo "laneway Connector update: $*" >&2; exit 1; }

configure_trusted_docker_client() {
  if [ -e /root ] || [ -L /root ]; then
    [ -d /root ] && [ ! -L /root ] && [ "$(stat -c '%u:%g' /root)" = 0:0 ] && \
      [ $((0$(stat -c '%a' /root) & 0022)) -eq 0 ] || \
      die "/root must be a root-owned real directory not writable by group or others"
  else
    [ "$(stat -c '%u:%g' /)" = 0:0 ] && [ $((0$(stat -c '%a' /) & 0022)) -eq 0 ] || \
      die "the filesystem root must protect the absent /root Docker configuration parent"
  fi
  docker_config=/root/.docker
  if [ -e "$docker_config" ] || [ -L "$docker_config" ]; then
    [ -d "$docker_config" ] && [ ! -L "$docker_config" ] && \
      [ "$(stat -c '%u:%g' "$docker_config")" = 0:0 ] && \
      [ $((0$(stat -c '%a' "$docker_config") & 0022)) -eq 0 ] || \
      die "/root/.docker must be a root-owned real directory not writable by group or others"
  fi
  DOCKER_CONFIG=$docker_config
  HOME=/root
  export DOCKER_CONFIG HOME
}

validate_protected_executable() {
  protected_executable=$1
  [ -f "$protected_executable" ] && [ ! -L "$protected_executable" ] && \
    [ -x "$protected_executable" ] && \
    [ "$(stat -c '%u:%g:%h' "$protected_executable")" = 0:0:1 ] || return 1
  protected_directory=$(dirname "$protected_executable")
  protected_leaf=true
  while :; do
    [ -d "$protected_directory" ] && [ ! -L "$protected_directory" ] || return 1
    protected_attributes=$(stat -c '%a:%u:%g' "$protected_directory") || return 1
    protected_mode=${protected_attributes%%:*}
    protected_owner=${protected_attributes#*:}
    [ "$protected_owner" = 0:0 ] || return 1
    if [ $((0$protected_mode & 0022)) -ne 0 ]; then
      [ "$protected_leaf" = false ] && [ $((0$protected_mode & 01000)) -ne 0 ] || return 1
    fi
    [ "$protected_directory" != / ] || return 0
    protected_directory=$(dirname "$protected_directory") || return 1
    protected_leaf=false
  done
}

if [ "$#" -ne 1 ]; then
  die "usage: update-connector.sh laneway-connector-NAME"
fi
case "$container" in
  laneway-connector-[A-Za-z0-9]* ) ;;
  * ) die "container name must begin with laneway-connector-" ;;
esac
case "$container" in *[!A-Za-z0-9_.-]*) die "container name contains unsafe characters" ;; esac
[ "$(id -u)" -eq 0 ] || die "run this updater as root"

if [ "${DOCKER_HOST+x}" = x ] || [ "${DOCKER_CONTEXT+x}" = x ] || \
  [ "${DOCKER_TLS+x}" = x ] || [ "${DOCKER_TLS_VERIFY+x}" = x ] || \
  [ "${DOCKER_CERT_PATH+x}" = x ] || [ "${DOCKER_CONFIG+x}" = x ]; then
  die "Docker target overrides are not allowed"
fi
if [ "${LANEWAY_REPOSITORY+x}" = x ] || [ "${LANEWAY_RELEASE_BASE_URL+x}" = x ] || \
  [ "${LANEWAY_AUTHENTICATED_RELEASE_BASE_URL+x}" = x ] || \
  [ "${LANEWAY_AUTHENTICATED_IMAGE_DIGESTS_FILE+x}" = x ] || \
  [ "${LANEWAY_AUTHENTICATED_COSIGN_BIN+x}" = x ] || [ "${LANEWAY_COSIGN_BIN+x}" = x ] || \
  [ "${LANEWAY_COMMAND+x}" = x ] || [ "${LANEWAY_CONTROL_COMMAND+x}" = x ]; then
  die "release source overrides are not allowed for Connector updates"
fi
trust_override=$(env | sed -n \
  -e 's/^\(COSIGN_[A-Za-z0-9_]*\)=.*/\1/p' \
  -e 's/^\(SIGSTORE_[A-Za-z0-9_]*\)=.*/\1/p' \
  -e 's/^\(TUF_[A-Za-z0-9_]*\)=.*/\1/p' | sed -n '1p')
[ -z "$trust_override" ] || die "$trust_override is not allowed for release verification"
if [ "${CURL_CA_BUNDLE+x}" = x ] || [ "${SSL_CERT_FILE+x}" = x ] || \
  [ "${SSL_CERT_DIR+x}" = x ]; then
  die "TLS trust path overrides are not allowed for release verification"
fi
unset DOCKER_DEFAULT_PLATFORM

for command in curl dirname docker env sed sha256sum stat; do
  command -v "$command" >/dev/null 2>&1 || die "$command is required"
done
configure_trusted_docker_client

lock_parent=${LANEWAY_LOCK_DIR:-/run/lock}
case "$lock_parent" in /*) ;; *) die "LANEWAY_LOCK_DIR must be absolute" ;; esac
case "$lock_parent" in /|*/|*//*|*/./*|*/../*|*/.|*/..) die "LANEWAY_LOCK_DIR must be canonical" ;; esac
lock_parent_physical=$(CDPATH='' cd -- "$lock_parent" 2>/dev/null && pwd -P) || \
  die "update lock directory does not exist: $lock_parent"
[ "$lock_parent_physical" = "$lock_parent" ] || die "LANEWAY_LOCK_DIR must identify its exact physical directory"
validate_protected_directory_chain() {
  protected_path=$1
  while :; do
    [ -d "$protected_path" ] && [ ! -L "$protected_path" ] || return 1
    protected_owner=$(stat -c '%u:%g' "$protected_path") || return 1
    [ "$protected_owner" = 0:0 ] || return 1
    protected_mode=$(stat -c '%a' "$protected_path") || return 1
    if [ $((0$protected_mode & 0022)) -ne 0 ] && [ $((0$protected_mode & 01000)) -eq 0 ]; then
      return 1
    fi
    [ "$protected_path" != / ] || return 0
    protected_path=$(dirname "$protected_path") || return 1
  done
}
validate_protected_directory_chain "$lock_parent" || \
  die "update lock directory ancestry must be root-owned and non-replaceable"
lock_dir=$lock_parent/laneway-connector-update-$container
mkdir "$lock_dir" 2>/dev/null || die "another update is already running for $container"
chmod 0700 "$lock_dir" || {
  rmdir "$lock_dir" 2>/dev/null || true
  die "could not protect the Connector update lock"
}
update_dir=
service_disrupted=false
update_committed=false
previous=$container-previous-$$
transaction_id=laneway-connector-update-$$
original_container_id=
container_identity() {
  docker --context default inspect --format '{{.Id}}' "$1" 2>/dev/null || true
}
container_transaction() {
  docker --context default inspect --format \
    '{{ index .Config.Labels "io.laneway.update-transaction" }}' "$1" 2>/dev/null || true
}
restore_disrupted_connector() {
  [ "$service_disrupted" = true ] || return 0
  current_container_id=$(container_identity "$container")
  if [ "$current_container_id" = "$original_container_id" ]; then
    docker --context default start "$container" >/dev/null 2>&1 || return 1
    service_disrupted=false
    return 0
  fi
  previous_container_id=$(container_identity "$previous")
  [ "$previous_container_id" = "$original_container_id" ] || return 1
  if [ -n "$current_container_id" ]; then
    [ "$(container_transaction "$container")" = "$transaction_id" ] || return 1
    docker --context default rm -f "$container" >/dev/null 2>&1 || return 1
  fi
  docker --context default rename "$previous" "$container" >/dev/null 2>&1 || return 1
  docker --context default start "$container" >/dev/null 2>&1 || return 1
  service_disrupted=false
}
cleanup() {
  cleanup_status=0
  if [ "$update_committed" != true ] && ! restore_disrupted_connector; then
    echo "laneway Connector update: automatic signal/failure recovery failed; preserving lock $lock_dir" >&2
    printf '%s\n' "manual recovery required for $container" > "$lock_dir/recovery-required" 2>/dev/null || true
    cleanup_status=1
  fi
  [ -z "$update_dir" ] || [ ! -e "$update_dir" ] || find "$update_dir" -depth -delete 2>/dev/null || true
  if [ "$cleanup_status" -eq 0 ]; then
    [ ! -d "$lock_dir" ] || rmdir "$lock_dir" 2>/dev/null || true
  fi
  return "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if ! validate_protected_directory_chain "$lock_parent" || [ ! -d "$lock_dir" ] || [ -L "$lock_dir" ] || \
  [ "$(stat -c '%a:%u:%g' "$lock_dir")" != 700:0:0 ]; then
  die "Connector update lock changed during acquisition"
fi
docker --context default version >/dev/null 2>&1 || die "Docker is unavailable"
docker --context default inspect "$container" >/dev/null 2>&1 || die "container does not exist: $container"
original_container_id=$(container_identity "$container")
printf '%s\n' "$original_container_id" | grep -Eq '^[0-9a-f]{64}$' || \
  die "container has an invalid Docker identity: $container"
temporary_parent=/var/tmp
if [ ! -d "$temporary_parent" ] || [ -L "$temporary_parent" ] || \
  [ "$(stat -c '%a:%u:%g' "$temporary_parent")" != 1777:0:0 ]; then
  die "/var/tmp must be a root-owned real directory with mode 1777"
fi
update_dir=$(mktemp -d "$temporary_parent/laneway-connector-update.XXXXXX") || \
  die "could not create a temporary update directory"

cosign_command=
if [ -x /usr/local/libexec/laneway/cosign-v3.1.3 ]; then
  cosign_command=/usr/local/libexec/laneway/cosign-v3.1.3
else
  case "$(uname -m)" in
    x86_64) cosign_architecture=amd64; cosign_sha=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 ;;
    aarch64|arm64) cosign_architecture=arm64; cosign_sha=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a ;;
    *) die "no pinned Cosign verifier is available for this architecture" ;;
  esac
  downloaded_cosign=$update_dir/cosign-v3.1.3
  curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
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
validate_protected_executable "$cosign_command" || \
  die "the protected Cosign verifier is missing or unsafe"
reported_cosign_version=$("$cosign_command" version --json 2>/dev/null |
  sed -n 's/.*"gitVersion":[[:space:]]*"\([^"]*\)".*/\1/p' | sed -n '1p')
[ "$reported_cosign_version" = v3.1.3 ] || \
  die "the protected Cosign verifier has an unexpected version"

latest_url=$(curl --disable --fail --silent --show-error --location \
  --proto '=https' --proto-redir '=https' \
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
  curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    "$release_url/$asset" \
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

current_ref=$(docker --context default inspect --format '{{.Config.Image}}' "$container")
if [ "$current_ref" = "$target" ]; then
  echo "$container is already current at $tag ($connector_digest)"
  exit 0
fi

mount_line=$(docker --context default inspect --format \
  '{{range .Mounts}}{{if eq .Destination "/var/lib/laneway"}}{{println .Type .Name}}{{end}}{{end}}' \
  "$container")
state_volume=$container-state
[ "$mount_line" = "volume $state_volume" ] || \
  die "container must mount the named volume $state_volume at /var/lib/laneway"
hostname=$(docker --context default inspect --format '{{.Config.Hostname}}' "$container")
[ -n "$hostname" ] || die "container hostname is empty"

echo "Updating $container from $current_ref to $target"
docker --context default pull "$target" >/dev/null

# Refuse to stop the serving Connector until the replacement image proves that
# the durable volume contains the complete identity needed without enrollment.
docker --context default run --rm --pull never \
  --user 65532:65532 --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --volume "$state_volume:/var/lib/laneway:ro" \
  "$target" connector validate --state-dir /var/lib/laneway/connector \
  >/dev/null || die "durable Connector identity is incomplete; existing container was not changed"

if docker --context default inspect "$previous" >/dev/null 2>&1; then
  die "rollback container name already exists: $previous"
fi
service_disrupted=true
docker --context default stop "$container" >/dev/null || die "could not stop $container"
if ! docker --context default rename "$container" "$previous"; then
  die "could not preserve the previous container"
fi

rollback() {
  echo "Replacement failed; restoring $current_ref" >&2
  restore_disrupted_connector || die "automatic rollback could not restore and restart the previous container"
  die "replacement did not become healthy; previous Connector restored"
}

if ! docker --context default run -d \
  --name "$container" \
  --hostname "$hostname" \
  --restart unless-stopped \
  --pull never \
  --label "io.laneway.update-transaction=$transaction_id" \
  --user 65532:65532 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=65532,gid=65532 \
  --tmpfs /run/laneway:rw,noexec,nosuid,nodev,size=4m,mode=0700,uid=65532,gid=65532 \
  --volume "$state_volume:/var/lib/laneway" \
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
  health=$(docker --context default inspect --format \
    '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' \
    "$container" 2>/dev/null || echo missing)
  [ "$health" != healthy ] || break
  running=$(docker --context default inspect --format '{{.State.Running}}' "$container" 2>/dev/null || echo false)
  [ "$running" = true ] || break
  attempt=$((attempt + 1))
  sleep 5
done
if [ "$health" != healthy ]; then
  docker --context default logs --tail 100 "$container" >&2 2>/dev/null || true
  rollback
fi

update_committed=true
service_disrupted=false
docker --context default rm "$previous" >/dev/null || \
  die "replacement is healthy but could not remove $previous"
echo "$container updated successfully to $tag ($connector_digest)"
