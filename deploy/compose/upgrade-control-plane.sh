#!/bin/sh
set -eu

# The top-level installer uses LANEWAY_VERSION to select the release. Do not
# let that selector override the version in the verified candidate .env when
# Docker Compose or validate.sh runs below.
unset LANEWAY_VERSION

die() { echo "Laneway control-plane upgrade: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run this command as root"
source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
destination=${LANEWAY_DEPLOY_DIR:-/opt/laneway}
case "$destination" in /*) ;; *) die "LANEWAY_DEPLOY_DIR must be absolute" ;; esac
[ "$destination" != / ] || die "deployment directory cannot be /"

for command in awk curl docker find grep install ln mktemp mv readlink sed sha256sum sleep wc; do
  command -v "$command" >/dev/null 2>&1 || die "required command is missing: $command"
done
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"
for path in "$destination/.env" "$destination/compose.yaml"; do
  if [ ! -f "$path" ] || [ -L "$path" ]; then
    die "existing deployment file is missing or unsafe: $path"
  fi
done
package_version=
[ -f "$source_dir/../../VERSION" ] && [ ! -L "$source_dir/../../VERSION" ] && \
  package_version=$(sed -n '1p' "$source_dir/../../VERSION")
printf '%s\n' "$package_version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || \
  die "control-plane upgrades require a packaged stable release"
tag=v$package_version
repository=${LANEWAY_REPOSITORY:-Doout/laneway}
base_url=${LANEWAY_RELEASE_BASE_URL:-https://github.com/$repository/releases/download/$tag}

work_dir=$(mktemp -d)
cleanup() {
  [ ! -e "$work_dir" ] || find "$work_dir" -depth -delete
}
trap cleanup EXIT HUP INT TERM
artifacts_file=${LANEWAY_BOOTSTRAP_ARTIFACTS_FILE:-}
if [ -z "$artifacts_file" ] || [ ! -f "$artifacts_file" ] || [ -L "$artifacts_file" ]; then
  # Compatibility path for an older laneway-control updater. It has already
  # installed this verified package, but cannot pass the manifest introduced
  # with it, so independently authenticate the release metadata here.
  artifacts_file=$work_dir/bootstrap-artifacts.toml
  curl --fail --location --silent --show-error "$base_url/bootstrap-artifacts.toml" -o "$artifacts_file" || \
    die "could not download the bootstrap artifact manifest"
  curl --fail --location --silent --show-error "$base_url/checksums.txt" -o "$work_dir/checksums.txt" || \
    die "could not download release checksums"
  curl --fail --location --silent --show-error "$base_url/checksums.sigstore.json" -o "$work_dir/checksums.sigstore.json" || \
    die "could not download the release signature bundle"
  cosign_command=${LANEWAY_COSIGN_BIN:-/usr/local/libexec/laneway/cosign-v3.1.3}
  command -v "$cosign_command" >/dev/null 2>&1 || die "a compatible Cosign verifier is required"
  "$cosign_command" verify-blob --bundle "$work_dir/checksums.sigstore.json" \
    --certificate-identity "https://github.com/$repository/.github/workflows/release.yml@refs/tags/$tag" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$work_dir/checksums.txt" >/dev/null 2>&1 || die "release checksum signature verification failed"
  (
    cd "$work_dir"
    grep '  bootstrap-artifacts.toml$' checksums.txt > bootstrap-artifacts-checksum.txt
    [ "$(wc -l < bootstrap-artifacts-checksum.txt)" -eq 1 ]
    sha256sum -c bootstrap-artifacts-checksum.txt >/dev/null
  ) || die "bootstrap artifact manifest checksum verification failed"
fi
if [ "$(grep -c '^\[\[bootstrap\.artifacts\]\]$' "$artifacts_file")" -ne 4 ]; then
  die "signed bootstrap artifact manifest must contain four platform artifacts"
fi
curl --fail --location --silent --show-error "$base_url/image-digests.txt" -o "$work_dir/image-digests.txt"

image_digest() {
  image=$1
  matches=$(sed -n "s|^${image}@\(sha256:[0-9a-f]\{64\}\)$|\1|p" "$work_dir/image-digests.txt")
  [ "$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l)" -eq 1 ] || \
    die "release metadata has no unique digest for $image"
  printf '%s' "$matches"
}

controller_digest=$(image_digest ghcr.io/doout/laneway-controller)
relay_digest=$(image_digest ghcr.io/doout/laneway-relay)
admin_digest=$(image_digest ghcr.io/doout/laneway-admin)
exit_digest=$(image_digest ghcr.io/doout/laneway-connector)

install -d -m 0700 -o 0 -g 0 "$destination/generated/lifecycle"
candidate=$destination/generated/lifecycle/upgrade-$package_version.env
awk -v version="$package_version" -v controller="$controller_digest" -v relay="$relay_digest" \
  -v admin="$admin_digest" -v exit_node="$exit_digest" '
  BEGIN {
    replacement["LANEWAY_VERSION"] = version
    replacement["LANEWAY_CONTROLLER_IMAGE_DIGEST"] = controller
    replacement["LANEWAY_RELAY_IMAGE_DIGEST"] = relay
    replacement["LANEWAY_ADMIN_IMAGE_DIGEST"] = admin
    replacement["LANEWAY_EXIT_NODE_IMAGE_DIGEST"] = exit_node
  }
  {
    key = $0
    sub(/=.*/, "", key)
    if (key in replacement) {
      print key "=" replacement[key]
      seen[key]++
    } else {
      print
    }
  }
  END {
    for (key in replacement) if (seen[key] != 1) exit 1
  }
' "$destination/.env" > "$work_dir/candidate.env" || die "existing release environment is incomplete"
install -m 0600 -o 0 -g 0 "$work_dir/candidate.env" "$candidate"

if [ ! -f "$source_dir/laneway-control" ] || [ -L "$source_dir/laneway-control" ]; then
  die "packaged laneway-control command is missing or unsafe"
fi
install -m 0755 -o 0 -g 0 "$source_dir/laneway-control" "$destination/.laneway-control.new"
mv "$destination/.laneway-control.new" "$destination/laneway-control"

if [ -e "$destination/lane" ] || [ -L "$destination/lane" ]; then
  if [ -L "$destination/lane" ]; then
    [ "$(readlink "$destination/lane")" = laneway-control ] || die "unexpected compatibility link: $destination/lane"
  elif [ -f "$destination/lane" ]; then
    legacy=$destination/generated/lifecycle/lane-before-$package_version
    if [ -e "$legacy" ] || [ -L "$legacy" ]; then
      die "legacy wrapper backup already exists: $legacy"
    fi
    mv "$destination/lane" "$legacy"
    ln -s laneway-control "$destination/lane"
  else
    die "refusing to replace unsafe compatibility path: $destination/lane"
  fi
else
  ln -s laneway-control "$destination/lane"
fi

system_command=${LANEWAY_CONTROL_COMMAND:-/usr/local/sbin/laneway-control}
case "$system_command" in /*) ;; *) die "LANEWAY_CONTROL_COMMAND must be absolute" ;; esac
if [ -e "$system_command" ] || [ -L "$system_command" ]; then
  [ -L "$system_command" ] || die "refusing to replace non-symlink command: $system_command"
  target=$(readlink "$system_command")
  case "$target" in "$destination/laneway-control"|"$destination/lane") ;; *) die "unexpected command link target: $target" ;; esac
else
  ln -s "$destination/laneway-control" "$system_command"
fi

current_version=$(sed -n 's/^LANEWAY_VERSION=//p' "$destination/.env")
printf '%s\n' "$current_version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || \
  die "installed release version is invalid"
if [ "$current_version" = "$package_version" ]; then
  echo "Laneway control plane is already on $tag; operator command was refreshed."
  exit 0
fi

for path in "$source_dir/compose.yaml" "$destination/generated/config/controller.toml" "$destination/generated/config/relay.toml"; do
  if [ ! -f "$path" ] || [ -L "$path" ]; then
    die "public HTTPS migration input is missing or unsafe: $path"
  fi
done
cp "$destination/generated/config/controller.toml" "$work_dir/controller.toml.previous"
cp "$destination/generated/config/relay.toml" "$work_dir/relay.toml.previous"
server_name=$(sed -n 's/^LANEWAY_CONTROLLER_SERVER_NAME=//p' "$destination/.env")
network_id=$(sed -n 's/^LANEWAY_NETWORK_ID=//p' "$destination/.env")
controller_port=$(sed -n 's/^LANEWAY_CONTROLLER_PORT=//p' "$destination/.env")
[ -n "$controller_port" ] || controller_port=8443
cp "$work_dir/controller.toml.previous" "$work_dir/controller.toml"
# Release artifacts are versioned update metadata. Remove the old array blocks
# before installing the signed manifest for this release.
awk '
  /^\[\[bootstrap\.artifacts\]\]$/ { dropping=1; next }
  /^\[/ && dropping { dropping=0 }
  !dropping { print }
' "$work_dir/controller.toml" > "$work_dir/controller.without-artifacts.toml"
mv "$work_dir/controller.without-artifacts.toml" "$work_dir/controller.toml"
if ! grep -Eq '^\[bootstrap\][[:space:]]*$' "$work_dir/controller.toml"; then
  printf '\n[bootstrap]\nnetwork_id = "%s"\ncontroller_endpoint = "https://%s:%s"\ncontroller_quic_endpoint = "%s:%s"\ncontroller_server_name = "%s"\n' \
    "$network_id" "$server_name" "$controller_port" "$server_name" "$controller_port" "$server_name" >> "$work_dir/controller.toml"
fi
cat "$artifacts_file" >> "$work_dir/controller.toml"
cp "$work_dir/relay.toml.previous" "$work_dir/relay.toml"
if ! grep -Eq '^\[public_https\][[:space:]]*$' "$work_dir/relay.toml"; then
  printf '\n[public_https]\nserver_name = "%s"\ncache_dir = "/var/lib/laneway-public"\n' "$server_name" >> "$work_dir/relay.toml"
fi
migration_dir=$work_dir/migration
install -d -m 0700 "$migration_dir"
install -m 0644 "$source_dir/compose.yaml" "$migration_dir/compose.yaml"
install -m 0444 "$work_dir/controller.toml" "$migration_dir/controller.toml"
install -m 0444 "$work_dir/relay.toml" "$migration_dir/relay.toml"

printf '\nApplying Laneway control-plane release\n'
printf '  Version: v%s -> %s\n' "$current_version" "$tag"
printf '  Network identity, PKI, state, ports, firewall, and host networking remain unchanged.\n\n'
if ! (cd "$destination" && ./laneway-control upgrade "$candidate" "$migration_dir"); then
  die "upgrade failed; restoring the previous deployment files and containers"
fi
public_ready=false
attempt=0
while [ "$attempt" -lt 30 ]; do
  if curl --fail --silent --show-error --max-time 10 --tlsv1.3 \
    "https://$server_name/.well-known/laneway/bootstrap.json" > "$work_dir/bootstrap.json" 2>/dev/null &&
    grep -F "\"network_id\":\"$network_id\"" "$work_dir/bootstrap.json" >/dev/null &&
    grep -F "releases/download/$tag/laneway_" "$work_dir/bootstrap.json" >/dev/null; then
    public_ready=true
    break
  fi
  attempt=$((attempt + 1))
  sleep 2
done
if [ "$public_ready" != true ]; then
  (cd "$destination" && ./laneway-control rollback) || die "public HTTPS bootstrap failed and automatic rollback also failed"
  die "public HTTPS bootstrap did not become ready; the previous deployment was restored"
fi
for name in compose.yaml validate.sh preflight.sh recovery.sh bootstrap.sh README.md; do
  [ ! -f "$source_dir/$name" ] || case "$name" in
    *.sh) install -m 0755 -o 0 -g 0 "$source_dir/$name" "$destination/$name" ;;
    *) install -m 0644 -o 0 -g 0 "$source_dir/$name" "$destination/$name" ;;
  esac
done
printf '\nLaneway control plane is now on %s\n' "$tag"
printf '  Public HTTPS: automatic certificate management on TCP 443\n'
printf '  Verify:       sudo laneway-control status\n'
