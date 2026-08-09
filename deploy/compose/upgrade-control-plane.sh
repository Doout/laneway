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

for command in awk curl docker find grep install ln mktemp mv readlink sed wc; do
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
cleanup() { [ ! -e "$work_dir" ] || find "$work_dir" -depth -delete; }
trap cleanup EXIT HUP INT TERM
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
exit_digest=$(image_digest ghcr.io/doout/laneway-exit-node)

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

echo "Upgrading Laneway control plane from v$current_version to $tag."
echo "Deployment identity, PKI, state, ports, firewall, and host networking are unchanged."
(cd "$destination" && ./laneway-control upgrade "$candidate")
echo "Laneway control plane upgraded to $tag."
echo "Run: sudo laneway-control status"
