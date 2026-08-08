#!/bin/sh
set -eu

source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository=${LANEWAY_REPOSITORY:-Doout/laneway}
noninteractive=${LANEWAY_NONINTERACTIVE:-false}

die() { echo "Laneway installer: $*" >&2; exit 1; }

ask() {
  label=$1
  default_value=${2:-}
  if [ "$noninteractive" = true ]; then
    REPLY=$default_value
    return
  fi
  if [ -n "$default_value" ]; then
    printf '%s [%s]: ' "$label" "$default_value" >&2
  else
    printf '%s: ' "$label" >&2
  fi
  IFS= read -r REPLY || die "input ended while reading: $label"
  [ -n "$REPLY" ] || REPLY=$default_value
}

valid_dns_name() {
  printf '%s\n' "$1" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
}

valid_port() {
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  [ "$1" -ge 1 ] || return 1
  [ "$1" -le 65535 ]
}

valid_ipv4() {
  candidate=$1
  first=${candidate%%.*}; remainder=${candidate#*.}
  [ "$remainder" != "$candidate" ] || return 1
  second=${remainder%%.*}; next=${remainder#*.}
  [ "$next" != "$remainder" ] || return 1
  third=${next%%.*}; fourth=${next#*.}
  [ "$fourth" != "$next" ] || return 1
  case "$fourth" in *.*) return 1 ;; esac
  for octet in "$first" "$second" "$third" "$fourth"; do
    case "$octet" in ''|*[!0-9]*) return 1 ;; esac
    [ "$octet" -le 255 ] || return 1
  done
}

valid_ipv4_pool() {
  candidate=$1
  address=${candidate%/*}
  prefix=${candidate#*/}
  [ "$address" != "$candidate" ] || return 1
  [ "$prefix" != "$candidate" ] || return 1
  valid_ipv4 "$address" || return 1
  case "$prefix" in ''|*[!0-9]*) return 1 ;; esac
  [ "$prefix" -le 32 ]
}

for command in curl cosign docker age getent grep sed sha256sum; do
  command -v "$command" >/dev/null 2>&1 || die "required command is missing: $command"
done
[ "$(id -u)" -eq 0 ] || die "run as root so the deployment can be protected and container ownership can be installed"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is unavailable"

if [ "$noninteractive" != true ]; then
  cat >&2 <<'EOF'
Laneway control-plane setup

Press Enter to accept a shown default. You will need:
  - a public DNS name that already resolves to this host
  - an age public recipient generated on a separate trusted machine
  - an issuer export containing ca.crt, intermediate-chain.crt, and
    intermediate.key (never copy the offline ca.key to this host)

No host networking or firewall settings will be changed.
EOF
fi

package_version=
if [ -f "$source_dir/../../VERSION" ] && [ ! -L "$source_dir/../../VERSION" ]; then
  package_version=$(sed -n '1p' "$source_dir/../../VERSION")
fi
version_default=${LANEWAY_VERSION:-$package_version}
if [ -n "${LANEWAY_VERSION:-}" ]; then
  release=$LANEWAY_VERSION
else
  ask "Release tag" "$version_default"
  release=$REPLY
fi
case "$release" in v*) release=${release#v} ;; esac
printf '%s\n' "$release" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || \
  die "release tag must be a stable vMAJOR.MINOR.PATCH tag"
tag=v$release
if [ -n "$package_version" ] && [ "$package_version" != "$release" ]; then
  die "the installed package is $package_version but the selected release is $release; install the matching package first"
fi

ask "Public DNS name" "${LANEWAY_DOMAIN:-}"
domain=$REPLY
valid_dns_name "$domain" || die "public DNS name is invalid"
getent ahosts "$domain" >/dev/null 2>&1 || die "public DNS does not resolve: $domain"

ask "Deployment directory" "${LANEWAY_DEPLOY_DIR:-/opt/laneway}"
destination=$REPLY
case "$destination" in /*) ;; *) die "deployment directory must be an absolute path" ;; esac
[ "$destination" != / ] || die "deployment directory cannot be /"
if [ -e "$destination" ] || [ -L "$destination" ]; then
  die "deployment directory already exists; refusing to overwrite it: $destination"
fi

ask "Network name" "${LANEWAY_NETWORK_NAME:-production}"
network_name=$REPLY
case "$network_name" in ''|*[!A-Za-z0-9._-]*) die "network name may contain only letters, numbers, dot, underscore, and dash" ;; esac

ask "Overlay IPv4 pool" "${LANEWAY_IPV4_POOL:-100.96.0.0/16}"
ipv4_pool=$REPLY
valid_ipv4_pool "$ipv4_pool" || die "overlay IPv4 pool is invalid"

ask "Host bind address" "${LANEWAY_BIND_ADDRESS:-0.0.0.0}"
bind_address=$REPLY
valid_ipv4 "$bind_address" || die "bind address must be an IPv4 address"

ask "Controller TCP/UDP port" "${LANEWAY_CONTROLLER_PORT:-8443}"
controller_port=$REPLY
valid_port "$controller_port" || die "controller port is invalid"
ask "Relay QUIC/UDP port" "${LANEWAY_RELAY_QUIC_PORT:-4433}"
relay_quic_port=$REPLY
valid_port "$relay_quic_port" || die "relay QUIC port is invalid"
ask "Relay TCP fallback port" "${LANEWAY_RELAY_TCP_PORT:-443}"
relay_tcp_port=$REPLY
valid_port "$relay_tcp_port" || die "relay TCP port is invalid"
[ "$controller_port" != "$relay_quic_port" ] || die "controller and relay UDP ports must differ"
[ "$controller_port" != "$relay_tcp_port" ] || die "controller and relay TCP ports must differ"

ask "Off-host age recovery recipient" "${LANEWAY_BACKUP_RECIPIENT:-}"
backup_recipient=$REPLY
printf '%s\n' "$backup_recipient" | grep -Eq '^age1[0-9a-z]{58}$' || \
  die "recovery recipient must be an age X25519 public recipient (the private identity stays off this host)"

ask "Online issuer export directory" "${LANEWAY_ISSUER_DIR:-}"
issuer_dir=$REPLY
case "$issuer_dir" in /*) ;; *) die "issuer export directory must be an absolute path" ;; esac
if [ ! -d "$issuer_dir" ] || [ -L "$issuer_dir" ]; then
  die "issuer export directory is missing or unsafe"
fi
if [ -e "$issuer_dir/ca.key" ] || [ -L "$issuer_dir/ca.key" ]; then
  die "offline root ca.key must not be present on this host"
fi
for name in ca.crt intermediate-chain.crt intermediate.key; do
  if [ ! -f "$issuer_dir/$name" ] || [ -L "$issuer_dir/$name" ]; then
    die "issuer export is missing a regular $name"
  fi
done

metadata_dir=$(mktemp -d)
cleanup() { [ ! -e "$metadata_dir" ] || find "$metadata_dir" -depth -delete; }
trap cleanup EXIT HUP INT TERM
base_url=${LANEWAY_RELEASE_BASE_URL:-https://github.com/$repository/releases/download/$tag}
curl --fail --location --silent --show-error "$base_url/image-digests.txt" -o "$metadata_dir/image-digests.txt"

image_digest() {
  image=$1
  matches=$(sed -n "s|^${image}@\(sha256:[0-9a-f]\{64\}\)$|\1|p" "$metadata_dir/image-digests.txt")
  [ "$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l)" -eq 1 ] || die "release metadata has no unique digest for $image"
  printf '%s' "$matches"
}

controller_digest=$(image_digest ghcr.io/doout/laneway-controller)
relay_digest=$(image_digest ghcr.io/doout/laneway-relay)
admin_digest=$(image_digest ghcr.io/doout/laneway-admin)
exit_node_digest=$(image_digest ghcr.io/doout/laneway-exit-node)
identity="https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/$tag"
for reference in \
  "ghcr.io/doout/laneway-controller@$controller_digest" \
  "ghcr.io/doout/laneway-relay@$relay_digest" \
  "ghcr.io/doout/laneway-admin@$admin_digest" \
  "ghcr.io/doout/laneway-exit-node@$exit_node_digest"
do
  cosign verify --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com "$reference" >/dev/null
done

network_id=$(laneway id)
controller_id=$(laneway id)
relay_id=$(laneway id)
for value in "$network_id" "$controller_id" "$relay_id"; do
  printf '%s\n' "$value" | grep -Eq '^[0-9a-f]{32}$' || die "laneway generated an invalid identity"
done
if [ "$network_id" = "$controller_id" ] || [ "$network_id" = "$relay_id" ] || [ "$controller_id" = "$relay_id" ]; then
  die "laneway generated duplicate identities"
fi

cat >&2 <<EOF

Laneway is ready to deploy:
  release:      $tag (signed images are pinned automatically)
  public name:  $domain
  directory:    $destination
  overlay pool: $ipv4_pool
  listeners:    $bind_address:$controller_port TCP+UDP, $bind_address:$relay_quic_port UDP, $bind_address:$relay_tcp_port TCP

This starts an isolated Docker Compose control plane. It does not edit the host
firewall, routes, interfaces, DNS, or sysctls. Ensure DNS and your external
firewall already allow the listed ports while preserving SSH access.
EOF
if [ "$noninteractive" = true ]; then
  confirmation=${LANEWAY_CONFIRM:-no}
else
  ask "Type deploy to continue" ""
  confirmation=$REPLY
fi
[ "$confirmation" = deploy ] || die "cancelled before changing the deployment"

install -d -m 0700 -o 0 -g 0 "$destination"
for name in compose.yaml lane bootstrap.sh preflight.sh prepare.sh recovery.sh validate.sh install-control-plane.sh README.md; do
  if [ ! -f "$source_dir/$name" ] || [ -L "$source_dir/$name" ]; then
    die "packaged deployment file is missing or unsafe: $name"
  fi
  mode=0644
  case "$name" in lane|*.sh) mode=0755 ;; esac
  install -m "$mode" -o 0 -g 0 "$source_dir/$name" "$destination/$name"
done

umask 077
env_tmp=$(mktemp "$destination/.env.XXXXXX")
{
  printf 'LANEWAY_VERSION=%s\n' "$release"
  printf 'LANEWAY_CONTROLLER_IMAGE_DIGEST=%s\n' "$controller_digest"
  printf 'LANEWAY_RELAY_IMAGE_DIGEST=%s\n' "$relay_digest"
  printf 'LANEWAY_ADMIN_IMAGE_DIGEST=%s\n' "$admin_digest"
  printf 'LANEWAY_EXIT_NODE_IMAGE_DIGEST=%s\n' "$exit_node_digest"
  printf 'LANEWAY_BIND_ADDRESS=%s\n' "$bind_address"
  printf 'LANEWAY_CONTROLLER_PORT=%s\n' "$controller_port"
  printf 'LANEWAY_RELAY_QUIC_PORT=%s\n' "$relay_quic_port"
  printf 'LANEWAY_RELAY_TCP_PORT=%s\n' "$relay_tcp_port"
  printf 'LANEWAY_EXIT_DIRECT_PORT=4434\n'
  printf 'LANEWAY_CONTROLLER_SERVER_NAME=%s\n' "$domain"
  printf 'LANEWAY_NETWORK_ID=%s\n' "$network_id"
  printf 'LANEWAY_CONTROLLER_SERVICE_ID=%s\n' "$controller_id"
  printf 'LANEWAY_RELAY_SERVICE_ID=%s\n' "$relay_id"
  printf 'LANEWAY_NETWORK_NAME=%s\n' "$network_name"
  printf 'LANEWAY_IPV4_POOL=%s\n' "$ipv4_pool"
  printf 'LANEWAY_RELAY_PUBLIC_ENDPOINT=%s:%s\n' "$domain" "$relay_quic_port"
  printf 'LANEWAY_BACKUP_RECIPIENT=%s\n' "$backup_recipient"
} > "$env_tmp"
chmod 0600 "$env_tmp"
mv "$env_tmp" "$destination/.env"

(cd "$destination" && ./lane init --issuer "$issuer_dir")
cat <<EOF

Laneway $tag is running. Useful commands:
  sudo $destination/lane status
  sudo $destination/lane invite --name DEVICE --ephemeral
  sudo $destination/lane backup
EOF
