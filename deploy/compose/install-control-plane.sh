#!/bin/sh
set -eu

source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository=${LANEWAY_REPOSITORY:-Doout/laneway}
noninteractive=${LANEWAY_NONINTERACTIVE:-false}
answers_file=${LANEWAY_INSTALLER_ANSWERS_FILE:-/var/lib/laneway-installer/control-plane.answers}
production_mode=${LANEWAY_PRODUCTION_MODE:-false}
cosign_bin=${LANEWAY_COSIGN_BIN-cosign}
checksum_signature_verified=${LANEWAY_CHECKSUM_SIGNATURE_VERIFIED:-unknown}

die() { echo "Laneway installer: $*" >&2; exit 1; }
add_missing() {
  if [ -n "${missing:-}" ]; then missing="$missing
$1"; else missing=$1; fi
}

case "$production_mode" in true|false) ;; *) die "LANEWAY_PRODUCTION_MODE must be true or false" ;; esac
if [ "$production_mode" = true ]; then install_profile=production; else install_profile=quick; fi

remembered() {
  key=$1
  fallback=${2:-}
  if [ ! -e "$answers_file" ] && [ ! -L "$answers_file" ]; then
    printf '%s' "$fallback"
    return
  fi
  if [ ! -f "$answers_file" ] || [ -L "$answers_file" ]; then
    die "remembered-answer file is not a safe regular file: $answers_file"
  fi
  [ "$(stat -c %u "$answers_file")" -eq 0 ] || die "remembered-answer file must be owned by root"
  [ "$(stat -c %a "$answers_file")" = 600 ] || die "remembered-answer file must have mode 0600"
  matches=$(sed -n "s/^${key}=//p" "$answers_file")
  count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l)
  [ "$count" -le 1 ] || die "remembered-answer file contains duplicate $key"
  if [ -n "$matches" ]; then printf '%s' "$matches"; else printf '%s' "$fallback"; fi
}

save_answers() {
  case "$answers_file" in /*) ;; *) die "remembered-answer file must use an absolute path" ;; esac
  answers_dir=$(dirname "$answers_file")
  if [ -e "$answers_dir" ] || [ -L "$answers_dir" ]; then
    if [ ! -d "$answers_dir" ] || [ -L "$answers_dir" ]; then
      die "remembered-answer directory is unsafe: $answers_dir"
    fi
    [ "$(stat -c %u "$answers_dir")" -eq 0 ] || die "remembered-answer directory must be owned by root"
    [ "$(stat -c %a "$answers_dir")" = 700 ] || die "remembered-answer directory must have mode 0700"
  else
    install -d -m 0700 -o 0 -g 0 "$answers_dir"
  fi
  temporary=$(mktemp "$answers_dir/.control-plane-installer.XXXXXX")
  {
    printf 'LANEWAY_DOMAIN=%s\n' "$domain"
    printf 'LANEWAY_DEPLOY_DIR=%s\n' "$destination"
    printf 'LANEWAY_NETWORK_NAME=%s\n' "$network_name"
    printf 'LANEWAY_IPV4_POOL=%s\n' "$ipv4_pool"
    printf 'LANEWAY_BIND_ADDRESS=%s\n' "$bind_address"
    printf 'LANEWAY_CONTROLLER_PORT=%s\n' "$controller_port"
    printf 'LANEWAY_RELAY_QUIC_PORT=%s\n' "$relay_quic_port"
    printf 'LANEWAY_RELAY_TCP_PORT=%s\n' "$relay_tcp_port"
    printf 'LANEWAY_PREPARED_INPUT_DIR=%s\n' "${issuer_dir:-}"
    printf 'LANEWAY_RECOVERY_KIT_DIR=%s\n' "${recovery_kit:-}"
    printf 'LANEWAY_BACKUP_RECIPIENT=%s\n' "${backup_recipient:-}"
  } > "$temporary"
  chmod 0600 "$temporary"
  chown 0:0 "$temporary"
  mv "$temporary" "$answers_file"
}

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

missing=
for command in age age-keygen chown curl date dirname docker find getent grep install jq laneway ln sed sha256sum ss stat sync wc; do
  command -v "$command" >/dev/null 2>&1 || add_missing "$command"
done
[ "$(id -u)" -eq 0 ] || add_missing "root privileges (run with sudo)"
if command -v docker >/dev/null 2>&1; then
  docker compose version >/dev/null 2>&1 || add_missing "Docker Compose v2"
fi
if [ -n "$missing" ]; then
  echo "Laneway pre-check found missing prerequisites:" >&2
  printf '%s\n' "$missing" | while IFS= read -r item; do printf '  - %s\n' "$item" >&2; done
  die "install the listed prerequisites and rerun; no deployment changes were made"
fi

if [ "$noninteractive" != true ]; then
  cat >&2 <<'EOF'
Laneway control-plane setup

Press Enter to accept a shown default. You will need:
  - a public DNS name that already resolves to this host

By default, the installer creates the issuer and recovery identity for you and
leaves one protected recovery-kit directory to copy off this server. You can
instead provide control-plane-input prepared on a separate trusted host.

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

ask "Public DNS name" "${LANEWAY_DOMAIN:-$(remembered LANEWAY_DOMAIN)}"
domain=$REPLY
valid_dns_name "$domain" || die "public DNS name is invalid"
getent ahosts "$domain" >/dev/null 2>&1 || die "public DNS does not resolve: $domain"

ask "Deployment directory" "${LANEWAY_DEPLOY_DIR:-$(remembered LANEWAY_DEPLOY_DIR /opt/laneway)}"
destination=$REPLY
case "$destination" in /*) ;; *) die "deployment directory must be an absolute path" ;; esac
[ "$destination" != / ] || die "deployment directory cannot be /"
if [ -e "$destination" ] || [ -L "$destination" ]; then
  die "deployment directory already exists; refusing to overwrite it: $destination"
fi
if [ -e /usr/local/sbin/laneway-control ] || [ -L /usr/local/sbin/laneway-control ]; then
  die "system control-plane command already exists: /usr/local/sbin/laneway-control"
fi

ask "Network name" "${LANEWAY_NETWORK_NAME:-$(remembered LANEWAY_NETWORK_NAME production)}"
network_name=$REPLY
case "$network_name" in ''|*[!A-Za-z0-9._-]*) die "network name may contain only letters, numbers, dot, underscore, and dash" ;; esac

ask "Overlay IPv4 pool" "${LANEWAY_IPV4_POOL:-$(remembered LANEWAY_IPV4_POOL 100.96.0.0/16)}"
ipv4_pool=$REPLY
valid_ipv4_pool "$ipv4_pool" || die "overlay IPv4 pool is invalid"

ask "Host bind address" "${LANEWAY_BIND_ADDRESS:-$(remembered LANEWAY_BIND_ADDRESS 0.0.0.0)}"
bind_address=$REPLY
valid_ipv4 "$bind_address" || die "bind address must be an IPv4 address"

ask "Controller TCP/UDP port" "${LANEWAY_CONTROLLER_PORT:-$(remembered LANEWAY_CONTROLLER_PORT 8443)}"
controller_port=$REPLY
valid_port "$controller_port" || die "controller port is invalid"
ask "Relay QUIC/UDP port" "${LANEWAY_RELAY_QUIC_PORT:-$(remembered LANEWAY_RELAY_QUIC_PORT 4433)}"
relay_quic_port=$REPLY
valid_port "$relay_quic_port" || die "relay QUIC port is invalid"
ask "Relay TCP fallback port" "${LANEWAY_RELAY_TCP_PORT:-$(remembered LANEWAY_RELAY_TCP_PORT 443)}"
relay_tcp_port=$REPLY
valid_port "$relay_tcp_port" || die "relay TCP port is invalid"
[ "$controller_port" != "$relay_quic_port" ] || die "controller and relay UDP ports must differ"
[ "$controller_port" != "$relay_tcp_port" ] || die "controller and relay TCP ports must differ"

validate_issuer_dir() {
  directory=$1
  case "$directory" in /*) ;; *) die "prepared input directory must be an absolute path" ;; esac
  if [ ! -d "$directory" ] || [ -L "$directory" ]; then
    die "prepared input directory is missing or unsafe"
  fi
  if [ -e "$directory/ca.key" ] || [ -L "$directory/ca.key" ]; then
    die "offline root ca.key must not be present in control-plane input"
  fi
  for name in ca.crt intermediate-chain.crt intermediate.key; do
    if [ ! -f "$directory/$name" ] || [ -L "$directory/$name" ]; then
      die "prepared input is missing a regular $name"
    fi
  done
}

automatic_issuer=false
issuer_dir=${LANEWAY_ISSUER_DIR:-}
if [ -z "$issuer_dir" ]; then
  ask "Prepared control-plane input directory (Enter to generate automatically)" "${LANEWAY_PREPARED_INPUT_DIR:-$(remembered LANEWAY_PREPARED_INPUT_DIR)}"
  issuer_dir=$REPLY
fi
if [ -n "$issuer_dir" ]; then
  validate_issuer_dir "$issuer_dir"
  backup_recipient=${LANEWAY_BACKUP_RECIPIENT:-$(remembered LANEWAY_BACKUP_RECIPIENT)}
  if [ -z "$backup_recipient" ] && [ -f "$issuer_dir/recovery-recipient.txt" ] && [ ! -L "$issuer_dir/recovery-recipient.txt" ]; then
    [ "$(wc -l < "$issuer_dir/recovery-recipient.txt")" -eq 1 ] || die "prepared recovery recipient file must contain exactly one line"
    backup_recipient=$(sed -n '1p' "$issuer_dir/recovery-recipient.txt")
  fi
  if [ -z "$backup_recipient" ]; then
    ask "Off-host age recovery recipient" ""
    backup_recipient=$REPLY
  fi
  printf '%s\n' "$backup_recipient" | grep -Eq '^age1[0-9a-z]{58}$' || \
    die "recovery recipient must be an age X25519 public recipient"
  recovery_description="prepared input: $issuer_dir"
else
  automatic_issuer=true
  recovery_default=/root/laneway-recovery-$domain-$(date -u +%Y%m%dT%H%M%SZ)
  ask "Recovery kit directory" "${LANEWAY_RECOVERY_KIT_DIR:-$(remembered LANEWAY_RECOVERY_KIT_DIR "$recovery_default")}"
  recovery_kit=$REPLY
  case "$recovery_kit" in /*) ;; *) die "recovery kit directory must be an absolute path" ;; esac
  [ "$recovery_kit" != / ] || die "recovery kit directory cannot be /"
  if [ -e "$recovery_kit" ] || [ -L "$recovery_kit" ]; then
    die "recovery kit already exists; refusing to overwrite it: $recovery_kit"
  fi
  recovery_description="generate automatically; copy $recovery_kit off-host after setup"
fi

save_answers

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
connector_digest=$(image_digest ghcr.io/doout/lane-edge)
exit_node_digest=$(image_digest ghcr.io/doout/laneway-exit-node)
identity="https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/$tag"
image_signatures_verified=true
for reference in \
  "ghcr.io/doout/laneway-controller@$controller_digest" \
  "ghcr.io/doout/laneway-relay@$relay_digest" \
  "ghcr.io/doout/laneway-admin@$admin_digest" \
  "ghcr.io/doout/lane-edge@$connector_digest" \
  "ghcr.io/doout/laneway-exit-node@$exit_node_digest"
do
  if [ -n "$cosign_bin" ] && command -v "$cosign_bin" >/dev/null 2>&1 && \
    "$cosign_bin" verify --certificate-identity "$identity" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com "$reference" >/dev/null; then
    :
  elif [ "$production_mode" = true ]; then
    die "production signature verification failed for $reference"
  else
    image_signatures_verified=false
    echo "WARNING: image signature could not be verified now: $reference" >&2
  fi
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
  release:      $tag (images are pinned by immutable digest)
  profile:      $install_profile
  public name:  $domain
  directory:    $destination
  overlay pool: $ipv4_pool
  listeners:    $bind_address:$controller_port TCP+UDP, $bind_address:$relay_quic_port UDP, $bind_address:$relay_tcp_port TCP
  recovery:     $recovery_description

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

if [ "$automatic_issuer" = true ]; then
  if [ ! -f "$source_dir/prepare-control-plane.sh" ] || [ -L "$source_dir/prepare-control-plane.sh" ]; then
    die "packaged automatic issuer helper is missing or unsafe"
  fi
  "$source_dir/prepare-control-plane.sh" "$recovery_kit"
  issuer_dir=$recovery_kit/control-plane-input
  validate_issuer_dir "$issuer_dir"
  [ "$(wc -l < "$issuer_dir/recovery-recipient.txt")" -eq 1 ] || die "generated recovery recipient file is invalid"
  backup_recipient=$(sed -n '1p' "$issuer_dir/recovery-recipient.txt")
  printf '%s\n' "$backup_recipient" | grep -Eq '^age1[0-9a-z]{58}$' || die "generated recovery recipient is invalid"
fi

install -d -m 0700 -o 0 -g 0 "$destination"
for name in compose.yaml laneway-control bootstrap.sh preflight.sh prepare.sh recovery.sh validate.sh install-control-plane.sh prepare-control-plane.sh upgrade-control-plane.sh README.md; do
  if [ ! -f "$source_dir/$name" ] || [ -L "$source_dir/$name" ]; then
    die "packaged deployment file is missing or unsafe: $name"
  fi
  mode=0644
  case "$name" in laneway-control|*.sh) mode=0755 ;; esac
  install -m "$mode" -o 0 -g 0 "$source_dir/$name" "$destination/$name"
done
ln -s laneway-control "$destination/lane"
ln -s "$destination/laneway-control" /usr/local/sbin/laneway-control

cat > "$destination/PRODUCTION-CHECKLIST.md" <<EOF
# Laneway production checklist

This installation uses the **$install_profile** profile for **$domain** on Laneway **$tag**.
The containers are pinned to immutable image digests. The host firewall and cloud
firewall were not changed by the installer.

## Before production traffic

- [ ] Copy the recovery kit and initial encrypted recovery bundle off this server.
- [ ] Verify the copied recovery kit's \`MANIFEST.sha256\`, then securely remove the server copy.
- [ ] Confirm DNS \`$domain\` resolves to this server's public address.
- [ ] Confirm the external firewall allows TCP 443, UDP 4433, and TCP+UDP 8443.
- [ ] Keep SSH restricted to your trusted access path; do not expose TCP 22 publicly.
- [ ] Run \`sudo laneway-control production-check\` until it succeeds.
- [ ] Test a client enrollment and recovery restore before depending on the service.
- [ ] Configure monitoring, security updates, and recurring encrypted backups.

## Verification recorded during install

- Release checksum signature verified: **$checksum_signature_verified**
- All container image signatures verified: **$image_signatures_verified**

Signature verification can depend on registry and transparency-log availability.
The \`production-check\` command is fail-closed and records a root-only marker only
after signatures, configuration, service health, DNS, and recovery backup checks pass.

Cloud firewall policy cannot be inspected reliably from inside this host. Confirm it
in your provider's control panel before putting Laneway into production.
EOF
chmod 0644 "$destination/PRODUCTION-CHECKLIST.md"

umask 077
env_tmp=$(mktemp "$destination/.env.XXXXXX")
{
  printf 'LANEWAY_VERSION=%s\n' "$release"
  printf 'LANEWAY_INSTALL_PROFILE=%s\n' "$install_profile"
  printf 'LANEWAY_CONTROLLER_IMAGE_DIGEST=%s\n' "$controller_digest"
  printf 'LANEWAY_RELAY_IMAGE_DIGEST=%s\n' "$relay_digest"
  printf 'LANEWAY_ADMIN_IMAGE_DIGEST=%s\n' "$admin_digest"
  printf 'LANEWAY_CONNECTOR_IMAGE_DIGEST=%s\n' "$connector_digest"
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

(cd "$destination" && ./laneway-control init --issuer "$issuer_dir")
initial_backup=initial-recovery-$(date -u +%Y%m%dT%H%M%SZ).age
(cd "$destination" && ./laneway-control backup "$initial_backup")
if [ "$automatic_issuer" = true ]; then
  install -m 0600 -o 0 -g 0 "$destination/generated/recovery/$initial_backup" "$recovery_kit/$initial_backup"
  find "$recovery_kit/control-plane-input" -depth -delete
  cat > "$recovery_kit/DEPLOYED.txt" <<EOF
Laneway $tag was deployed for $domain.

This recovery kit contains the private age identity, encrypted offline root,
and initial encrypted control-plane recovery bundle. Copy the entire directory
off this server, verify the copy, and then securely remove this server copy.
EOF
  chmod 0600 "$recovery_kit/DEPLOYED.txt"
  (
    cd "$recovery_kit"
    sha256sum README.txt DEPLOYED.txt laneway-recovery.identity offline-root.tar.age "$initial_backup" > MANIFEST.sha256
  )
  sync -f "$recovery_kit/MANIFEST.sha256"
  sync -f "$recovery_kit"
fi
cat <<EOF

Laneway $tag is running. Useful commands:
  sudo laneway-control status
  sudo laneway-control production-check
  sudo laneway-control invite --name DEVICE --ephemeral
  sudo laneway-control backup
  initial encrypted backup: $destination/generated/recovery/$initial_backup
EOF
if [ "$automatic_issuer" = true ]; then
  cat <<EOF

IMPORTANT: copy this entire recovery kit off-host now:
  $recovery_kit

After verifying the off-host copy, securely remove the server copy. It contains
the private recovery identity; the running control plane does not need it.
EOF
else
  cat <<EOF

Copy the initial encrypted backup shown above to the trusted host that holds
your recovery kit. The private recovery identity remains off this server.
EOF
fi
