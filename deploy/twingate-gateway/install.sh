#!/bin/sh
# Install/upgrade the private host worker. Run from a trusted release checkout.
set -eu
uid=${1:-65532}
case "$uid" in ''|*[!0-9]*) echo "Expected numeric controller UID." >&2; exit 2;; esac
[ "$(id -u)" = 0 ] && [ "$(uname -s)" = Linux ]
for tool in docker ip nft nsenter systemctl python3; do command -v "$tool" >/dev/null; done
[ -c /dev/net/tun ]
base=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=/var/lib/laneway-gateways
case $# in
  0|1)
    tag=v0.3.10
    images=$(python3 -B -c 'import runpy,sys; w=runpy.run_path(sys.argv[1]); print(w["CLIENT"], w["LEGACY_CONNECTOR"])' "$base/worker.py")
    read -r provider connector <<EOF
$images
EOF
    ;;
  3)
    tag=$2
    connector=$3
    provider=$(python3 -B -c 'import runpy,sys; print(runpy.run_path(sys.argv[1])["CLIENT"])' "$base/worker.py")
    printf '%s\n' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
    printf '%s\n' "$connector" | grep -Eq '^ghcr[.]io/doout/laneway/edge@sha256:[0-9a-f]{64}$'
    ;;
  *) echo "Usage: install.sh [CONTROLLER_UID [RELEASE_TAG EDGE_IMAGE_DIGEST]]" >&2; exit 2 ;;
esac
export DOCKER_HOST=unix:///var/run/docker.sock
unset DOCKER_CONTEXT
docker info >/dev/null
verify=${LANEWAY_COSIGN_BIN:-$(command -v cosign || true)}
if [ -z "$verify" ] && [ -x /usr/local/libexec/laneway/cosign-v3.1.3 ]; then
  verify=/usr/local/libexec/laneway/cosign-v3.1.3
fi
if [ -z "$verify" ]; then
  case "$(uname -m)" in
    x86_64) arch=amd64; sum=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71;;
    aarch64) arch=arm64; sum=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a;;
    *) echo "Unsupported release architecture" >&2; exit 1;;
  esac
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  verify="$tmp/cosign"
  curl -fsSL --proto '=https' "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-$arch" -o "$verify"
  printf '%s  %s\n' "$sum" "$verify" | sha256sum -c -
  chmod 0700 "$verify"
fi
"$verify" verify --certificate-identity "https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' "$connector" >/dev/null
for image in "$provider" "$connector"; do docker pull "$image"; done
install -d -m 0750 -o root -g "$uid" "$root" "$root/spool" "$root/spool/status"
install -d -m 0700 -o "$uid" -g "$uid" "$root/spool/requests"
install -d -m 0700 -o root -g root "$root/work"
install -d -m 0755 /usr/local/lib/laneway
install -m 0755 "$base/worker.py" /usr/local/lib/laneway/twingate-gateway.py
install -m 0644 "$base/laneway-twingate-gateway.service" /etc/systemd/system/
printf 'LANEWAY_CONTROLLER_UID=%s\nLANEWAY_GATEWAY_EDGE_IMAGE=%s\n' "$uid" "$connector" > /etc/laneway-twingate-gateway
systemctl daemon-reload
systemctl enable laneway-twingate-gateway
systemctl restart laneway-twingate-gateway
