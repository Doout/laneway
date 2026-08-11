#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
workflow=$repo_dir/.github/workflows/release.yml
dockerfile=$repo_dir/deploy/containers/Dockerfile
connector_dockerfile=$repo_dir/deploy/containers/Dockerfile.connector
exit_dockerfile=$repo_dir/deploy/containers/Dockerfile.exit-node
connector_updater=$repo_dir/deploy/containers/update-connector.sh
compose_file=$repo_dir/deploy/compose/compose.yaml
lane_workflow=$repo_dir/deploy/compose/laneway-control
prepare_workflow=$repo_dir/deploy/compose/prepare.sh
recovery_workflow=$repo_dir/deploy/compose/recovery.sh
installer=$repo_dir/deploy/compose/install-control-plane.sh
preparer=$repo_dir/deploy/compose/prepare-control-plane.sh
upgrader=$repo_dir/deploy/compose/upgrade-control-plane.sh
package_workflow=$repo_dir/scripts/package.sh
package_installer=$repo_dir/scripts/install-package.sh
client_installer=$repo_dir/install.sh

require() {
  pattern=$1
  path=$2
  if ! grep -F -- "$pattern" "$path" >/dev/null; then
    echo "release contract is missing '$pattern' in ${path#"$repo_dir"/}" >&2
    exit 1
  fi
}

# Release credentials can publish packages and attestations, so every external
# action is fixed to an immutable commit instead of a mutable tag or branch.
if sed -n 's/^[[:space:]]*- uses: \([^ #]*\).*/\1/p' "$workflow" |
  grep -Ev '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$' >/dev/null; then
  echo "release workflow contains an action that is not pinned to a full commit" >&2
  exit 1
fi

for image in \
  ghcr.io/doout/laneway-controller \
  ghcr.io/doout/laneway-relay \
  ghcr.io/doout/laneway-admin \
  ghcr.io/doout/lane-edge \
  ghcr.io/doout/laneway-exit-node
do
  require "image: $image" "$workflow"
done

for value in 'production-check' 'production-verified' 'cosign_command' 'compose_with_env' 'compose_file_with_env' 'backup_recovery' 'database was not rolled back' 'run_update' 'releases/latest' 'verify-blob'; do
  require "$value" "$lane_workflow"
done
for value in 'pki verify-authority' 'offline root private key ca.key must never' 'chown 65532:65532'; do
  require "$value" "$prepare_workflow"
done
for value in 'age --encrypt' 'age --decrypt' 'unexpected recovery archive entry' 'generated/recovery' 'chown 0:0'; do
  require "$value" "$recovery_workflow"
done
for value in 'Release tag' 'image-digests.txt' 'production signature verification failed' 'PRODUCTION-CHECKLIST.md' 'LANEWAY_INSTALL_PROFILE' 'does not edit the host' 'prepare-control-plane.sh' 'initial encrypted backup' 'control-plane.answers' 'save_answers'; do
  require "$value" "$installer"
done
for value in '/dev/shm' 'offline-root.tar.age' 'control-plane-input' 'pki verify-authority' 'Never copy laneway-recovery.identity'; do
  require "$value" "$preparer"
done
for value in 'generated/lifecycle' 'image-digests.txt' 'LANEWAY_BOOTSTRAP_ARTIFACTS_FILE' 'laneway-control upgrade' 'host networking remain unchanged'; do
  require "$value" "$upgrader"
done
for value in '.env.example' 'install-control-plane.sh' 'prepare-control-plane.sh' 'upgrade-control-plane.sh' 'generated/config/*.example' 'must not read or archive'; do
  require "$value" "$package_workflow"
done
for value in 'releases/latest' "laneway_\${operating_system}_\${architecture}.tar.gz" 'shasum -a 256 -c' 'configure --yes' 'configure --check' 'normal macOS user'; do
  require "$value" "$client_installer"
done
if grep -F "cp -R \"\$project_dir/deploy/.\"" "$package_workflow" >/dev/null; then
  echo "package workflow recursively copies private deployment runtime state" >&2
  exit 1
fi

for value in \
	'os: [linux, darwin]' \
	"dist/laneway_\${{ matrix.os }}_\${{ matrix.arch }}" \
	'laneway_darwin_amd64 laneway_darwin_arm64' \
	'install.sh' \
	'bootstrap-artifacts.toml' \
	'platforms: linux/amd64,linux/arm64' \
  'provenance: mode=max' \
  'sbom: true' \
  'cosign sign' \
  'cosign sign-blob' \
  'actions/attest-build-provenance@' \
  'aquasecurity/trivy-action@' \
  'Extract OCI layout for vulnerability scanning' \
  "tar -xf \"/tmp/\${{ matrix.name }}.oci.tar\" -C \"/tmp/\${{ matrix.name }}.oci\"" \
  "test -f \"/tmp/\${{ matrix.name }}.oci/index.json\"" \
  "input: /tmp/\${{ matrix.name }}.oci" \
  'ignore-unfixed: false' \
  'severity: HIGH,CRITICAL' \
  'version: v0.73.0' \
  'syft-version: v1.50.0' \
  'cosign-release: v3.1.3' \
  'sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6' \
  'docker.io/tonistiigi/binfmt@sha256:' \
  'image=moby/buildkit:buildx-stable-1@sha256:' \
  'image-digests.txt'
do
  require "$value" "$workflow"
done
require 'bootstrap-artifacts.toml image-digests.txt install.sh' "$workflow"

for value in \
  'LANEWAY_CONTROLLER_IMAGE_DIGEST' \
  'LANEWAY_RELAY_IMAGE_DIGEST' \
  'LANEWAY_ADMIN_IMAGE_DIGEST' \
  'LANEWAY_EXIT_NODE_IMAGE_DIGEST'
do
  require "$value" "$compose_file"
done

if grep -E '(^|[[:space:]:@])latest([[:space:]]|$)' "$workflow" >/dev/null; then
  echo "release workflow must not publish or consume a mutable latest tag" >&2
  exit 1
fi

for path in "$dockerfile" "$connector_dockerfile" "$exit_dockerfile"; do
  require '# syntax=docker/dockerfile:1.9@sha256:' "$path"
  require "FROM --platform=\$BUILDPLATFORM golang:1.26-alpine@sha256:" "$path"
  require 'ARG VERSION=dev' "$path"
  require 'ARG TARGETOS' "$path"
  require 'ARG TARGETARCH' "$path"
  require "CGO_ENABLED=0 GOOS=\${TARGETOS} GOARCH=\${TARGETARCH}" "$path"
  require "laneway.dev/laneway/internal/buildinfo.Version=\${VERSION}" "$path"
done
require 'FROM scratch' "$connector_dockerfile"
require 'ENTRYPOINT ["/usr/local/bin/laneway"]' "$connector_dockerfile"
require 'CMD ["connector", "run"]' "$connector_dockerfile"
if grep -E '^RUN apk|/bin/sh|/sbin/tini|/bin/setpriv' "$connector_dockerfile" >/dev/null; then
  echo "scratch Connector image contains an OS package or interactive runtime tool" >&2
  exit 1
fi
require 'FROM alpine:3.23@sha256:' "$exit_dockerfile"
for package in ca-certificates iproute2-minimal nftables procps-ng setpriv tini; do
  if ! grep -E "^[[:space:]]+${package}=[0-9]" "$exit_dockerfile" >/dev/null; then
    echo "Exit Node runtime package is not version-pinned: $package" >&2
    exit 1
  fi
done
require 'libcap-setcap=2.78-r0' "$exit_dockerfile"
require 'setcap cap_net_admin=ep /bin/setpriv' "$exit_dockerfile"
require 'ENTRYPOINT ["/bin/setpriv", "--inh-caps=+net_admin", "--ambient-caps=+net_admin", "--no-new-privs", "/sbin/tini", "--", "/usr/local/bin/laneway", "node", "run"]' "$exit_dockerfile"
require 'CMD ["-config", "/etc/laneway/exit-node.toml"]' "$exit_dockerfile"
require 'LANEWAY_CONNECTOR_IMAGE_DIGEST' "$lane_workflow"
require 'ghcr.io/doout/lane-edge:LANEWAY_CONNECTOR_IMAGE_DIGEST' "$lane_workflow"
require 'ghcr.io/doout/laneway-connector:LANEWAY_EXIT_NODE_IMAGE_DIGEST' "$lane_workflow"
require 'ghcr.io/doout/laneway-exit-node:LANEWAY_EXIT_NODE_IMAGE_DIGEST' "$lane_workflow"
require 'deploy/containers/Dockerfile.connector' "$repo_dir/.github/workflows/ci.yml"
require '! docker run --rm --network none --entrypoint /bin/sh lane-edge:ci -c true' "$repo_dir/.github/workflows/ci.yml"
require './integration/connector-bootstrap.sh lane-edge:ci' "$repo_dir/.github/workflows/ci.yml"
require './integration/connector-upgrade.sh lane-edge:ci' "$repo_dir/.github/workflows/ci.yml"
require './integration/connector-updater.sh' "$repo_dir/.github/workflows/ci.yml"
for value in \
  'releases/latest' \
  'checksums.sigstore.json' \
  'verify-blob' \
  'image-digests.txt' \
  'Connector image signature verification failed' \
  'connector validate --state-dir /var/lib/laneway/connector' \
  'container must mount the named volume' \
  'docker rename' \
  'previous Connector restored'
do
  require "$value" "$connector_updater"
done
require 'deploy/containers/update-connector.sh' "$package_workflow"
require 'laneway-update-connector' "$package_installer"

echo "Release signing, provenance, SBOM, scan, and multi-architecture contract is valid"
