#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
workflow=$repo_dir/.github/workflows/release.yml
dockerfile=$repo_dir/deploy/containers/Dockerfile
exit_dockerfile=$repo_dir/deploy/containers/Dockerfile.exit-node
compose_file=$repo_dir/deploy/compose/compose.yaml
lane_workflow=$repo_dir/deploy/compose/lane

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
  ghcr.io/doout/laneway-exit-node
do
  require "image: $image" "$workflow"
done

for value in 'cosign verify' 'compose_with_env' 'backup_database' 'database was not rolled back'; do
  require "$value" "$lane_workflow"
done

for value in \
  'platforms: linux/amd64,linux/arm64' \
  'provenance: mode=max' \
  'sbom: true' \
  'cosign sign' \
  'cosign sign-blob' \
  'actions/attest-build-provenance@' \
  'aquasecurity/trivy-action@' \
  "input: /tmp/\${{ matrix.name }}.oci.tar" \
  'ignore-unfixed: false' \
  'severity: HIGH,CRITICAL' \
  'version: v0.73.0' \
  'syft-version: v1.50.0' \
  'cosign-release: v3.1.3' \
  'docker.io/tonistiigi/binfmt@sha256:' \
  'image=moby/buildkit:buildx-stable-1@sha256:' \
  'image-digests.txt'
do
  require "$value" "$workflow"
done

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

for path in "$dockerfile" "$exit_dockerfile"; do
  require '# syntax=docker/dockerfile:1.9@sha256:' "$path"
  require "FROM --platform=\$BUILDPLATFORM golang:1.26-alpine@sha256:" "$path"
  require 'ARG VERSION=dev' "$path"
  require 'ARG TARGETOS' "$path"
  require 'ARG TARGETARCH' "$path"
  require "CGO_ENABLED=0 GOOS=\${TARGETOS} GOARCH=\${TARGETARCH}" "$path"
  require "laneway.dev/laneway/internal/buildinfo.Version=\${VERSION}" "$path"
done
require 'FROM alpine:3.23@sha256:' "$exit_dockerfile"
for package in ca-certificates iproute2-minimal nftables procps-ng setpriv tini; do
  if ! grep -E "^[[:space:]]+${package}=[0-9]" "$exit_dockerfile" >/dev/null; then
    echo "Exit Node runtime package is not version-pinned: $package" >&2
    exit 1
  fi
done

echo "Release signing, provenance, SBOM, scan, and multi-architecture contract is valid"
