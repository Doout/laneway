#!/bin/sh
# Contract patterns match literal shell variables and workflow expressions in source.
# shellcheck disable=SC2016
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
workflow=$repo_dir/.github/workflows/release.yml
ci_workflow=$repo_dir/.github/workflows/ci.yml
node_workflow=$repo_dir/.github/workflows/node.yml
dockerignore=$repo_dir/.dockerignore
gitignore=$repo_dir/.gitignore
compose_gitignore=$repo_dir/deploy/compose/.gitignore
dockerfile=$repo_dir/deploy/containers/Dockerfile
connector_dockerfile=$repo_dir/deploy/containers/Dockerfile.connector
exit_dockerfile=$repo_dir/deploy/containers/Dockerfile.exit-node
connector_updater=$repo_dir/deploy/containers/update-connector.sh
compose_file=$repo_dir/deploy/compose/compose.yaml
compose_dev_file=$repo_dir/deploy/compose/compose.dev.yaml
docker_exit_integration=$repo_dir/integration/docker-exit-node.sh
console_image_boundary=$repo_dir/integration/console-image-boundary.sh
administrator_lifecycle=$repo_dir/integration/administrator-lifecycle.sh
control_plane_bootstrap=$repo_dir/integration/control-plane-bootstrap.sh
control_plane_outer_installer=$repo_dir/integration/control-plane-outer-installer.sh
control_plane_upgrade=$repo_dir/integration/control-plane-upgrade.sh
control_plane_release_fixtures=$repo_dir/integration/fixtures/control-plane-release
lane_workflow=$repo_dir/deploy/compose/laneway-control
bootstrap_workflow=$repo_dir/deploy/compose/bootstrap.sh
prepare_workflow=$repo_dir/deploy/compose/prepare.sh
recovery_workflow=$repo_dir/deploy/compose/recovery.sh
installer=$repo_dir/deploy/compose/install-control-plane.sh
preparer=$repo_dir/deploy/compose/prepare-control-plane.sh
upgrader=$repo_dir/deploy/compose/upgrade-control-plane.sh
package_workflow=$repo_dir/scripts/package.sh
package_installer=$repo_dir/scripts/install-package.sh
client_installer=$repo_dir/install.sh
web_package=$repo_dir/web/package.json
vite_config=$repo_dir/web/vite.config.ts
playwright_config=$repo_dir/web/playwright.config.ts
control_plane=$repo_dir/web/src/lib/control-plane.tsx

require() {
  pattern=$1
  path=$2
  if ! grep -F -- "$pattern" "$path" >/dev/null; then
    echo "release contract is missing '$pattern' in ${path#"$repo_dir"/}" >&2
    exit 1
  fi
}

require_line() {
  pattern=$1
  path=$2
  if ! grep -Fx -- "$pattern" "$path" >/dev/null; then
    echo "release contract is missing exact line '$pattern' in ${path#"$repo_dir"/}" >&2
    exit 1
  fi
}

require_release_target() {
  image=$1
  expected=$2
  actual=$(awk -v image="$image" '
    $1 == "image:" { active = ($2 == image); next }
    active && $1 == "target:" { print $2; exit }
  ' "$workflow")
  if [ "$actual" != "$expected" ]; then
    echo "release image $image selects Docker target ${actual:-none}, want $expected" >&2
    exit 1
  fi
}

require_compose_target() {
  service=$1
  target=$2
  if ! awk -v service="  $service:" -v target="      target: $target" '
    $0 == service { active = 1; next }
    active && $0 ~ /^  [^[:space:]][^:]*:[[:space:]]*$/ { active = 0 }
    active && $0 == target { found = 1 }
    END { exit found ? 0 : 1 }
  ' "$compose_dev_file"; then
    echo "development Compose service $service does not select Docker target $target" >&2
    exit 1
  fi
}

require_fixture_sha256() {
  expected=$1
  path=$2
  actual=$(sha256sum "$path" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    echo "saved release fixture ${path#"$repo_dir"/} has digest $actual, want $expected" >&2
    exit 1
  fi
}

# Release credentials can publish packages and attestations, so every external
# action is fixed to an immutable commit instead of a mutable tag or branch.
if sed -n 's/^[[:space:]]*- uses: \([^ #]*\).*/\1/p' "$workflow" "$node_workflow" |
  grep -Ev '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$' >/dev/null; then
  echo "release workflow contains an action that is not pinned to a full commit" >&2
  exit 1
fi

require 'uses: ./.github/workflows/node.yml' "$workflow"
require 'uses: ./.github/workflows/node.yml' "$ci_workflow"
require 'needs: [package, image, native-node]' "$workflow"
require 'name: package-relay-${{ matrix.platform.asset }}' "$node_workflow"
require 'name: package-relay-linux_${{ matrix.arch }}' "$workflow"
require 'pattern: laneway-*' "$workflow"
require 'dist/lanewayd_*' "$workflow"
require 'dist/laneway-native_*' "$workflow"
require 'dist/laneway-compat_*' "$workflow"
require 'install-node.sh install-node.ps1 lanewayd_*' "$workflow"
require 'laneway_linux_amd64 laneway_linux_arm64 laneway_darwin_amd64 laneway_darwin_arm64 laneway_windows_*.exe' "$workflow"
require 'dist/laneway_linux_amd64' "$workflow"
require 'dist/laneway_linux_arm64' "$workflow"
require 'dist/laneway_windows_*.exe' "$workflow"
require 'target: x86_64-unknown-linux-musl, asset: linux_amd64' "$node_workflow"
require 'target: aarch64-unknown-linux-musl, asset: linux_arm64' "$node_workflow"
for target in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64 windows_arm64
do
  require "asset: $target" "$node_workflow"
done

for image in \
  ghcr.io/doout/laneway-controller \
  ghcr.io/doout/laneway-relay \
  ghcr.io/doout/laneway-admin \
  ghcr.io/doout/lane-edge \
  ghcr.io/doout/laneway-exit-node
do
  require "image: $image" "$workflow"
done
require_release_target ghcr.io/doout/laneway-controller controller
require_release_target ghcr.io/doout/laneway-relay relay
require_release_target ghcr.io/doout/laneway-admin admin
if grep -F 'BINARY=' "$workflow" >/dev/null || grep -F 'matrix.binary' "$workflow" >/dev/null; then
  echo "release images must use fixed Docker targets instead of a free-form binary argument" >&2
  exit 1
fi
release_target_expression="target: \${{ matrix.target }}"
if [ "$(grep -Fc "$release_target_expression" "$workflow")" -ne 2 ]; then
  echo "release scan and publication builds must both select the matrix Docker target" >&2
  exit 1
fi

for value in 'production-check' 'production-verified' 'cosign_command' 'compose_with_env' 'compose_file_with_env' 'backup_recovery' 'create_release_database_snapshot' 'restore_release_database_snapshot' 'publish_previous_release' 'load_previous_release' 'previous images, configuration, and database restored' 'run_update' 'releases/latest' 'verify-blob' 'administrator bootstrap --username USERNAME' 'administrator recover --username USERNAME' 'administrator root-token rotate' 'committed_pending_complete' '--force-recreate --no-deps controller' '--admin-token-file' 'DOCKER_CONFIG' 'docker --context default' 'unset DOCKER_DEFAULT_PLATFORM' 'LANEWAY_BIND_ADDRESS must be a canonical IPv4 address' 'LANEWAY_IPV4_POOL must be a canonical routable IPv4 /8 through /30' 'distinct nonzero 32-character lowercase hex values' 'LANEWAY_NETWORK_NAME must be 1 through 253 bytes'; do
  require "$value" "$lane_workflow"
done
for value in \
  'user-token|api-token) acquire_lock; run_user_token "$@" ;;' \
  'invite) acquire_lock; run_invite "$@" ;;' \
  'route) acquire_lock; run_route "$@" ;;' \
  'run_status "$@"' \
  'production-check) acquire_lock; run_production_check "$@" ;;'
do
  require "$value" "$lane_workflow"
done
# The release contract intentionally searches for escaped variables inside the
# generated Connector bootstrap heredoc.
for value in \
  'for docker_override in DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_TLS DOCKER_CONFIG' \
  '[[ ! -v \$docker_override ]] || die "\$docker_override is not allowed for Connector bootstrap"' \
  'docker --context default pull' \
  'temporary_parent=/var/tmp'
do
  require "$value" "$lane_workflow"
done
for value in 'pki verify-authority' 'offline root private key ca.key must never' 'chown 65532:65532' '[controller.initial_network]' 'LANEWAY_NETWORK_NAME' 'LANEWAY_IPV4_POOL'; do
  require "$value" "$prepare_workflow"
done
for value in 'age --encrypt' 'age --decrypt' 'unexpected recovery archive entry' 'generated/recovery' 'chown 0:0'; do
  require "$value" "$recovery_workflow"
done
for value in 'Release tag' 'image-digests.txt' 'release checksum signature verification failed' 'PRODUCTION-CHECKLIST.md' 'LANEWAY_INSTALL_PROFILE' 'does not edit the host' 'prepare-control-plane.sh' 'initial encrypted backup' 'control-plane.answers' 'save_answers'; do
  require "$value" "$installer"
done
for value in '/dev/shm' '1777:0:0' 'root-owned sticky real tmpfs' 'offline-root.tar.age' 'control-plane-input' 'pki verify-authority' 'Never copy laneway-recovery.identity'; do
  require "$value" "$preparer"
done
for value in 'generated/lifecycle' 'image-digests.txt' 'LANEWAY_BOOTSTRAP_ARTIFACTS_FILE' 'laneway-control upgrade' 'host networking remain unchanged' '[controller.initial_network]' 'LANEWAY_NETWORK_NAME' 'LANEWAY_IPV4_POOL' 'DOCKER_CONFIG' 'docker --context default compose' 'observer lifecycle lock handoff is valid only for verified-package preflight' 'mutating upgrade lock handoff requires the owner role' 'LANEWAY_DEPLOY_DIR must be a canonical safe absolute path' 'LANEWAY_DEPLOY_DIR must identify its exact physical real directory' 'pwd -P' 'temporary_parent=/var/tmp' 'laneway-control-upgrade.XXXXXX'; do
  require "$value" "$upgrader"
done
for value in 'controller network get' 'did not expose configured initial network' 'controller relay register' 'DOCKER_CONFIG' 'docker --context default compose'; do
  require "$value" "$bootstrap_workflow"
done
if grep -F 'controller network create' "$bootstrap_workflow" >/dev/null; then
  echo "post-health bootstrap must not duplicate controller-owned initial-network creation" >&2
  exit 1
fi
if grep -F 'controller network list' "$bootstrap_workflow" >/dev/null; then
  echo "initial-network verification must use exact lookup, not a fixed-size list" >&2
  exit 1
fi
for value in '.env.example' 'install-control-plane.sh' 'prepare-control-plane.sh' 'upgrade-control-plane.sh' 'generated/config/*.example' 'must not read or archive'; do
  require "$value" "$package_workflow"
done
require 'CONTROL-PLANE-UPGRADE-PREFLIGHT' "$package_workflow"
require 'laneway-control-upgrade-preflight-v1' "$package_workflow"
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
  require 'cargo build --manifest-path rust/Cargo.toml --locked --release -p laneway-healthcheck' "$path"
  require 'cargo build --manifest-path rust/Cargo.toml --locked --release -p laneway-cli' "$path"
  require 'COPY --from=build-cli /src/rust/target/release/laneway /usr/local/bin/laneway' "$path"
  require 'go build -tags laneway_compat -trimpath' "$path"
  require '/out/laneway-compat /usr/local/bin/laneway-compat' "$path"
  require 'COPY --from=build-healthcheck /src/rust/target/release/laneway-healthcheck /usr/local/bin/laneway-healthcheck' "$path"
  if grep -F './cmd/laneway-healthcheck' "$path" >/dev/null; then
    echo "production packaging still builds the Go healthcheck in ${path#"$repo_dir"/}" >&2
    exit 1
  fi
done
require 'RUN pnpm build:live' "$dockerfile"
require 'FROM scratch AS runtime' "$dockerfile"
require 'FROM runtime AS controller' "$dockerfile"
require 'FROM runtime AS relay' "$dockerfile"
require 'FROM runtime AS admin' "$dockerfile"
require 'FROM build-base AS build-controller' "$dockerfile"
require 'AS build-relay' "$dockerfile"
require 'FROM scratch AS relay-package' "$dockerfile"
require 'FROM relay-package AS linux-package' "$dockerfile"
require 'FROM build-base AS build-admin' "$dockerfile"
require "test \"\${BINARY}\" = laneway-controller" "$dockerfile"
require "test \"\${BINARY}\" = laneway-relay" "$dockerfile"
require "test \"\${BINARY}\" = laneway" "$dockerfile"
require '-o /out/laneway ./cmd/laneway-controller' "$dockerfile"
require 'cargo build --manifest-path rust/Cargo.toml --locked --release -p laneway-relay' "$dockerfile"
require 'cargo build --manifest-path rust/Cargo.toml --locked --release -p lanewayd' "$dockerfile"
require 'COPY --from=relay-package /laneway-relay /usr/local/bin/laneway' "$dockerfile"
require 'COPY --from=build-node /src/rust/target/release/lanewayd /lanewayd' "$dockerfile"
require 'COPY --from=build-node /src/rust/target/release/laneway /laneway' "$dockerfile"
require '--target linux-package' "$package_workflow"
require 'Test Rust relay and healthcheck' "$workflow"
require '"$cli" _network-helper-native --version' "$workflow"
require '"$compat" _network-helper-bridge-version' "$workflow"
require 'Verify packaged Rust executables' "$workflow"
require 'Exercise the release utun helper with the Go client' "$node_workflow"
require 'TestDarwinNativeHelper' "$node_workflow"
require 'for command in laneway-relay laneway-controller lanewayd' "$package_installer"
require_line 'ExecStart=/usr/local/bin/laneway node run -config /etc/laneway/laneway.toml' "$repo_dir/deploy/systemd/lanewayd.service"
require_line 'ExecStart=/usr/local/sbin/lanewayd run --system --config /etc/laneway/node-rust.toml' "$repo_dir/deploy/systemd/lanewayd-rs.service"
require "python3 integration/rootless.py --bin-dir \"\$bins\" --public-https" "$node_workflow"
for source in "$dockerfile" "$package_workflow" "$node_workflow"; do
  if grep -F './cmd/laneway-relay' "$source" >/dev/null; then
    echo "production packaging still builds the retired Go relay in ${source#"$repo_dir"/}" >&2
    exit 1
  fi
done
require 'go build -tags laneway_compat -trimpath -ldflags "$ldflags" -o "$package_dir/bin/laneway-compat"' "$package_workflow"
require 'go build -trimpath -ldflags "$ldflags" -o "$staging_dir/$standalone"' "$package_workflow"
require '--bin laneway-compat-windows --features windows-compat --target "$TARGET"' "$node_workflow"
require 'cp "rust/target/$TARGET/release/laneway-compat-windows.exe" "dist/$COMPAT_ASSET"' "$node_workflow"
require 'laneway-compat-windows.exe rust/target/debug/laneway-compat.exe' "$repo_dir/Makefile"
require 'Assert-NativeCompanion' "$repo_dir/integration/node-install-windows.ps1"
require 'go build -tags laneway_compat -trimpath' "$node_workflow"
require 'go build -trimpath -ldflags "-s -w -X laneway.dev/laneway/internal/buildinfo.Version=$version" -o "../dist/$LEGACY_ASSET"' "$node_workflow"
require 'go build -tags laneway_compat -ldflags' "$ci_workflow"
require '-o "$bins/laneway-go-reference" ./cmd/laneway' "$ci_workflow"
require '"$script_dir/bin/laneway" configure --system --yes' "$package_installer"
require '-o /out/laneway-compat ./cmd/laneway' "$dockerfile"
require 'bin/laneway-compat' "$package_workflow"
require 'bin/laneway-compat' "$package_installer"
console_copy_stage=$(awk '/^FROM / { stage = $NF } /^COPY --from=console / { print stage }' "$dockerfile")
if [ "$console_copy_stage" != controller ]; then
  echo "console assets must be copied exactly once and only by the controller target" >&2
  exit 1
fi
if [ "$(awk '/^FROM / { stage = $NF } END { print stage }' "$dockerfile")" != relay ]; then
  echo "the shared Dockerfile default target must preserve the historical relay image" >&2
  exit 1
fi
require_compose_target controller controller
require_compose_target relay relay
require_compose_target admin admin
if grep -F 'BINARY:' "$compose_dev_file" >/dev/null ||
  grep -F -- '--build-arg BINARY=' "$docker_exit_integration" >/dev/null ||
  grep -F -- '--build-arg BINARY=' "$ci_workflow" >/dev/null; then
  echo "development and integration image builds must use fixed Docker targets" >&2
  exit 1
fi
require '--target controller' "$docker_exit_integration"
require '--target relay' "$docker_exit_integration"
require '--target admin' "$docker_exit_integration"
require '"dev": "vite --mode demo"' "$web_package"
require '"build": "vite build"' "$web_package"
require '"build:live": "tsc -b && vite build --mode live"' "$web_package"
require '"build:demo": "tsc -b && vite build --mode demo"' "$web_package"
require "mode !== 'live' && mode !== 'demo'" "$vite_config"
require 'parseConsoleBuildMode(import.meta.env.MODE)' "$control_plane"
require "sourcemap: mode === 'demo'" "$vite_config"
require "command: 'corepack pnpm preview --host 127.0.0.1'" "$playwright_config"
require 'reuseExistingServer: false' "$playwright_config"
for value in '.laneway' '**/*.key' '**/*.pem' '**/laneway-recovery.identity' 'laneway-recovery-kit-*' 'web/.env*' 'deploy/compose/.env' 'deploy/compose/generated'; do
  require_line "$value" "$dockerignore"
done
for value in '.laneway/' '*.key' '*.pem' '**/laneway-recovery.identity' 'laneway-recovery-kit-*/' 'web/.env*' '!web/.env.example' 'deploy/compose/.env'; do
  require_line "$value" "$gitignore"
done
for value in 'generated/backups/' 'generated/config/*.toml' 'generated/pki/' 'generated/secrets/' 'generated/lifecycle/' 'generated/recovery/' 'generated/.prepare.*' 'generated/.recovery-backup.*' '!generated/config/*.example'; do
  require_line "$value" "$compose_gitignore"
done
require 'FROM scratch' "$connector_dockerfile"
require 'HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=6' "$connector_dockerfile"
require 'CMD ["/usr/local/bin/laneway-healthcheck", "-unix", "/run/laneway/lanewayd.sock"]' "$connector_dockerfile"
require 'ENTRYPOINT ["/usr/local/bin/laneway"]' "$connector_dockerfile"
require 'CMD ["connector", "run"]' "$connector_dockerfile"
if awk '/^FROM / { runtime = ($2 == "scratch") } runtime' "$connector_dockerfile" |
  grep -E '^RUN apk|/bin/sh|/sbin/tini|/bin/setpriv' >/dev/null; then
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
require 'ghcr.io/doout/laneway-connector' "$lane_workflow"
require 'ghcr.io/doout/laneway-exit-node' "$lane_workflow"
require 'deploy/containers/Dockerfile.connector' "$ci_workflow"
require 'if corepack pnpm build; then' "$ci_workflow"
require 'corepack pnpm build:demo' "$ci_workflow"
require 'corepack pnpm build:live' "$ci_workflow"
require 'LANEWAY_EXPECTED_BUILD_MODE=demo corepack pnpm test:e2e' "$ci_workflow"
require 'LANEWAY_EXPECTED_BUILD_MODE=live corepack pnpm exec playwright test e2e/build-mode.spec.ts' "$ci_workflow"
require '--target controller --build-arg VERSION=ci' "$ci_workflow"
require '--target relay --build-arg VERSION=ci' "$ci_workflow"
require '--target admin --build-arg VERSION=ci' "$ci_workflow"
require 'docker run --rm --network none laneway-controller:ci -version' "$ci_workflow"
require 'docker run --rm --network none laneway-relay:ci -version' "$ci_workflow"
require './integration/console-image-boundary.sh laneway-controller:ci laneway-relay:ci laneway-admin:ci lane-edge:ci laneway-exit-node:ci' "$ci_workflow"
require 'if docker run --rm --network none --entrypoint /bin/sh lane-edge:ci -c true; then' "$ci_workflow"
require './integration/connector-bootstrap.sh lane-edge:ci' "$ci_workflow"
require './integration/connector-upgrade.sh lane-edge:ci' "$ci_workflow"
require './integration/connector-updater.sh' "$ci_workflow"
require './integration/administrator-lifecycle.sh' "$ci_workflow"
require 'shellcheck ./integration/control-plane-bootstrap.sh' "$ci_workflow"
require './integration/control-plane-bootstrap.sh' "$ci_workflow"
require './integration/control-plane-outer-installer.sh' "$ci_workflow"
require 'integration/control-plane-outer-installer.sh' "$workflow"
require 'integration/control-plane-bootstrap.sh integration/release-contract.sh integration/control-plane-outer-installer.sh' "$workflow"
if ! grep -Eq '^[[:space:]]+\./integration/control-plane-bootstrap\.sh[[:space:]]*$' "$ci_workflow" ||
  ! grep -Eq '^[[:space:]]+\./integration/control-plane-bootstrap\.sh[[:space:]]*$' "$workflow"; then
  echo "control-plane bootstrap integration must execute in CI and release verification" >&2
  exit 1
fi
# The single quotes intentionally preserve the literal workflow `$PATH`.
if ! grep -Eq '^[[:space:]]+sudo env PATH="\$PATH" \./integration/control-plane-outer-installer\.sh[[:space:]]*$' "$ci_workflow" ||
  ! grep -Eq '^[[:space:]]+sudo env PATH="\$PATH" \./integration/control-plane-outer-installer\.sh[[:space:]]*$' "$workflow"; then
  echo "outer control-plane installer integration must execute in CI and release verification" >&2
  exit 1
fi
if ! grep -Eq '^[[:space:]]+\./integration/administrator-lifecycle\.sh[[:space:]]*$' "$ci_workflow" ||
  ! grep -Eq '^[[:space:]]+\./integration/administrator-lifecycle\.sh[[:space:]]*$' "$workflow"; then
  echo "administrator lifecycle integration must execute in CI and release verification" >&2
  exit 1
fi
if [ ! -x "$console_image_boundary" ]; then
  echo "console image boundary integration check must be executable" >&2
  exit 1
fi
if [ ! -x "$administrator_lifecycle" ]; then
  echo "administrator lifecycle integration check must be executable" >&2
  exit 1
fi
if [ ! -x "$control_plane_bootstrap" ]; then
  echo "control-plane bootstrap integration check must be executable" >&2
  exit 1
fi
if [ ! -x "$control_plane_outer_installer" ]; then
  echo "outer control-plane installer integration check must be executable" >&2
  exit 1
fi
for value in 'DOCKER_CONFIG' 'COMPOSE_PROJECT_NAME' 'TAR_OPTIONS' 'TUF_MIRROR' \
  'temporary_tree_snapshot' 'LANEWAY_UPGRADE_PREFLIGHT_ONLY' 'operator.lock' \
  'CONTROL-PLANE-UPGRADE-PREFLIGHT' 'laneway-control-upgrade-preflight-v1' \
  'legacy-updater-invoked' 'caller-path-tool' 'LANEWAY_OUTER_TEST_COSIGN_FAIL'; do
  require "$value" "$control_plane_outer_installer"
done
for value in 'LANE_TEST_REQUIRE_LOCK' 'did not expose configured initial network' '<network> <create>' 'root-bearer-must-not-be-logged' 'operator.lock'; do
  require "$value" "$control_plane_bootstrap"
done
for value in 'COMPOSE_PROJECT_NAME' 'COMPOSE_PROFILES' 'managed_keys=' 'legacy-no-connector.env' 'LANE_TEST_ASSERT_COMPOSE_ENV_CLEAN' 'LANE_TEST_ASSERT_DOCKER_CONTEXT' 'zero-network-id' 'long-network-name'; do
  require "$value" "$control_plane_bootstrap"
done
for value in 'release_fixture_dir=' 'for saved_tag in v0.2.17 v0.2.18 v0.2.53 v0.2.54' 'LANEWAY_LIFECYCLE_LOCK_TOKEN' 'strict legacy image repository'; do
  require "$value" "$control_plane_upgrade"
done

# These are byte-exact Compose snapshots from the named repository tags. The
# paired environments preserve the installer schema at each image transition;
# v0.2.18 is explicitly synthetic because that tag had no published assets.
require_fixture_sha256 eab30b9d2fd1c2eafb06e1426ba58b76fa0bf23beae6895924132d91f62bcc68 \
  "$control_plane_release_fixtures/v0.2.17/compose.yaml"
require_fixture_sha256 8a4f17fc88dca8179c07773acd6257d1ea262b4176a0048ef2da8377cff30aa2 \
  "$control_plane_release_fixtures/v0.2.18/compose.yaml"
require_fixture_sha256 0ac856f2ce0001e65b807ba03e49be1bb0875fef68a1ae2a53405259238f6ce5 \
  "$control_plane_release_fixtures/v0.2.53/compose.yaml"
require_fixture_sha256 471293b58367be93b232f6a13fbcc8ce708bbab690721a03c19216987e063e81 \
  "$control_plane_release_fixtures/v0.2.54/compose.yaml"
for fixture_tag in v0.2.17 v0.2.18 v0.2.53 v0.2.54; do
  fixture_env=$control_plane_release_fixtures/$fixture_tag/release.env
  fixture_compose=$control_plane_release_fixtures/$fixture_tag/compose.yaml
  test -f "$fixture_env" && test -f "$fixture_compose"
  grep -Fx "LANEWAY_VERSION=${fixture_tag#v}" "$fixture_env" >/dev/null
  if grep -Ev '^(#.*|[[:space:]]*|[A-Z][A-Z0-9_]*=[A-Za-z0-9._:/+-]+)$' "$fixture_env" >/dev/null; then
    echo "saved release environment $fixture_tag is not canonical" >&2
    exit 1
  fi
done
grep -F 'image: ghcr.io/doout/laneway-exit-node:' "$control_plane_release_fixtures/v0.2.17/compose.yaml" >/dev/null
for fixture_tag in v0.2.18 v0.2.53; do
  grep -F 'image: ghcr.io/doout/laneway-connector:' "$control_plane_release_fixtures/$fixture_tag/compose.yaml" >/dev/null
  if grep -q '^LANEWAY_CONNECTOR_IMAGE_DIGEST=' "$control_plane_release_fixtures/$fixture_tag/release.env"; then
    echo "$fixture_tag unexpectedly uses the five-image environment schema" >&2
    exit 1
  fi
done
grep -F 'image: ghcr.io/doout/laneway-exit-node:' "$control_plane_release_fixtures/v0.2.54/compose.yaml" >/dev/null
grep -q '^LANEWAY_CONNECTOR_IMAGE_DIGEST=' "$control_plane_release_fixtures/v0.2.54/release.env"
for value in 'LANE_TEST_FAIL_NEW_AUTH' 'LANE_TEST_FAIL_COMPLETE' 'operator.lock' 'committed_pending_complete' '.admin.token.rotate.orphan'; do
  require "$value" "$administrator_lifecycle"
done
for value in \
  'releases/latest' \
  'checksums.sigstore.json' \
  'verify-blob' \
  'image-digests.txt' \
  'Connector image signature verification failed' \
  'connector validate --state-dir /var/lib/laneway/connector' \
  'container must mount the named volume' \
  'docker --context default rename' \
  'DOCKER_CONFIG' \
  'unset DOCKER_DEFAULT_PLATFORM' \
  'curl --disable' \
  'temporary_parent=/var/tmp' \
  'previous Connector restored'
do
  require "$value" "$connector_updater"
done
require 'deploy/containers/update-connector.sh' "$package_workflow"
require 'laneway-update-connector' "$package_installer"
require "cp \"\$project_dir/install.sh\" \"\$package_dir/install-control-plane-release.sh\"" "$package_workflow"
require "install -m 0755 \"\$script_dir/install-control-plane-release.sh\" \"\$sharedir/install-control-plane-release.sh\"" "$package_installer"
require 'TAR_OPTIONS is not allowed' "$lane_workflow"
require 'TAR_OPTIONS is not allowed' "$preparer"
require 'TAR_OPTIONS is not allowed' "$recovery_workflow"
require 'TAR_OPTIONS is not allowed' "$upgrader"
require 'curl --disable' "$lane_workflow"
require 'curl --disable' "$upgrader"

echo "Release signing, provenance, SBOM, scan, and multi-architecture contract is valid"
