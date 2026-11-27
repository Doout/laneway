#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH='' cd -- "$script_dir/.." && pwd)
version=${VERSION-dev}
package_goos=${PACKAGE_GOOS:-$(uname -s | tr '[:upper:]' '[:lower:]')}
package_goarch=${PACKAGE_GOARCH:-}
if [ -z "$package_goarch" ]; then
  case "$(uname -m)" in
    x86_64) package_goarch=amd64 ;;
    arm64|aarch64) package_goarch=arm64 ;;
    *) package_goarch=$(uname -m) ;;
  esac
fi
package_rust_runtime_dir=${PACKAGE_RUST_RUNTIME_DIR:-}
package_rust_macos=${PACKAGE_RUST_MACOS:-}

case "$package_goos" in linux|darwin) ;; *) echo "unsupported package operating system: $package_goos" >&2; exit 1;; esac
case "$package_goarch" in
  amd64|arm64) ;;
  *)
    echo "unsupported package architecture: $package_goarch" >&2
    exit 1
    ;;
esac
[ -n "$version" ] || { echo "version is empty" >&2; exit 1; }
case "$package_goos" in
  linux)
    [ -n "$package_rust_runtime_dir" ] && [ -z "$package_rust_macos" ] ||
      { echo "Linux packages require PACKAGE_RUST_RUNTIME_DIR (the five static Rust runtimes)" >&2; exit 1; }
    sh "$script_dir/verify-rust-release-runtime.sh" "$package_rust_runtime_dir" "$package_goarch"
    ;;
  darwin)
    [ -n "$package_rust_macos" ] && [ -z "$package_rust_runtime_dir" ] ||
      { echo "macOS packages require PACKAGE_RUST_MACOS (native lanewayd-rs)" >&2; exit 1; }
    sh "$script_dir/verify-rust-macos-runtime.sh" "$package_rust_macos" "$package_goarch"
    ;;
esac
case "$version" in
  *[!0-9A-Za-z._+-]*)
    echo "version contains unsupported characters" >&2
    exit 1
    ;;
esac

staging_dir=$(mktemp -d)
trap 'find "$staging_dir" -depth -delete' EXIT HUP INT TERM
package_dir="$staging_dir/laneway"
archive="laneway_${package_goos}_${package_goarch}.tar.gz"
standalone="laneway_${package_goos}_${package_goarch}"
mkdir -p "$package_dir/bin" "$package_dir/docs" "$project_dir/dist"
if [ "$package_goos" = linux ]; then
	mkdir -p "$package_dir/sbin" "$package_dir/examples" "$package_dir/systemd" \
		"$package_dir/nftables" "$package_dir/spec" "$package_dir/deploy" "$package_dir/integration"
	for runtime in laneway-controller-rs laneway-healthcheck-rs laneway-relay-rs laneway-update-rs lanewayd-rs; do
		install -m 0755 "$package_rust_runtime_dir/$runtime" "$package_dir/sbin/$runtime"
	done
	ln -s lanewayd-rs "$package_dir/sbin/lanewayd"
	cp "$project_dir/docs/rust-runtime-migration.md" "$package_dir/docs/"
	cp "$project_dir/deploy/systemd/laneway-rust-updater.service" \
		"$project_dir/deploy/systemd/laneway-rust-updater.timer" \
		"$project_dir/deploy/systemd/lanewayd-rs.service" \
		"$project_dir/deploy/systemd/laneway-relay-rs.service" "$package_dir/systemd/"
	cp "$project_dir/deploy/examples/managed-updates-rust.toml" \
	  "$project_dir/deploy/examples/node-rust.toml" "$project_dir/deploy/examples/node-rust-controller.toml" \
	  "$project_dir/deploy/examples/relay-rust.toml" "$package_dir/examples/"
else
	install -m 0755 "$package_rust_macos" "$package_dir/bin/lanewayd-rs"
	printf '%s\n' rust-v1 > "$package_dir/macos-runtime"
	cp "$project_dir/docs/rust-runtime-migration.md" "$package_dir/docs/"
fi

case "$package_goos" in
  linux) install -m 0755 "$package_rust_runtime_dir/lanewayd-rs" "$package_dir/bin/laneway" ;;
  darwin) install -m 0755 "$package_rust_macos" "$package_dir/bin/laneway" ;;
esac
ln -s laneway "$package_dir/bin/lane"

cp "$project_dir/README.md" "$package_dir/README.md"
cp "$project_dir/LICENSE-MIT" "$project_dir/LICENSE-APACHE" "$package_dir/"
cp "$project_dir/docs/operations.md" "$package_dir/docs/operations.md"
cp "$project_dir/docs/rootless.md" "$package_dir/docs/rootless.md"
cp "$project_dir/docs/ephemeral-shared-host-exit.md" "$package_dir/docs/ephemeral-shared-host-exit.md"
if [ "$package_goos" = linux ]; then
cp "$project_dir/deploy/examples/controller.toml" \
  "$project_dir/deploy/examples/node-controller.toml" \
  "$project_dir/deploy/examples/node.toml" \
  "$project_dir/deploy/examples/relay-controller.toml" \
	"$project_dir/deploy/examples/relay.toml" \
	"$package_dir/examples/"
cp "$project_dir"/deploy/nftables/* "$package_dir/nftables/"
cp "$project_dir/deploy/README.md" "$package_dir/docs/deployment.md"
cp "$project_dir/docs/benchmarks.md" "$package_dir/docs/benchmarks.md"
cp "$project_dir/docs/node-locations.md" "$package_dir/docs/node-locations.md"
cp "$project_dir/docs/service-certificate-renewal.md" "$package_dir/docs/service-certificate-renewal.md"
cp "$project_dir/docs/rust-controller-node.md" "$package_dir/docs/rust-controller-node.md"
cp "$project_dir/spec/threat-model.md" "$package_dir/docs/threat-model.md"
cp "$project_dir"/spec/*.md "$package_dir/spec/"
# Copy only reviewed deployment sources. Never traverse the ignored Compose
# runtime tree: a package build on an operator host must not read or archive
# .env, generated credentials, databases, or recovery bundles.
for directory in containers ephemeral-exit examples nftables; do
	cp -R "$project_dir/deploy/$directory" "$package_dir/deploy/$directory"
done
cp -R "$package_dir/systemd" "$package_dir/deploy/systemd"
install -m 0644 "$project_dir/deploy/README.md" "$package_dir/deploy/README.md"
install -d -m 0755 "$package_dir/deploy/compose/generated/config"
for name in .env.example README.md compose.dev.yaml compose.rust.yaml compose.yaml laneway-certificate-renewal.service laneway-certificate-renewal.timer; do
	install -m 0644 "$project_dir/deploy/compose/$name" "$package_dir/deploy/compose/$name"
done
for name in bootstrap.sh install-control-plane.sh prepare-control-plane.sh upgrade-control-plane.sh preflight.sh prepare.sh prepare-rust.py recovery.sh validate.sh verify-rust-release.sh laneway-control renew-service-certificates.py; do
	install -m 0755 "$project_dir/deploy/compose/$name" "$package_dir/deploy/compose/$name"
done
install -m 0644 "$project_dir"/deploy/compose/generated/config/*.example \
	"$package_dir/deploy/compose/generated/config/"
cp "$project_dir/integration/README.md" "$package_dir/integration/README.md"
cp "$project_dir/scripts/setup-node.sh" "$package_dir/sbin/laneway-setup-node"
fi
cp "$project_dir/SECURITY.md" "$package_dir/SECURITY.md"
cp "$project_dir/scripts/install-package.sh" "$package_dir/install.sh"
printf '%s\n' "$version" > "$package_dir/VERSION"
find "$package_dir" -type f -exec chmod 0644 {} +
find "$package_dir" -type d -exec chmod 0755 {} +
chmod 0755 "$package_dir/install.sh" "$package_dir/bin/laneway"
if [ "$package_goos" = linux ]; then
	chmod 0755 "$package_dir"/sbin/* "$package_dir"/deploy/compose/*.sh \
		"$package_dir"/deploy/compose/laneway-control \
		"$package_dir"/deploy/containers/update-connector.sh \
		"$package_dir"/deploy/ephemeral-exit/bootstrap.sh
elif [ -n "$package_rust_macos" ]; then
	chmod 0755 "$package_dir/bin/lanewayd-rs"
fi

tmp_archive="$staging_dir/$archive"
if [ "$(uname -s)" = Darwin ]; then
	(
		cd "$staging_dir"
		TZ=UTC find laneway -exec touch -h -t 197001010000.00 {} +
		find laneway -print | LC_ALL=C sort > members
		COPYFILE_DISABLE=1 /usr/bin/tar -cf payload.tar --format ustar --no-recursion \
			--uid 0 --gid 0 --uname root --gname wheel -T members
	)
else
	tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
		-C "$staging_dir" -cf "$staging_dir/payload.tar" laneway
fi
gzip -n < "$staging_dir/payload.tar" > "$tmp_archive"
mv "$tmp_archive" "$project_dir/dist/$archive"
if [ "$package_goos" = darwin ]; then
	cp "$package_dir/bin/laneway" "$project_dir/dist/$standalone"
	chmod 0755 "$project_dir/dist/$standalone"
fi
(
  cd "$project_dir/dist"
  if [ "$(uname -s)" = Darwin ]; then
    shasum -a 256 "$archive" > "$archive.sha256"
  else
    sha256sum "$archive" > "$archive.sha256"
  fi
)
echo "$project_dir/dist/$archive"
