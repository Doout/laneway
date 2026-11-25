#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH='' cd -- "$script_dir/.." && pwd)
version=${VERSION-dev}
package_goos=${PACKAGE_GOOS:-$(cd "$project_dir/go" && go env GOOS)}
package_goarch=${PACKAGE_GOARCH:-$(cd "$project_dir/go" && go env GOARCH)}

case "$package_goos" in linux|darwin) ;; *) echo "unsupported package operating system: $package_goos" >&2; exit 1;; esac
case "$package_goarch" in
  amd64|arm64) ;;
  *)
    echo "unsupported package architecture: $package_goarch" >&2
    exit 1
    ;;
esac
[ -n "$version" ] || { echo "version is empty" >&2; exit 1; }
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
fi

ldflags="-s -w -X laneway.dev/laneway/internal/buildinfo.Version=$version"
native_dir=${PACKAGE_NATIVE_DIR:-}
(
  cd "$project_dir/go"
  if [ -z "$native_dir" ]; then
    CGO_ENABLED=0 GOOS="$package_goos" GOARCH="$package_goarch" \
      go build -tags laneway_compat -trimpath -ldflags "$ldflags" -o "$package_dir/bin/laneway-compat" ./cmd/laneway
  fi
  CGO_ENABLED=0 GOOS="$package_goos" GOARCH="$package_goarch" \
    go build -trimpath -ldflags "$ldflags" -o "$staging_dir/$standalone" ./cmd/laneway
	ln -s laneway "$package_dir/bin/lane"
	if [ "$package_goos" = linux ]; then
		CGO_ENABLED=0 GOOS="$package_goos" GOARCH="$package_goarch" \
			go build -trimpath -ldflags "$ldflags" -o "$package_dir/sbin/laneway-controller" ./cmd/laneway-controller
	fi
)

if [ -n "$native_dir" ]; then
  platform=${package_goos}_${package_goarch}
  install -m 0755 "$native_dir/laneway-native_$platform" "$package_dir/bin/laneway"
  install -m 0755 "$native_dir/laneway-compat_$platform" "$package_dir/bin/laneway-compat"
  if [ "$package_goos" = linux ]; then
    install -m 0755 "$native_dir/lanewayd_$platform" "$package_dir/sbin/lanewayd"
    install -m 0755 "$native_dir/laneway-relay" "$package_dir/sbin/laneway-relay"
  else
    install -m 0755 "$native_dir/lanewayd_$platform" "$package_dir/bin/lanewayd"
  fi
elif [ "$package_goos" = linux ]; then
	docker buildx build --platform "linux/$package_goarch" \
		--file "$project_dir/deploy/containers/Dockerfile" --target linux-package \
		--build-arg "VERSION=$version" --output "type=local,dest=$package_dir/sbin" "$project_dir"
	mv "$package_dir/sbin/laneway" "$package_dir/bin/laneway"
else
	mac_cli=${PACKAGE_MAC_CLI:-}
	mac_node=${PACKAGE_MAC_NODE:-}
	if [ -z "$mac_cli" ] && [ -z "$mac_node" ]; then
		case "$package_goarch" in
			amd64) target=x86_64-apple-darwin ;;
			arm64) target=aarch64-apple-darwin ;;
		esac
		if [ "$(uname -s)" != Darwin ]; then
			echo "Darwin packages built on Linux require PACKAGE_MAC_CLI and PACKAGE_MAC_NODE" >&2
			exit 1
		fi
		LANEWAY_CLI_RELEASE_VERSION="$version" LANEWAY_NODE_RELEASE_VERSION="$version" \
			MACOSX_DEPLOYMENT_TARGET=12.0 CARGO_PROFILE_RELEASE_STRIP=symbols \
			cargo build --manifest-path "$project_dir/rust/Cargo.toml" \
				--target-dir "$project_dir/rust/target" --target "$target" --locked --release \
				-p laneway-cli -p lanewayd
		mac_cli="$project_dir/rust/target/$target/release/laneway"
		mac_node="$project_dir/rust/target/$target/release/lanewayd"
	fi
	if [ ! -f "$mac_cli" ] || [ ! -f "$mac_node" ]; then
		echo "Darwin packages require both PACKAGE_MAC_CLI and PACKAGE_MAC_NODE" >&2
		exit 1
	fi
	install -m 0755 "$mac_cli" "$package_dir/bin/laneway"
	install -m 0755 "$mac_node" "$package_dir/bin/lanewayd"
fi

cp "$project_dir/README.md" "$package_dir/README.md"
cp "$project_dir/LICENSE-MIT" "$project_dir/LICENSE-APACHE" "$package_dir/"
cp "$project_dir/docs/operations.md" "$package_dir/docs/operations.md"
if [ "$package_goos" = linux ]; then
cp "$project_dir/deploy/examples/controller.toml" \
  "$project_dir/deploy/examples/node-controller.toml" \
  "$project_dir/deploy/examples/node.toml" \
  "$project_dir/deploy/examples/relay-controller.toml" \
	"$project_dir/deploy/examples/relay.toml" \
	"$package_dir/examples/"
cp "$project_dir/deploy/systemd/lanewayd.service" \
  "$project_dir/deploy/systemd/lanewayd-rs.service" \
  "$project_dir/deploy/systemd/laneway-relay.service" \
  "$project_dir/deploy/systemd/laneway-controller.service" \
  "$package_dir/systemd/"
cp "$project_dir"/deploy/nftables/* "$package_dir/nftables/"
cp "$project_dir/deploy/README.md" "$package_dir/docs/deployment.md"
cp "$project_dir/docs/benchmarks.md" "$package_dir/docs/benchmarks.md"
cp "$project_dir/docs/rust-controller-node.md" "$package_dir/docs/rust-controller-node.md"
cp "$project_dir/spec/threat-model.md" "$package_dir/docs/threat-model.md"
cp "$project_dir"/spec/*.md "$package_dir/spec/"
# Copy only reviewed deployment sources. Never traverse the ignored Compose
# runtime tree: a package build on an operator host must not read or archive
# .env, generated credentials, databases, or recovery bundles.
for directory in containers examples nftables systemd; do
	cp -R "$project_dir/deploy/$directory" "$package_dir/deploy/$directory"
done
install -m 0644 "$project_dir/deploy/README.md" "$package_dir/deploy/README.md"
install -d -m 0755 "$package_dir/deploy/compose/generated/config"
for name in .env.example README.md compose.dev.yaml compose.yaml; do
	install -m 0644 "$project_dir/deploy/compose/$name" "$package_dir/deploy/compose/$name"
done
for name in bootstrap.sh install-control-plane.sh prepare-control-plane.sh upgrade-control-plane.sh preflight.sh prepare.sh recovery.sh validate.sh laneway-control; do
	install -m 0755 "$project_dir/deploy/compose/$name" "$package_dir/deploy/compose/$name"
done
install -m 0644 "$project_dir"/deploy/compose/generated/config/*.example \
	"$package_dir/deploy/compose/generated/config/"
cp "$project_dir/integration/README.md" "$package_dir/integration/README.md"
cp "$project_dir/scripts/setup-node.sh" "$package_dir/sbin/laneway-setup-node"
cp "$project_dir/install.sh" "$package_dir/install-control-plane-release.sh"
fi
cp "$project_dir/SECURITY.md" "$package_dir/SECURITY.md"
cp "$project_dir/scripts/install-package.sh" "$package_dir/install.sh"
printf '%s\n' "$version" > "$package_dir/VERSION"
if [ "$package_goos" = linux ]; then
	printf '%s\n' laneway-control-upgrade-preflight-v1 > \
		"$package_dir/CONTROL-PLANE-UPGRADE-PREFLIGHT"
fi
find "$package_dir" -type f -exec chmod 0644 {} +
find "$package_dir" -type d -exec chmod 0755 {} +
chmod 0755 "$package_dir/install.sh" "$package_dir/bin/laneway" "$package_dir/bin/laneway-compat"
if [ -f "$package_dir/bin/lanewayd" ]; then
	chmod 0755 "$package_dir/bin/lanewayd"
fi
if [ "$package_goos" = linux ]; then
	chmod 0755 "$package_dir/install-control-plane-release.sh" \
		"$package_dir"/sbin/* "$package_dir"/deploy/compose/*.sh \
		"$package_dir"/deploy/compose/laneway-control \
		"$package_dir"/deploy/containers/update-connector.sh
fi

tmp_archive="$staging_dir/$archive"
archive_tar=tar
if command -v gtar >/dev/null 2>&1; then
	archive_tar=gtar
fi
"$archive_tar" --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
  -C "$staging_dir" -cf "$staging_dir/laneway.tar" laneway
gzip -n -c "$staging_dir/laneway.tar" > "$tmp_archive"
mv "$tmp_archive" "$project_dir/dist/$archive"
# Longstanding standalone asset for clients that still use the Go command.
install -m 0755 "$staging_dir/$standalone" "$project_dir/dist/$standalone"
(
  cd "$project_dir/dist"
  sha256sum "$archive" > "$archive.sha256"
)
echo "$project_dir/dist/$archive"
