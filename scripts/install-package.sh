#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
destination_root=${DESTDIR:-}
prefix=${PREFIX:-/usr/local}
bindir="$destination_root$prefix/bin"
sbindir="$destination_root$prefix/sbin"
sharedir="$destination_root$prefix/share/laneway"
unitdir="$destination_root$prefix/lib/systemd/system"

if [ -z "$destination_root" ] && [ "$(id -u)" -ne 0 ]; then
  echo "run this installer as root, or set DESTDIR for a staged install" >&2
  exit 1
fi
if [ "$prefix" != /usr/local ]; then
  echo "PREFIX must be /usr/local because the packaged systemd units use that path" >&2
  exit 1
fi

if [ -z "$destination_root" ]; then
  if ! getent group laneway >/dev/null 2>&1; then
    groupadd --system laneway
  fi
	group_entry=$(getent group laneway)
	group_gid=$(printf '%s\n' "$group_entry" | cut -d: -f3)
	group_members=$(printf '%s\n' "$group_entry" | cut -d: -f4)
	case "$group_gid" in *[!0-9]*|'') group_gid=999999;; esac
	case "$group_members" in ''|laneway) ;; *)
		echo "existing laneway group has unexpected supplementary members" >&2
		exit 1
		;;
	esac
	if [ "$group_gid" -ge 1000 ]; then
		echo "existing laneway group is not a system group" >&2
		exit 1
	fi
  if ! id laneway >/dev/null 2>&1; then
    useradd --system --gid laneway --home-dir /var/lib/laneway \
      --shell /usr/sbin/nologin laneway
	else
		account=$(getent passwd laneway)
		account_uid=$(printf '%s\n' "$account" | cut -d: -f3)
		account_home=$(printf '%s\n' "$account" | cut -d: -f6)
		account_shell=$(printf '%s\n' "$account" | cut -d: -f7)
		case "$account_uid" in *[!0-9]*|'') account_uid=999999;; esac
		case "$account_shell" in */nologin|*/false) locked_shell=true;; *) locked_shell=false;; esac
		if [ "$account_uid" -ge 1000 ] || [ "$account_home" != /var/lib/laneway ] || \
		  [ "$(id -gn laneway)" != laneway ] || [ "$(id -Gn laneway)" != laneway ] || \
		  [ "$locked_shell" != true ]; then
			echo "existing laneway account is not a locked system service account" >&2
			exit 1
		fi
  fi
  install -d -m 0750 -o root -g laneway /etc/laneway
fi

install -d -m 0755 "$bindir" "$sbindir" "$sharedir/examples" \
	"$sharedir/docs" "$sharedir/nftables" "$sharedir/spec" \
	"$sharedir/deploy" "$sharedir/integration" "$unitdir"
install -m 0755 "$script_dir/bin/laneway" "$bindir/laneway"
for command in lanewayd laneway-relay laneway-controller; do
  install -m 0755 "$script_dir/sbin/$command" "$sbindir/$command"
done
install -m 0755 "$script_dir/sbin/laneway-setup-node" "$sbindir/laneway-setup-node"
install -m 0644 "$script_dir"/examples/*.toml "$sharedir/examples/"
install -m 0644 "$script_dir"/docs/*.md "$sharedir/docs/"
install -m 0644 "$script_dir"/nftables/* "$sharedir/nftables/"
cp -R "$script_dir/spec/." "$sharedir/spec/"
cp -R "$script_dir/deploy/." "$sharedir/deploy/"
cp -R "$script_dir/integration/." "$sharedir/integration/"
install -m 0644 "$script_dir"/systemd/*.service "$unitdir/"
install -m 0644 "$script_dir/README.md" "$script_dir/SECURITY.md" \
  "$script_dir/LICENSE-MIT" "$script_dir/LICENSE-APACHE" \
  "$script_dir/VERSION" "$sharedir/"

if [ -z "$destination_root" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi

echo "Laneway $(cat "$script_dir/VERSION") installed."
echo "Examples: $prefix/share/laneway/examples"
echo "Next: configure the role for this host, then enable its service."
echo "Managed node helper: laneway-setup-node --help"
