//go:build linux

package nodeapp

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func lockProcessPrivileges() error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capget(&header, &data[0]); err != nil {
		return fmt.Errorf("read capabilities: %w", err)
	}
	mask := uint32(1 << unix.CAP_NET_ADMIN)
	if data[0].Permitted&mask == 0 {
		return fmt.Errorf("CAP_NET_ADMIN is not permitted")
	}
	data[0] = unix.CapUserData{Effective: mask, Permitted: mask, Inheritable: mask}
	data[1] = unix.CapUserData{}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return fmt.Errorf("reduce capabilities to CAP_NET_ADMIN: %w", err)
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, unix.CAP_NET_ADMIN, 0, 0); err != nil {
		return fmt.Errorf("retain CAP_NET_ADMIN for network helpers: %w", err)
	}
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}
