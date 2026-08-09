//go:build linux

package nethelper

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func authenticateHelperPeer(fd int) error {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return err
	}
	if cred == nil || cred.Pid <= 0 {
		return errors.New("network helper peer has no process identity")
	}
	return nil
}

func helperSocketType() int { return unix.SOCK_SEQPACKET | unix.SOCK_CLOEXEC }

func hardenProcess() error {
	for capability := 0; capability <= 63; capability++ {
		if capability == unix.CAP_NET_ADMIN {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("drop capability %d: %w", capability, err)
		}
	}
	mask := uint32(1 << uint(unix.CAP_NET_ADMIN))
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	data := [2]unix.CapUserData{{Effective: mask, Permitted: mask, Inheritable: mask}}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, unix.CAP_NET_ADMIN, 0, 0); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}
