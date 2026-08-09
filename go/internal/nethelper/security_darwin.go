//go:build darwin

package nethelper

import (
	"errors"

	"golang.org/x/sys/unix"
)

func authenticateHelperPeer(fd int) error {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return err
	}
	if cred == nil {
		return errors.New("network helper peer has no credentials")
	}
	return nil
}

func helperSocketType() int { return unix.SOCK_SEQPACKET }

// macOS has no Linux-style capability set. The helper remains a separate,
// credential-free root process reachable only through its inherited socket;
// its strict protocol exposes only scoped utun and route operations.
func hardenProcess() error { return nil }
