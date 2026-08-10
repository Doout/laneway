//go:build darwin

package nethelper

import (
	"errors"

	"golang.org/x/sys/unix"
)

func authenticateHelperPeer(fd int) error {
	pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		return err
	}
	if pid <= 0 {
		return errors.New("network helper peer has no process identity")
	}
	return nil
}

// Darwin does not implement SOCK_SEQPACKET for AF_UNIX socket pairs. A
// connected SOCK_DGRAM pair preserves message boundaries and descriptor
// passing while LOCAL_PEERPID still authenticates the inherited peer.
func helperSocketType() int     { return unix.SOCK_DGRAM }
func helperSocketProtocol() int { return unix.SOCK_DGRAM }

// macOS has no Linux-style capability set. The helper remains a separate,
// credential-free root process reachable only through its inherited socket;
// its strict protocol exposes only scoped utun and route operations.
func hardenProcess() error { return nil }
