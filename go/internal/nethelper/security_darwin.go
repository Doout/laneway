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

// Darwin does not reliably implement message-oriented AF_UNIX socket pairs.
// SOCK_STREAM is universally supported; socket_unix adds strict length framing
// while retaining SCM_RIGHTS and LOCAL_PEERPID authentication.
func helperSocketType() int     { return unix.SOCK_STREAM }
func helperSocketProtocol() int { return unix.SOCK_STREAM }

// macOS has no Linux-style capability set. The helper remains a separate,
// credential-free root process reachable only through its inherited socket;
// its strict protocol exposes only scoped utun and route operations.
func hardenProcess() error { return nil }
