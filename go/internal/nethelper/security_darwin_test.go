//go:build darwin

package nethelper

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestDarwinHelperUsesSupportedUnixDatagrams(t *testing.T) {
	if got := helperSocketType(); got != unix.SOCK_DGRAM {
		t.Fatalf("helper socket type = %d, want SOCK_DGRAM", got)
	}
	if got := helperSocketProtocol(); got != unix.SOCK_DGRAM {
		t.Fatalf("helper socket protocol = %d, want SOCK_DGRAM", got)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, helperSocketType(), 0)
	if err != nil {
		t.Fatalf("create helper socket pair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	for _, fd := range fds {
		if err := authenticateHelperPeer(fd); err != nil {
			t.Fatalf("authenticate helper socket peer: %v", err)
		}
	}
}
