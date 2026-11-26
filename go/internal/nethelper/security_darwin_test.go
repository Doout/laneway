//go:build darwin

package nethelper

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestDarwinHelperUsesSupportedUnixStreams(t *testing.T) {
	if got := helperSocketType(); got != unix.SOCK_STREAM {
		t.Fatalf("helper socket type = %d, want SOCK_STREAM", got)
	}
	if got := helperSocketProtocol(); got != unix.SOCK_STREAM {
		t.Fatalf("helper socket protocol = %d, want SOCK_STREAM", got)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, helperSocketType(), 0)
	if err != nil {
		t.Fatalf("create helper socket pair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	for _, fd := range fds {
		if pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID); err != nil || pid <= 0 {
			t.Fatalf("invalid Darwin helper socket peer PID %d: %v", pid, err)
		}
	}
}
