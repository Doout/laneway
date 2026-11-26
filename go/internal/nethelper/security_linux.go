//go:build linux

package nethelper

import "golang.org/x/sys/unix"

func helperSocketType() int     { return unix.SOCK_SEQPACKET | unix.SOCK_CLOEXEC }
func helperSocketProtocol() int { return unix.SOCK_SEQPACKET }
