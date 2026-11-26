//go:build darwin

package nethelper

import "golang.org/x/sys/unix"

func helperSocketType() int     { return unix.SOCK_STREAM }
func helperSocketProtocol() int { return unix.SOCK_STREAM }
