//go:build aix || darwin || dragonfly || freebsd || netbsd || openbsd || solaris

package main

import (
	"syscall"
	"time"
)

func processCPUTime() time.Duration {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	return time.Duration(usage.Utime.Sec+usage.Stime.Sec)*time.Second +
		time.Duration(usage.Utime.Usec+usage.Stime.Usec)*time.Microsecond
}

// Portable Go does not expose resident-set bytes on these targets. The JSON
// resource_scope makes this zero explicitly unavailable rather than measured.
func processRSSBytes() uint64 { return 0 }

func processResourceScope() string {
	return "process-rusage+rss-unavailable+go-runtime"
}
