//go:build windows

package main

import "time"

// The Go runtime does not expose process CPU time or resident-set bytes on
// Windows. Allocation and GC fields remain measured by runtime.MemStats; the
// report's resource_scope explicitly marks these two optional values absent.
func processCPUTime() time.Duration { return 0 }
func processRSSBytes() uint64       { return 0 }

func processResourceScope() string {
	return "cpu-rss-unavailable+go-runtime"
}
