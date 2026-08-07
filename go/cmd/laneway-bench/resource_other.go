//go:build !linux

package main

import (
	"errors"
	"time"
)

func processCPUTime() time.Duration { return 0 }
func processRSSBytes() uint64       { return 0 }
func processCPUTimeForPID(int) (time.Duration, error) {
	return 0, errors.New("external process CPU telemetry is only supported on Linux")
}
func externalProcessRSSBytes(int) (uint64, error) {
	return 0, errors.New("external process RSS telemetry is only supported on Linux")
}
