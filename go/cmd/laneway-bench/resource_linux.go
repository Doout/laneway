//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func processCPUTime() time.Duration {
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil {
		return 0
	}
	return timevalDuration(usage.Utime) + timevalDuration(usage.Stime)
}

func timevalDuration(value syscall.Timeval) time.Duration {
	return time.Duration(value.Sec)*time.Second + time.Duration(value.Usec)*time.Microsecond
}

func processRSSBytes() uint64 {
	return processRSSBytesForPID("self")
}

var (
	clockTicksOnce  sync.Once
	clockTicksValue uint64
	clockTicksError error
)

func processCPUTimeForPID(pid int) (time.Duration, error) {
	contents, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, fmt.Errorf("read external process CPU: %w", err)
	}
	text := string(contents)
	closing := strings.LastIndexByte(text, ')')
	if closing < 0 || closing+2 >= len(text) {
		return 0, fmt.Errorf("parse external process CPU: malformed stat")
	}
	fields := strings.Fields(text[closing+2:])
	if len(fields) < 13 {
		return 0, fmt.Errorf("parse external process CPU: short stat")
	}
	user, userErr := strconv.ParseUint(fields[11], 10, 64)
	system, systemErr := strconv.ParseUint(fields[12], 10, 64)
	if userErr != nil || systemErr != nil {
		return 0, fmt.Errorf("parse external process CPU ticks")
	}
	ticks, err := systemClockTicks()
	if err != nil {
		return 0, err
	}
	return time.Duration(user+system) * time.Second / time.Duration(ticks), nil
}

func systemClockTicks() (uint64, error) {
	clockTicksOnce.Do(func() {
		output, err := exec.Command("getconf", "CLK_TCK").Output()
		if err != nil {
			clockTicksError = fmt.Errorf("query CLK_TCK: %w", err)
			return
		}
		clockTicksValue, clockTicksError = strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
		if clockTicksError != nil || clockTicksValue == 0 {
			clockTicksError = fmt.Errorf("parse CLK_TCK value %q", strings.TrimSpace(string(output)))
		}
	})
	return clockTicksValue, clockTicksError
}

func processRSSBytesForPID(pid string) uint64 {
	contents, err := os.ReadFile("/proc/" + pid + "/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(contents))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * uint64(os.Getpagesize())
}

func externalProcessRSSBytes(pid int) (uint64, error) {
	value := processRSSBytesForPID(strconv.Itoa(pid))
	if value == 0 {
		return 0, fmt.Errorf("read nonzero external process RSS")
	}
	return value, nil
}
