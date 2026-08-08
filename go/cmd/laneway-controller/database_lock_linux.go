//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func acquireControllerDatabaseLock(databasePath string) (*os.File, error) {
	path := databasePath + ".lock"
	fd, err := unix.Open(path, unix.O_CLOEXEC|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open controller lifecycle lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open controller lifecycle lock: invalid file descriptor")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect controller lifecycle lock: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = file.Close()
		return nil, errors.New("controller lifecycle lock is not a regular file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("controller database is already in use")
		}
		return nil, fmt.Errorf("lock controller lifecycle: %w", err)
	}
	return file, nil
}

func acquireControllerRestoreLock(databasePath string) (*os.File, error) {
	return acquireControllerDatabaseLock(databasePath)
}
