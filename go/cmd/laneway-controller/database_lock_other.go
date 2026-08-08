//go:build !linux

package main

import (
	"errors"
	"os"
)

func acquireControllerDatabaseLock(string) (*os.File, error) {
	return os.Open(os.DevNull)
}

func acquireControllerRestoreLock(string) (*os.File, error) {
	return nil, errors.New("controller lifecycle locking is not supported on this platform")
}
