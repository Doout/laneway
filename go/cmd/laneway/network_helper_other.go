//go:build !linux && !darwin

package main

import "github.com/Doout/laneway/go/internal/platform"

func runPlatformNetworkHelper(int) error { return platform.ErrUnsupported }
