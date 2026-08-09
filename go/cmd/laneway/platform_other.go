//go:build !linux && !darwin

package main

import (
	"errors"
	"flag"

	"laneway.dev/laneway/internal/bootstrap"
	"laneway.dev/laneway/internal/nethelper"
)

const credentialDescriptorDirectory = "/proc/self/fd"

func connectPlatformPreflight() error {
	return errors.New("foreground connect currently requires Linux or macOS")
}

func addPlatformConnectFlags(*flag.FlagSet, *connectPlatformOptions) {}

func validatePlatformArtifact(metadata bootstrap.Metadata) error {
	_, err := metadata.ArtifactForCurrentPlatform()
	return err
}

func connectUsage() error {
	return errors.New("usage: laneway connect lane.example.com [--route PREFIX] [--ephemeral [--token-file PATH]]")
}

func platformNetworkHelperOptions() nethelper.StartOptions { return nethelper.StartOptions{} }
