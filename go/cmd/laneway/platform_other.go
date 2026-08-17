//go:build !linux && !darwin

package main

import (
	"errors"
	"flag"

	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/nethelper"
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
	return errors.New("usage: laneway connect [DOMAIN] [--route PREFIX] [--ephemeral [--token-file PATH]]")
}

func platformNetworkHelperOptions() nethelper.StartOptions { return nethelper.StartOptions{} }
