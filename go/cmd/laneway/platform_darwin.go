//go:build darwin

package main

import (
	"errors"
	"flag"

	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/nethelper"
)

const credentialDescriptorDirectory = "/dev/fd"

func connectPlatformPreflight() error {
	source, err := currentExecutable()
	if err != nil {
		return err
	}
	return macConfigurationStatus(source)
}

func addPlatformConnectFlags(*flag.FlagSet, *connectPlatformOptions) {}

func validatePlatformArtifact(bootstrap.Metadata) error { return nil }

func connectUsage() error {
	return errors.New("usage: laneway connect [DOMAIN] [--route PREFIX] [--ephemeral [--token-file PATH]]")
}

func platformNetworkHelperOptions() nethelper.StartOptions {
	return nethelper.StartOptions{Executable: "/Library/PrivilegedHelperTools/laneway-network-helper"}
}
