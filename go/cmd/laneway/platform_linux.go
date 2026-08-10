//go:build linux

package main

import (
	"errors"
	"flag"

	"laneway.dev/laneway/internal/bootstrap"
	"laneway.dev/laneway/internal/nethelper"
)

const credentialDescriptorDirectory = "/proc/self/fd"

func connectPlatformPreflight() error { return nil }

func addPlatformConnectFlags(fs *flag.FlagSet, options *connectPlatformOptions) {
	fs.StringVar(&options.exitSelector, "exit", "", "controller-authorized exit node name or NodeID")
	fs.StringVar(&options.failureMode, "failure-mode", "closed", "exit path failure behavior: closed or open")
	fs.Func("dns", "temporary exit DNS server (repeatable; omitted preserves native DNS)", func(value string) error {
		options.dns = append(options.dns, value)
		return nil
	})
	fs.Func("local-lan", "native local-LAN bypass prefix for exit mode (repeatable)", func(value string) error {
		options.localLAN = append(options.localLAN, value)
		return nil
	})
}

func validatePlatformArtifact(metadata bootstrap.Metadata) error {
	_, err := metadata.ArtifactForCurrentPlatform()
	return err
}

func connectUsage() error {
	return errors.New("usage: laneway connect [DOMAIN] [--route PREFIX] [--exit NAME_OR_NODE_ID] [--dns ADDRESS] [--ephemeral [--token-file PATH]]")
}

func platformNetworkHelperOptions() nethelper.StartOptions { return nethelper.StartOptions{} }
