//go:build !linux

package main

import "errors"

func runNodeInstall([]string) error {
	return errors.New("managed node installation requires Linux and systemd")
}

func runManagedNodeRenew([]string) error {
	return errors.New("managed node renewal requires Linux and systemd")
}

func runNodeUninstall([]string) error {
	return errors.New("managed node uninstall requires Linux and systemd")
}

func runEphemeralExitPrepare([]string) error {
	return errors.New("ephemeral Exit preparation requires Linux and systemd")
}
