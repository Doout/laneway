package main

import (
	"errors"
	"os"
)

func configureProductSystem(check, yes bool) error {
	if check || yes {
		return errors.New("--check and --yes configure the macOS network helper")
	}
	return runProductSystem("configure", "")
}

func startProductSystem(config string) error {
	return runProductSystem("run", config)
}

func runProductSystem(subcommand, config string) error {
	if err := guardManagedProductNode(); err != nil {
		return err
	}
	if config == "" && os.Geteuid() != 0 {
		return errors.New("system enrollment uses host-owned credentials; run this command with sudo")
	}
	args := []string{subcommand, "--system"}
	if config != "" {
		args = append(args, "--config", config)
	}
	path, err := productTrustedDaemon()
	if err != nil {
		return err
	}
	return execProductDaemon(path, args, productSystemEnv(os.Environ()))
}

func guardManagedProductNode() error {
	if !runningInContainer() {
		return nil
	}
	role, _ := deploymentContainerRole()
	switch role {
	case "connector":
		return errors.New("this Connector is already managed by its container; reconfigure or restart it on the deployment host")
	case "server":
		return errors.New("this service is already managed by the control plane; reconfigure or restart it on the deployment host")
	}
	return nil
}
