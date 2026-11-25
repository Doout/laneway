package main

import "errors"

func configureProductSystem(check, yes bool) error {
	var args []string
	if check {
		args = append(args, "--check")
	}
	if yes {
		args = append(args, "--yes")
	}
	return runMacConfigure(args)
}

func startProductSystem(config string) error {
	if config != "" {
		return errors.New("--config is only available for Linux system networking")
	}
	return runConnect(nil)
}
