//go:build !linux

package main

import "fmt"

func detectUpdateTarget() (string, error) { return "client", nil }
func updateContainerHandoff(string) error { return nil }

func configureServer([]string) error {
	return fmt.Errorf("run sudo laneway configure server on the Linux Docker host")
}

func updateDeployment(target string, _ []string) error {
	return fmt.Errorf("run sudo laneway update %s on the Linux Docker host", target)
}
