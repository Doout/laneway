//go:build linux

package main

import (
	"strings"
	"testing"

	"github.com/Doout/laneway/go/internal/bootstrap"
)

func TestConsoleEnrollmentCommandSurface(t *testing.T) {
	const controllerHost = "controller.example.test:9443"
	const tokenFile = "./laneway.code"

	discoveryURL, err := bootstrap.DiscoveryURL(controllerHost)
	if err != nil || discoveryURL != "https://"+controllerHost+bootstrap.WellKnownPath {
		t.Fatalf("controller host with port resolved to %q: %v", discoveryURL, err)
	}

	commands := []struct {
		name string
		args []string
	}{
		{name: "durable node", args: []string{"node", "install", controllerHost, "--token-file", tokenFile}},
		{name: "remembered user", args: []string{"login", controllerHost, "--token-file", tokenFile}},
		{name: "ephemeral user", args: []string{"connect", controllerHost, "--ephemeral", "--token-file", tokenFile}},
	}
	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			args := append(append([]string(nil), command.args...), "--help")
			if err := executeCLI(args); err != nil {
				t.Fatalf("console command %q does not reach the shipped CLI parser: %v", strings.Join(command.args, " "), err)
			}
		})
	}
}
