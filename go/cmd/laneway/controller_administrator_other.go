//go:build !linux

package main

import (
	"errors"

	"github.com/spf13/cobra"
)

// The installed control-plane wrapper and its internal administrator
// lifecycle commands are Linux-only. Keep a compile-time definition for
// portable client builds; the platform command tree never registers it.
func controllerAdministratorCommand() *cobra.Command {
	return command("administrator", "Internal administrator lifecycle operations", runControllerAdministrator)
}

func runControllerAdministrator([]string) error {
	return errors.New("controller administrator lifecycle commands require Linux")
}
