//go:build !linux && !darwin

package main

import "github.com/spf13/cobra"

func addPlatformCommands(*cobra.Command) {}
