//go:build !unix

package main

import (
	"os"
	"os/exec"
)

func execProductDaemon(path string, args, env []string) error {
	command := exec.Command(path, args...)
	command.Env = env
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
}

func trustedSystemDaemon(string) bool { return false }
