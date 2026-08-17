//go:build !linux

package nodeapp

import (
	"errors"

	"laneway.dev/laneway/internal/config"
)

func resolveEphemeralExitCredentials(*config.Config) error {
	return errors.New("ephemeral Exit runtime requires Linux")
}

func hardenEphemeralExitProcess() error {
	return errors.New("ephemeral Exit runtime requires Linux")
}
