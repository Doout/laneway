//go:build !linux

package nodeapp

import (
	"errors"

	"github.com/Doout/laneway/go/internal/config"
)

func resolveEphemeralExitCredentials(*config.Config) error {
	return errors.New("ephemeral Exit runtime requires Linux")
}

func hardenEphemeralExitProcess() error {
	return errors.New("ephemeral Exit runtime requires Linux")
}
