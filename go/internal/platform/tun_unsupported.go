//go:build !linux && !darwin

package platform

import (
	"context"
	"os"
)

func OpenTUN(context.Context, TUNConfig) (TUNDevice, error) {
	return nil, ErrUnsupported
}

func DuplicateTUNFile(TUNDevice) (*os.File, error) { return nil, ErrUnsupported }

func AdoptTUNFile(*os.File, TUNConfig) (TUNDevice, error) { return nil, ErrUnsupported }
