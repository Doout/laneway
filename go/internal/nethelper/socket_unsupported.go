//go:build !linux && !darwin

package nethelper

import (
	"context"

	"github.com/Doout/laneway/go/internal/platform"
)

const (
	unixMessageTruncated = 0
	unixControlTruncated = 0
)

type StartOptions struct {
	Executable string
	SudoPath   string
	Direct     bool
}

func Start(context.Context, Setup, StartOptions) (*Session, error) {
	return nil, platform.ErrUnsupported
}
