//go:build !linux && !darwin

package nethelper

import (
	"context"

	"laneway.dev/laneway/internal/platform"
)

type ServiceConfig struct{}

const (
	unixMessageTruncated = 0
	unixControlTruncated = 0
)

type StartOptions struct {
	Executable string
	SudoPath   string
	Direct     bool
}

func ProductionConfig() ServiceConfig { return ServiceConfig{} }

func ServeInheritedFD(context.Context, int, ServiceConfig) error { return platform.ErrUnsupported }

func Start(context.Context, Setup, StartOptions) (*Session, error) {
	return nil, platform.ErrUnsupported
}
