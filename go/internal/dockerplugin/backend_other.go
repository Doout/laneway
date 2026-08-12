//go:build !linux

package dockerplugin

import (
	"context"
	"fmt"
)

type LinuxBackendConfig struct {
	IPCommand       string
	NFTCommand      string
	TunnelInterface string
}
type LinuxBackend struct{}

func NewLinuxBackend(LinuxBackendConfig) (*LinuxBackend, error) {
	return nil, fmt.Errorf("%w: Docker policy networks require Linux", ErrInvalid)
}
func (*LinuxBackend) ApplyNetwork(context.Context, *Network, Authorization) error  { return ErrInvalid }
func (*LinuxBackend) RemoveNetwork(context.Context, *Network, Authorization) error { return ErrInvalid }
func (*LinuxBackend) Join(context.Context, *Network, *Endpoint) error              { return ErrInvalid }
func (*LinuxBackend) Leave(context.Context, *Network, *Endpoint) error             { return ErrInvalid }
