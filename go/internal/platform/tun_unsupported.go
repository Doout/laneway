//go:build !linux

package platform

import "context"

func OpenTUN(context.Context, TUNConfig) (TUNDevice, error) {
	return nil, ErrUnsupported
}
