//go:build !linux

package wireguard

import "context"

func OpenDevice(context.Context, DeviceConfig) (Device, error) { return nil, ErrUnsupported }
