//go:build !linux && !darwin

package main

import (
	"context"

	"github.com/Doout/laneway/go/internal/bootstrap"
)

func tryNativeClient(...string) (bool, error) {
	return false, nil
}

func fetchBootstrap(ctx context.Context, authority string) (bootstrap.Metadata, error) {
	return bootstrap.Fetch(ctx, authority)
}
