//go:build !linux

package platform

import (
	"context"
	"errors"
	"testing"
)

func TestUnsupportedConstructors(t *testing.T) {
	if device, err := OpenTUN(context.Background(), TUNConfig{}); device != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("OpenTUN = (%v, %v)", device, err)
	}
	if manager, err := NewRouteManager(RouteManagerConfig{}); manager != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("NewRouteManager = (%v, %v)", manager, err)
	}
}
