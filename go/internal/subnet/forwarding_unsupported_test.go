//go:build !linux

package subnet

import (
	"errors"
	"testing"
)

func TestNewForwardingManagerUnsupported(t *testing.T) {
	manager, err := NewForwardingManager(ForwardingManagerConfig{})
	if manager != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("NewForwardingManager() = %v, %v", manager, err)
	}
}
