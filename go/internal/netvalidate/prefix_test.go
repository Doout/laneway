package netvalidate

import (
	"errors"
	"net/netip"
	"testing"
)

func TestRoutablePrefix(t *testing.T) {
	for _, value := range []string{"10.0.0.0/8", "fd00::/64", "2001:db8::/32"} {
		if err := RoutablePrefix(netip.MustParsePrefix(value), false); err != nil {
			t.Fatalf("%s: %v", value, err)
		}
	}
	for _, value := range []string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1/128", "fe80::/10", "ff00::/8"} {
		if err := RoutablePrefix(netip.MustParsePrefix(value), false); !errors.Is(err, ErrUnroutablePrefix) {
			t.Fatalf("%s error = %v", value, err)
		}
	}
	for _, value := range []string{"0.0.0.0/0", "::/0"} {
		prefix := netip.MustParsePrefix(value)
		if err := RoutablePrefix(prefix, false); !errors.Is(err, ErrUnroutablePrefix) {
			t.Fatalf("non-exit %s error = %v", value, err)
		}
		if err := RoutablePrefix(prefix, true); err != nil {
			t.Fatalf("exit %s: %v", value, err)
		}
	}
}
