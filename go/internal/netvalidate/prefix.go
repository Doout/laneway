// Package netvalidate contains shared network-address validation boundaries.
package netvalidate

import (
	"errors"
	"net/netip"
)

var ErrUnroutablePrefix = errors.New("prefix is not a canonical routable unicast range")

var forbiddenPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/32"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// RoutablePrefix accepts canonical unicast ranges. The only unspecified
// ranges permitted are the two exact defaults, and only when allowDefault is
// true (for controller-approved exit routes).
func RoutablePrefix(prefix netip.Prefix, allowDefault bool) error {
	if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
		return ErrUnroutablePrefix
	}
	if prefix.Bits() == 0 {
		if allowDefault {
			return nil
		}
		return ErrUnroutablePrefix
	}
	for _, forbidden := range forbiddenPrefixes {
		if prefix.Overlaps(forbidden) {
			return ErrUnroutablePrefix
		}
	}
	return nil
}
