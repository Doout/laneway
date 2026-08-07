package netvalidate

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// MaxRelayEndpoints is the stable-v1 bound on controller-authorized relay
	// services in one atomic network snapshot.
	MaxRelayEndpoints = 32
	// MaxRelayAddressesPerEndpoint bounds DNS expansion for one relay service.
	MaxRelayAddressesPerEndpoint = 16
	// MaxRelayTargets bounds the complete service/address expansion retained by
	// a node, and therefore its native transport-bypass set.
	MaxRelayTargets = 128
)

var ErrInvalidHostPort = errors.New("endpoint is not a canonical host:port")

// CanonicalHostPort validates a numeric IP or ASCII DNS host with a nonzero
// port and returns one language-neutral canonical spelling. DNS names are
// lower-cased and a single root dot is removed; single-label names are valid.
func CanonicalHostPort(value string) (string, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || value != strings.TrimSpace(value) || host == "" {
		return "", ErrInvalidHostPort
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", ErrInvalidHostPort
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if address.Zone() != "" || address.Is4In6() || !UsableRelayAddress(address) {
			return "", ErrInvalidHostPort
		}
		return net.JoinHostPort(address.String(), strconv.FormatUint(port, 10)), nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if len(host) == 0 || len(host) > 253 {
		return "", ErrInvalidHostPort
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidHostPort
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", ErrInvalidHostPort
			}
		}
	}
	return net.JoinHostPort(host, strconv.FormatUint(port, 10)), nil
}

// UsableRelayAddress rejects address classes that cannot identify a unicast
// transport destination. Loopback and link-local addresses remain valid for
// intentionally colocated or single-segment deployments.
func UsableRelayAddress(address netip.Addr) bool {
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	if address.Is4() {
		return address.As4() != [4]byte{255, 255, 255, 255}
	}
	return true
}
