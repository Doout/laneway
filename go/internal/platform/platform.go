// Package platform provides the operating-system boundary used by the Laneway
// dataplane. The interfaces in this file are portable; privileged Linux
// implementations and unprivileged in-memory implementations live beside it.
package platform

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

const (
	DefaultTUNName = "lane0"
	MinMTU         = 576
	MinIPv6MTU     = 1280
	DefaultMTU     = 1200 // Conservative for QUIC DATAGRAM encapsulation.
	MaxMTU         = 65535

	DefaultRouteTable    = 254 // Linux main routing table.
	DefaultRouteProtocol = 250 // Private protocol tag used to identify our routes.
)

var (
	// ErrUnsupported is stable across all non-Linux platform entry points.
	ErrUnsupported   = errors.New("platform: operation unsupported on this operating system")
	ErrClosed        = errors.New("platform: resource is closed")
	ErrInvalidTUN    = errors.New("platform: invalid TUN configuration")
	ErrInvalidRoute  = errors.New("platform: invalid route")
	ErrRouteConflict = errors.New("platform: route is no longer owned by Laneway")
)

var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// TUNDevice exchanges complete IP packets with the host kernel. Implementations
// must unblock an operation when its context is cancelled or Close is called.
type TUNDevice interface {
	Name() string
	MTU() int
	Addresses() []netip.Prefix
	Read(context.Context, []byte) (int, error)
	Write(context.Context, []byte) (int, error)
	Close() error
}

type TUNConfig struct {
	Name      string
	MTU       int
	Addresses []netip.Prefix
	IPCommand string
	Runner    CommandRunner
}

func normalizeTUNConfig(config TUNConfig) (TUNConfig, error) {
	if config.Name == "" {
		config.Name = DefaultTUNName
	}
	if config.MTU == 0 {
		config.MTU = DefaultMTU
	}
	// Linux IFNAMSIZ is 16 including the terminating NUL. Keeping this bound in
	// the portable validation makes behavior identical in tests and on Linux.
	if len(config.Name) > 15 || !interfaceNamePattern.MatchString(config.Name) {
		return TUNConfig{}, fmt.Errorf("%w: invalid interface name %q", ErrInvalidTUN, config.Name)
	}
	if config.MTU < MinMTU || config.MTU > MaxMTU {
		return TUNConfig{}, fmt.Errorf("%w: MTU %d is outside [%d,%d]", ErrInvalidTUN, config.MTU, MinMTU, MaxMTU)
	}
	seen := make(map[netip.Prefix]struct{}, len(config.Addresses))
	addresses := make([]netip.Prefix, 0, len(config.Addresses))
	hasIPv6 := false
	for _, prefix := range config.Addresses {
		hostBits := 32
		if prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
			hostBits = 128
			hasIPv6 = true
		}
		if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Bits() != hostBits || prefix != prefix.Masked() ||
			prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return TUNConfig{}, fmt.Errorf("%w: interface address must be a canonical unicast IPv4 /32 or IPv6 /128, got %q", ErrInvalidTUN, prefix)
		}
		prefix = netip.PrefixFrom(prefix.Addr(), prefix.Bits())
		if _, duplicate := seen[prefix]; duplicate {
			return TUNConfig{}, fmt.Errorf("%w: duplicate interface address %s", ErrInvalidTUN, prefix)
		}
		seen[prefix] = struct{}{}
		addresses = append(addresses, prefix)
	}
	if hasIPv6 && config.MTU < MinIPv6MTU {
		return TUNConfig{}, fmt.Errorf("%w: IPv6 requires MTU of at least %d", ErrInvalidTUN, MinIPv6MTU)
	}
	config.Addresses = addresses
	return config, nil
}

// Route is one overlay or approved subnet route. Default routes are managed by
// the exit-node policy layer because they require transport-bypass rules.
type Route struct {
	Prefix netip.Prefix
	Metric uint32
}

// RoutePlan is applied as a unit. Any route containing a TransportBypass
// address is omitted, preventing the tunnel transport from recursively using
// lane0. Exit-node defaults use a separate policy-routing manager.
type RoutePlan struct {
	Routes          []Route
	TransportBypass []netip.Addr
}

// ValidateRoutePlan validates a complete route snapshot without changing host
// state. Apply uses the same validation.
func ValidateRoutePlan(plan RoutePlan) error {
	_, err := normalizePlan(plan)
	return err
}

// RouteManager owns only routes that it installed. Apply atomically reconciles
// the desired set, Restore puts back displaced state, and Close restores using
// an implementation-defined bounded shutdown context.
type RouteManager interface {
	Apply(context.Context, RoutePlan) error
	Restore(context.Context) error
	Close() error
}

// CommandRunner makes privileged route mutations explicit and mockable. A
// runner must execute name directly with args; it must not concatenate a shell
// command.
type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type RouteManagerConfig struct {
	InterfaceName   string
	IPCommand       string
	Table           int
	Protocol        int
	ShutdownTimeout time.Duration
	Runner          CommandRunner
}

func normalizePlan(plan RoutePlan) (map[string]Route, error) {
	bypass := make([]netip.Addr, 0, len(plan.TransportBypass))
	for _, addr := range plan.TransportBypass {
		if !addr.IsValid() || addr.Is4In6() || addr.IsUnspecified() || addr.IsMulticast() {
			return nil, fmt.Errorf("%w: invalid transport bypass address %q", ErrInvalidRoute, addr)
		}
		bypass = append(bypass, addr)
	}

	desired := make(map[string]Route, len(plan.Routes))
	for _, route := range plan.Routes {
		prefix := route.Prefix
		if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Bits() < 1 || prefix.Bits() > prefix.Addr().BitLen() || prefix != prefix.Masked() {
			return nil, fmt.Errorf("%w: route requires a canonical non-default IPv4 or IPv6 prefix, got %q", ErrInvalidRoute, prefix)
		}
		prefix = netip.PrefixFrom(prefix.Addr(), prefix.Bits())
		route.Prefix = prefix
		excluded := false
		for _, addr := range bypass {
			if prefix.Addr().BitLen() == addr.BitLen() && prefix.Contains(addr) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		key := prefix.String()
		if previous, ok := desired[key]; ok && previous != route {
			return nil, fmt.Errorf("%w: conflicting duplicate %s", ErrInvalidRoute, key)
		}
		desired[key] = route
	}
	return desired, nil
}
