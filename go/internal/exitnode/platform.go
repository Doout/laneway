package exitnode

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

const (
	// DefaultRouteTable is deliberately separate from the main table. Exit
	// selection is activated by an owned policy rule, never by overwriting the
	// host's ordinary default-routing state.
	DefaultRouteTable    = 51820
	DefaultRouteProtocol = 251
	DefaultRulePriority  = 11000
)

var interfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type RouteManagerConfig struct {
	InterfaceName   string
	IPCommand       string
	Table           int
	Protocol        int
	RulePriority    int
	ShutdownTimeout time.Duration
	Runner          CommandRunner
}

func normalizeRouteConfig(config RouteManagerConfig) (RouteManagerConfig, error) {
	if config.InterfaceName == "" || len(config.InterfaceName) > 15 || !interfacePattern.MatchString(config.InterfaceName) {
		return RouteManagerConfig{}, fmt.Errorf("%w: invalid tunnel interface %q", ErrInvalid, config.InterfaceName)
	}
	if config.IPCommand == "" {
		config.IPCommand = "ip"
	}
	if config.Table == 0 {
		config.Table = DefaultRouteTable
	}
	if config.Table < 1 {
		return RouteManagerConfig{}, fmt.Errorf("%w: invalid route table", ErrInvalid)
	}
	if config.Table == 253 || config.Table == 254 || config.Table == 255 {
		return RouteManagerConfig{}, fmt.Errorf("%w: exit routes require a dedicated non-system table", ErrInvalid)
	}
	if config.Protocol == 0 {
		config.Protocol = DefaultRouteProtocol
	}
	if config.Protocol < 1 || config.Protocol > 255 {
		return RouteManagerConfig{}, fmt.Errorf("%w: invalid route protocol", ErrInvalid)
	}
	if config.RulePriority == 0 {
		config.RulePriority = DefaultRulePriority
	}
	if config.RulePriority < 1 || config.RulePriority > 32765 {
		return RouteManagerConfig{}, fmt.Errorf("%w: invalid policy-rule priority", ErrInvalid)
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = DefaultShutdownTimeout
	}
	if config.ShutdownTimeout < 0 {
		return RouteManagerConfig{}, fmt.Errorf("%w: negative shutdown timeout", ErrInvalid)
	}
	return config, nil
}

type DNSManagerConfig struct {
	InterfaceName   string
	ResolveCommand  string
	ShutdownTimeout time.Duration
	Runner          CommandRunner
}

const DefaultResolveCommand = "/usr/bin/resolvectl"

func normalizeDNSConfig(config DNSManagerConfig) (DNSManagerConfig, error) {
	if config.InterfaceName == "" || len(config.InterfaceName) > 15 || !interfacePattern.MatchString(config.InterfaceName) {
		return DNSManagerConfig{}, fmt.Errorf("%w: invalid DNS interface %q", ErrInvalid, config.InterfaceName)
	}
	if config.ResolveCommand == "" {
		config.ResolveCommand = DefaultResolveCommand
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = DefaultShutdownTimeout
	}
	if config.ShutdownTimeout < 0 {
		return DNSManagerConfig{}, fmt.Errorf("%w: negative shutdown timeout", ErrInvalid)
	}
	return config, nil
}
