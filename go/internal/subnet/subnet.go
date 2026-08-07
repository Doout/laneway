// Package subnet manages the host forwarding state used by a Laneway subnet
// router. The public contract is portable; the privileged implementation is
// selected by build tags and an in-memory implementation is available to
// callers that must not mutate their host.
package subnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"time"
)

const (
	DefaultTableName       = "laneway"
	DefaultOwnerChain      = "laneway_owner"
	DefaultForwardChain    = "laneway_forward"
	DefaultNATChain        = "laneway_postrouting"
	DefaultShutdownTimeout = 5 * time.Second
)

var (
	ErrUnsupported = errors.New("subnet: forwarding is unsupported on this operating system")
	ErrClosed      = errors.New("subnet: forwarding manager is closed")
	ErrInvalid     = errors.New("subnet: invalid forwarding configuration")
	ErrOwnership   = errors.New("subnet: nftables state is not owned by Laneway")
)

// Mode controls whether traffic leaving the overlay is source-NATed. NAT is
// the default because it does not require the private LAN to have a return
// route for overlay addresses.
type Mode string

const (
	ModeNAT    Mode = "nat"
	ModeRouted Mode = "routed"
)

// ForwardingRoute carries the forwarding semantics for one controller-
// authorized subnet. Different prefixes may use different modes in the same
// complete snapshot.
type ForwardingRoute struct {
	Prefix netip.Prefix
	Mode   Mode
}

// ForwardingPlan is the complete desired forwarding state. Prefixes are
// controller-authorized private-LAN destinations, not overlay source ranges.
// An empty prefix set disables forwarding and restores the saved host state.
type ForwardingPlan struct {
	AuthorizedPrefixes []netip.Prefix
	Mode               Mode
	// Routes is the mode-aware representation used by controller snapshots.
	// AuthorizedPrefixes and Mode remain supported for static configurations.
	Routes []ForwardingRoute
}

// ValidateForwardingPlan validates a complete forwarding snapshot without
// changing nftables or sysctl state.
func ValidateForwardingPlan(plan ForwardingPlan) error {
	_, err := normalizePlan(plan)
	return err
}

// ForwardingManager applies a complete snapshot. Apply is transactional and
// idempotent, Restore returns the host to its pre-Apply state, and Close uses a
// bounded implementation-defined shutdown context.
type ForwardingManager interface {
	Apply(context.Context, ForwardingPlan) error
	Restore(context.Context) error
	Close() error
}

// CommandRunner executes an executable directly. Implementations must not
// concatenate name or args into a shell command.
type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type ForwardingManagerConfig struct {
	// Both interfaces are mandatory: silently guessing either can expose the
	// wrong host network to the overlay.
	InputInterface  string
	OutputInterface string

	TableName     string
	OwnerChain    string
	ForwardChain  string
	NATChain      string
	NFTCommand    string
	SysctlCommand string

	ShutdownTimeout time.Duration
	Runner          CommandRunner
}

var (
	interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	nftNamePattern       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)
)

func normalizeConfig(config ForwardingManagerConfig) (ForwardingManagerConfig, error) {
	for label, value := range map[string]string{
		"input interface":  config.InputInterface,
		"output interface": config.OutputInterface,
	} {
		// IFNAMSIZ is 16 including the NUL terminator on Linux. Applying the
		// bound portably makes fake and real managers agree.
		if value == "" || len(value) > 15 || !interfaceNamePattern.MatchString(value) {
			return ForwardingManagerConfig{}, fmt.Errorf("%w: invalid %s %q", ErrInvalid, label, value)
		}
	}
	if config.InputInterface == config.OutputInterface {
		return ForwardingManagerConfig{}, fmt.Errorf("%w: input and output interfaces must differ", ErrInvalid)
	}
	if config.TableName == "" {
		config.TableName = DefaultTableName
	}
	if config.ForwardChain == "" {
		config.ForwardChain = DefaultForwardChain
	}
	if config.OwnerChain == "" {
		config.OwnerChain = DefaultOwnerChain
	}
	if config.NATChain == "" {
		config.NATChain = DefaultNATChain
	}
	for label, value := range map[string]string{
		"table":         config.TableName,
		"owner chain":   config.OwnerChain,
		"forward chain": config.ForwardChain,
		"NAT chain":     config.NATChain,
	} {
		if !nftNamePattern.MatchString(value) {
			return ForwardingManagerConfig{}, fmt.Errorf("%w: unsafe nftables %s name %q", ErrInvalid, label, value)
		}
	}
	if config.OwnerChain == config.ForwardChain || config.OwnerChain == config.NATChain || config.ForwardChain == config.NATChain {
		return ForwardingManagerConfig{}, fmt.Errorf("%w: nftables chain names must be distinct", ErrInvalid)
	}
	if config.NFTCommand == "" {
		config.NFTCommand = "nft"
	}
	if config.SysctlCommand == "" {
		config.SysctlCommand = "sysctl"
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = DefaultShutdownTimeout
	}
	if config.ShutdownTimeout < 0 {
		return ForwardingManagerConfig{}, fmt.Errorf("%w: negative shutdown timeout", ErrInvalid)
	}
	return config, nil
}

func normalizePlan(plan ForwardingPlan) (ForwardingPlan, error) {
	legacyMode := plan.Mode
	if legacyMode == "" {
		legacyMode = ModeNAT
	}
	if legacyMode != ModeNAT && legacyMode != ModeRouted {
		return ForwardingPlan{}, fmt.Errorf("%w: unknown forwarding mode %q", ErrInvalid, plan.Mode)
	}
	routeModes := make(map[netip.Prefix]Mode, len(plan.AuthorizedPrefixes)+len(plan.Routes))
	add := func(prefix netip.Prefix, mode Mode) error {
		if mode != ModeNAT && mode != ModeRouted {
			return fmt.Errorf("%w: unknown forwarding mode %q", ErrInvalid, mode)
		}
		if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix != prefix.Masked() || prefix.Bits() == 0 {
			return fmt.Errorf("%w: authorized prefix must be canonical and non-default, got %q", ErrInvalid, prefix)
		}
		if prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return fmt.Errorf("%w: authorized prefix is not unicast %q", ErrInvalid, prefix)
		}
		if previous, duplicate := routeModes[prefix]; duplicate && previous != mode {
			return fmt.Errorf("%w: conflicting forwarding modes for %q", ErrInvalid, prefix)
		}
		routeModes[prefix] = mode
		return nil
	}
	for _, prefix := range plan.AuthorizedPrefixes {
		if err := add(prefix, legacyMode); err != nil {
			return ForwardingPlan{}, err
		}
	}
	for _, route := range plan.Routes {
		if err := add(route.Prefix, route.Mode); err != nil {
			return ForwardingPlan{}, err
		}
	}
	routes := make([]ForwardingRoute, 0, len(routeModes))
	for prefix, mode := range routeModes {
		routes = append(routes, ForwardingRoute{Prefix: prefix, Mode: mode})
	}
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Prefix.Addr().Compare(routes[j].Prefix.Addr()) < 0 ||
			(routes[i].Prefix.Addr() == routes[j].Prefix.Addr() && routes[i].Prefix.Bits() < routes[j].Prefix.Bits())
	})
	plan.AuthorizedPrefixes = make([]netip.Prefix, len(routes))
	for i, route := range routes {
		plan.AuthorizedPrefixes[i] = route.Prefix
	}
	plan.Routes = routes
	plan.Mode = legacyMode
	if len(routes) != 0 {
		plan.Mode = routes[0].Mode
		for _, route := range routes[1:] {
			if route.Mode != plan.Mode {
				plan.Mode = ""
				break
			}
		}
	}
	return plan, nil
}

func plansEqual(a, b ForwardingPlan) bool {
	if len(a.Routes) != len(b.Routes) {
		return false
	}
	for i := range a.Routes {
		if a.Routes[i] != b.Routes[i] {
			return false
		}
	}
	return true
}

func clonePlan(plan ForwardingPlan) ForwardingPlan {
	plan.AuthorizedPrefixes = append([]netip.Prefix(nil), plan.AuthorizedPrefixes...)
	plan.Routes = append([]ForwardingRoute(nil), plan.Routes...)
	return plan
}
