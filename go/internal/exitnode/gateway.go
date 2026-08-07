package exitnode

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

const DefaultGatewayTable = "laneway_exit"

// GatewayPlan enables forwarding on an authorized exit node. OverlaySources
// limits which source prefixes may be NATed; an empty or default source range
// is never accepted.
type GatewayPlan struct {
	Enabled        bool
	Authorized     bool
	OverlaySources []netip.Prefix
}

// ValidateGatewayPlan validates a complete exit-gateway snapshot without
// changing forwarding or nftables state.
func ValidateGatewayPlan(plan GatewayPlan) error {
	_, _, err := normalizeGatewayPlan(plan)
	return err
}

type GatewayManager interface {
	Apply(context.Context, GatewayPlan) error
	Restore(context.Context) error
	Close() error
}

type GatewayManagerConfig struct {
	InputInterface  string
	OutputInterface string
	TableName       string
	OwnerChain      string
	ForwardChain    string
	NATChain        string
	NFTCommand      string
	SysctlCommand   string
	ShutdownTimeout time.Duration
	Runner          CommandRunner
	// ForwardingExternallyManaged is set when the daemon-level dual-stack
	// coordinator owns the required sysctls for coexisting subnet/exit roles.
	ForwardingExternallyManaged bool
}

func normalizeGatewayConfig(config GatewayManagerConfig) (GatewayManagerConfig, error) {
	for label, value := range map[string]string{"input": config.InputInterface, "output": config.OutputInterface} {
		if value == "" || len(value) > 15 || !interfacePattern.MatchString(value) {
			return GatewayManagerConfig{}, fmt.Errorf("%w: invalid %s interface %q", ErrInvalid, label, value)
		}
	}
	if config.InputInterface == config.OutputInterface {
		return GatewayManagerConfig{}, fmt.Errorf("%w: gateway interfaces must differ", ErrInvalid)
	}
	if config.TableName == "" {
		config.TableName = DefaultGatewayTable
	}
	if config.OwnerChain == "" {
		config.OwnerChain = "laneway_owner"
	}
	if config.ForwardChain == "" {
		config.ForwardChain = "laneway_forward"
	}
	if config.NATChain == "" {
		config.NATChain = "laneway_nat"
	}
	for label, value := range map[string]string{"table": config.TableName, "owner chain": config.OwnerChain, "forward chain": config.ForwardChain, "NAT chain": config.NATChain} {
		if len(value) > 32 || !nftNamePattern.MatchString(value) {
			return GatewayManagerConfig{}, fmt.Errorf("%w: invalid nftables %s %q", ErrInvalid, label, value)
		}
	}
	if config.OwnerChain == config.ForwardChain || config.OwnerChain == config.NATChain || config.ForwardChain == config.NATChain {
		return GatewayManagerConfig{}, fmt.Errorf("%w: nftables chain names must differ", ErrInvalid)
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
		return GatewayManagerConfig{}, fmt.Errorf("%w: negative shutdown timeout", ErrInvalid)
	}
	return config, nil
}

func normalizeGatewayPlan(plan GatewayPlan) (GatewayPlan, bool, error) {
	if !plan.Enabled {
		return GatewayPlan{}, false, nil
	}
	if !plan.Authorized {
		return GatewayPlan{}, false, ErrUnauthorized
	}
	prefixes, err := normalizePrefixes(plan.OverlaySources)
	if err != nil {
		return GatewayPlan{}, false, err
	}
	if len(prefixes) == 0 {
		return GatewayPlan{}, false, fmt.Errorf("%w: overlay source prefixes are required", ErrInvalid)
	}
	plan.OverlaySources = prefixes
	return plan, true, nil
}

var nftNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)
