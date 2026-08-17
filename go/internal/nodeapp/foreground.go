package nodeapp

import (
	"context"
	"errors"
	"net/netip"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/config"
	"github.com/Doout/laneway/go/internal/dataplane"
	"github.com/Doout/laneway/go/internal/exitnode"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/nodeservice"
	"github.com/Doout/laneway/go/internal/pathmanager"
	"github.com/Doout/laneway/go/internal/platform"
	"github.com/Doout/laneway/go/internal/wireguard"
)

// HostNetwork is the complete native-networking boundary used by a node
// runtime. Foreground clients supply a helper-backed instance; persistent
// nodes use the direct root/service implementation.
type HostNetwork struct {
	TUN        platform.TUNDevice
	Routes     platform.RouteManager
	ExitRoutes exitnode.RouteManager
	DNS        exitnode.DNSManager
	Close      func() error
}

// NetworkOpener creates the TUN and applies the initial route plan as one
// transaction. The foreground implementation starts the authenticated
// privileged helper only after controller discovery and configuration have
// been validated by the unprivileged process.
type NetworkOpener func(context.Context, platform.TUNConfig, platform.RoutePlan) (HostNetwork, error)

type RuntimeStatus struct {
	NetworkID        string
	NodeID           string
	Interface        string
	OverlayAddresses []netip.Prefix
	Path             string
}

type ForegroundOptions struct {
	NetworkOpener NetworkOpener
	Status        func(RuntimeStatus)
	// FilterConfiguration restricts the controller-authorized snapshot to the
	// routes explicitly selected for this temporary session. It must fail
	// closed when a requested route or exit is no longer authorized.
	FilterConfiguration func(*lanewayv1.NodeConfiguration) (*lanewayv1.NodeConfiguration, error)
}

// RunForeground runs the authenticated node dataplane under caller-owned
// signal and lifecycle control. It never creates persistent service state and
// requires an explicit native-networking boundary.
func RunForeground(ctx context.Context, cfg config.Config, options ForegroundOptions) error {
	if ctx == nil {
		return errors.New("foreground node runtime requires a context")
	}
	if options.NetworkOpener == nil {
		return errors.New("foreground node runtime requires a network opener")
	}
	return nonCancellationError(runConfig(ctx, cfg, "", runtimeOptions{
		networkOpener: options.NetworkOpener, status: options.Status,
		filterConfiguration: options.FilterConfiguration, foreground: true,
	}))
}

func openDirectHostNetwork(ctx context.Context, tunConfig platform.TUNConfig, initial platform.RoutePlan) (HostNetwork, error) {
	tun, err := platform.OpenTUN(ctx, tunConfig)
	if err != nil {
		return HostNetwork{}, err
	}
	routes, err := platform.NewRouteManager(platform.RouteManagerConfig{InterfaceName: tun.Name()})
	if err != nil {
		return HostNetwork{}, errors.Join(err, tun.Close())
	}
	if err := routes.Apply(ctx, initial); err != nil {
		return HostNetwork{}, errors.Join(err, routes.Close(), tun.Close())
	}
	return HostNetwork{TUN: tun, Routes: routes, Close: func() error {
		return errors.Join(routes.Close(), tun.Close())
	}}, nil
}

type runtimeOptions struct {
	networkOpener       NetworkOpener
	status              func(RuntimeStatus)
	filterConfiguration func(*lanewayv1.NodeConfiguration) (*lanewayv1.NodeConfiguration, error)
	foreground          bool
	wireGuardOpener     func(context.Context, wireguard.SecureManagerConfig) (secureWireGuardRuntime, error)
}

type secureWireGuardRuntime interface {
	nodeservice.WireGuardRelayHandler
	dataplane.DirectPathAttacher
	Run(context.Context) error
	Name() string
	MTU() int
	PublicKey() wireguard.PublicKey
	ApplyGuard(context.Context, wireguard.FirewallPlan) error
	RestoreGuard(context.Context) error
	ApplySnapshot(context.Context, wireguard.SecureSnapshot) error
	RelayMetrics() wireguard.RelayEndpointMetrics
	CarrierMetrics() wireguard.CarrierMuxMetrics
	CarrierPathMetrics() pathmanager.Metrics
	SelectedCarrier(identity.NodeID) string
	CarrierSummary() string
	PathAvailable(identity.NodeID) bool
	Close() error
}

type noOpRouteManager struct{}

func (noOpRouteManager) Apply(_ context.Context, plan platform.RoutePlan) error {
	return platform.ValidateRoutePlan(plan)
}
func (noOpRouteManager) Restore(context.Context) error { return nil }
func (noOpRouteManager) Close() error                  { return nil }
