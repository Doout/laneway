package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/protocol"
	"laneway.dev/laneway/internal/subnet"
)

// daemonSubnetManager reconciles the complete set of approved subnet routes
// owned by this node. fixedForwardPrefixes contains non-subnet authorization
// (currently the separately managed exit gateway prefix) that must survive a
// subnet advertisement or withdrawal.
type daemonSubnetManager struct {
	mu                   sync.Mutex
	forwarding           subnet.ForwardingManager
	fixedForwardPrefixes []netip.Prefix
	setRelayPrefixes     func([]netip.Prefix) error
	setDirectPrefixes    func([]netip.Prefix) error
	serveExit            bool
	published            []netip.Prefix
}

type ipForwardFamilies struct{ ipv4, ipv6 bool }

func (f ipForwardFamilies) any() bool { return f.ipv4 || f.ipv6 }

func (m *daemonSubnetManager) RequiresIPForwarding(configuration *lanewayv1.NodeConfiguration, local identity.NodeIdentity) (bool, error) {
	families, err := m.RequiredIPForwardFamilies(configuration, local)
	return families.any(), err
}

func (m *daemonSubnetManager) RequiredIPForwardFamilies(configuration *lanewayv1.NodeConfiguration, local identity.NodeIdentity) (ipForwardFamilies, error) {
	if m == nil {
		return ipForwardFamilies{}, nil
	}
	routes, err := approvedLocalSubnetRoutes(configuration, local)
	if err != nil {
		return ipForwardFamilies{}, err
	}
	var result ipForwardFamilies
	for _, route := range routes {
		result.ipv4 = result.ipv4 || route.Prefix.Addr().Is4()
		result.ipv6 = result.ipv6 || route.Prefix.Addr().Is6()
	}
	if !m.serveExit {
		return result, nil
	}
	prefixes, err := approvedLocalExitPrefixes(configuration, local)
	if err != nil {
		return ipForwardFamilies{}, err
	}
	for _, prefix := range prefixes {
		result.ipv4 = result.ipv4 || prefix.Addr().Is4()
		result.ipv6 = result.ipv6 || prefix.Addr().Is6()
	}
	return result, nil
}

func (m *daemonSubnetManager) DenyForwardPrefixes() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Fail-close denial is intentionally best effort across both publishers:
	// failure in one dataplane must not restore authorization in the other.
	var result error
	if m.setRelayPrefixes != nil {
		result = errors.Join(result, m.setRelayPrefixes(nil))
	}
	if m.setDirectPrefixes != nil {
		result = errors.Join(result, m.setDirectPrefixes(nil))
	}
	// The accepted authorization is empty even if a backend could not enact
	// the denial; future transactional rollback must never re-authorize the
	// expired prefix set.
	m.published = nil
	return result
}

func (m *daemonSubnetManager) Apply(ctx context.Context, configuration *lanewayv1.NodeConfiguration, local identity.NodeIdentity) error {
	if m == nil {
		return nil
	}
	plan, prefixes, err := m.Prepare(configuration, local, false)
	if err != nil {
		return err
	}
	if err := m.ApplyPlan(ctx, plan); err != nil {
		return err
	}
	return m.PublishPrefixes(prefixes)
}

// Prepare derives and validates both the privileged forwarding plan and the
// userspace forwarding authorization. It performs no mutation.
func (m *daemonSubnetManager) Prepare(configuration *lanewayv1.NodeConfiguration, local identity.NodeIdentity, includeExit bool) (subnet.ForwardingPlan, []netip.Prefix, error) {
	if m == nil {
		return subnet.ForwardingPlan{}, nil, nil
	}
	routes, err := approvedLocalSubnetRoutes(configuration, local)
	if err != nil {
		return subnet.ForwardingPlan{}, nil, err
	}
	if len(routes) != 0 && m.forwarding == nil {
		return subnet.ForwardingPlan{}, nil, errors.New("approved local subnet route requires routing.output_interface")
	}
	plan := subnet.ForwardingPlan{Routes: routes}
	if err := subnet.ValidateForwardingPlan(plan); err != nil {
		return subnet.ForwardingPlan{}, nil, err
	}
	prefixes := append([]netip.Prefix(nil), m.fixedForwardPrefixes...)
	for _, route := range routes {
		prefixes = append(prefixes, route.Prefix)
	}
	if includeExit && m.serveExit {
		exitPrefixes, err := approvedLocalExitPrefixes(configuration, local)
		if err != nil {
			return subnet.ForwardingPlan{}, nil, err
		}
		prefixes = append(prefixes, exitPrefixes...)
	}
	return plan, prefixes, nil
}

func (m *daemonSubnetManager) ApplyPlan(ctx context.Context, plan subnet.ForwardingPlan) error {
	if m == nil || m.forwarding == nil {
		return nil
	}
	if err := m.forwarding.Apply(ctx, plan); err != nil {
		return fmt.Errorf("apply approved local subnet routes: %w", err)
	}
	return nil
}

// PublishApprovedForwardPrefixes adds exit defaults only after the exit
// gateway manager has successfully installed its enforcement/NAT state.
func (m *daemonSubnetManager) PublishApprovedForwardPrefixes(configuration *lanewayv1.NodeConfiguration, local identity.NodeIdentity) error {
	if m == nil {
		return nil
	}
	_, prefixes, err := m.Prepare(configuration, local, true)
	if err != nil {
		return err
	}
	return m.PublishPrefixes(prefixes)
}

// PublishPrefixes atomically updates relay and direct userspace authorization.
// If the second publisher fails, the first is restored to the last accepted
// prefix set before the error is returned.
func (m *daemonSubnetManager) PublishPrefixes(prefixes []netip.Prefix) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := append([]netip.Prefix(nil), m.published...)
	if m.setRelayPrefixes != nil {
		if err := m.setRelayPrefixes(prefixes); err != nil {
			var rollbackErr error
			rollbackErr = errors.Join(rollbackErr, m.setRelayPrefixes(previous))
			if m.setDirectPrefixes != nil {
				rollbackErr = errors.Join(rollbackErr, m.setDirectPrefixes(previous))
			}
			return errors.Join(fmt.Errorf("authorize relay subnet forwarding: %w", err), rollbackErr)
		}
	}
	if m.setDirectPrefixes != nil {
		if err := m.setDirectPrefixes(prefixes); err != nil {
			var rollbackErr error
			if m.setRelayPrefixes != nil {
				rollbackErr = m.setRelayPrefixes(previous)
			}
			rollbackErr = errors.Join(rollbackErr, m.setDirectPrefixes(previous))
			return errors.Join(fmt.Errorf("authorize direct subnet forwarding: %w", err), rollbackErr)
		}
	}
	m.published = append(m.published[:0], prefixes...)
	return nil
}

func approvedLocalExitPrefixes(configuration *lanewayv1.NodeConfiguration, local identity.NodeIdentity) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for i, route := range configuration.GetRoutes().GetRoutes() {
		if route.GetKind() != lanewayv1.RouteKind_ROUTE_KIND_EXIT {
			continue
		}
		if len(route.GetViaNodeId()) != identity.IDSize {
			return nil, fmt.Errorf("controller exit route %d has an invalid owner", i)
		}
		var owner identity.NodeID
		copy(owner[:], route.GetViaNodeId())
		if owner != local.NodeID {
			continue
		}
		if !protocol.Capability(configuration.GetEnabledCapabilities()).Has(protocol.CapabilityExitNodeV1) {
			return nil, errors.New("controller enabled a local exit route without exit-node policy capability")
		}
		prefix, err := protoPrefix(route.GetDestination())
		if err != nil || prefix.Bits() != 0 {
			return nil, fmt.Errorf("controller exit route %d has an invalid default prefix", i)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func approvedLocalSubnetRoutes(configuration *lanewayv1.NodeConfiguration, local identity.NodeIdentity) ([]subnet.ForwardingRoute, error) {
	var routes []subnet.ForwardingRoute
	for i, route := range configuration.GetRoutes().GetRoutes() {
		if route.GetKind() != lanewayv1.RouteKind_ROUTE_KIND_SUBNET {
			continue
		}
		if len(route.GetViaNodeId()) != identity.IDSize {
			return nil, fmt.Errorf("controller subnet route %d has an invalid owner", i)
		}
		var owner identity.NodeID
		copy(owner[:], route.GetViaNodeId())
		if owner != local.NodeID {
			continue
		}
		if !protocol.Capability(configuration.GetEnabledCapabilities()).Has(protocol.CapabilitySubnetRouterV1) {
			return nil, errors.New("controller enabled a local subnet route without subnet-router policy capability")
		}
		prefix, err := protoPrefix(route.GetDestination())
		if err != nil {
			return nil, fmt.Errorf("controller subnet route %d has an invalid prefix", i)
		}
		mode, err := subnetMode(route.GetMode())
		if err != nil {
			return nil, fmt.Errorf("controller subnet route %d: %w", i, err)
		}
		routes = append(routes, subnet.ForwardingRoute{Prefix: prefix, Mode: mode})
	}
	return routes, nil
}

func subnetMode(mode lanewayv1.RouteAdvertisementMode) (subnet.Mode, error) {
	switch mode {
	case lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT:
		return subnet.ModeNAT, nil
	case lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_ROUTED:
		return subnet.ModeRouted, nil
	default:
		return "", errors.New("NAT/routed mode is unspecified")
	}
}
