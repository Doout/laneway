package nodeapp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/netvalidate"
	"laneway.dev/laneway/internal/nodeservice"
	"laneway.dev/laneway/internal/platform"
	"laneway.dev/laneway/internal/policy"
	"laneway.dev/laneway/internal/protocol"
	"laneway.dev/laneway/internal/revocation"
	"laneway.dev/laneway/internal/routing"
	"laneway.dev/laneway/internal/subnet"
	"laneway.dev/laneway/internal/wireguard"
)

type controllerApplyState struct {
	mu                       sync.Mutex
	accepted                 *preparedControllerConfiguration
	revoked                  *revocation.Set
	authority                *nodeRuntimeAuthority
	candidateEnabled         atomic.Bool
	candidateMax             atomic.Uint32
	candidateTTLSeconds      atomic.Uint32
	certificateRenewalNeeded atomic.Bool
	certificateRenewAfter    atomic.Uint64
	certificateNotAfter      atomic.Uint64
	relayTargetMu            sync.Mutex
	relayTargets             []nodeservice.RelayTarget
	relayChanges             chan struct{}
	wireGuard                secureWireGuardRuntime
}

// CertificateRenewalNeeded derives the health bit from the current clock so a
// same-epoch lease renewal cannot freeze a pre-threshold value indefinitely.
// The stored bit is reserved for an explicit fail-closed/forced-renewal state.
func (s *controllerApplyState) CertificateRenewalNeeded(now time.Time) bool {
	if s == nil || s.certificateRenewalNeeded.Load() {
		return s != nil
	}
	renewAfter := s.certificateRenewAfter.Load()
	return renewAfter != 0 && now.Unix() >= 0 && uint64(now.Unix()) >= renewAfter
}

func (s *controllerApplyState) CandidateExchangeEnabled() bool {
	return s != nil && s.candidateEnabled.Load()
}

func (s *controllerApplyState) CandidateExchangeMaxCandidates() int {
	return int(s.candidateMax.Load())
}

func (s *controllerApplyState) CandidateExchangeTTL() time.Duration {
	return time.Duration(s.candidateTTLSeconds.Load()) * time.Second
}

func (s *controllerApplyState) RelayTargets() []nodeservice.RelayTarget {
	s.relayTargetMu.Lock()
	defer s.relayTargetMu.Unlock()
	return append([]nodeservice.RelayTarget(nil), s.relayTargets...)
}

func (s *controllerApplyState) RelayAuthorityChanges() <-chan struct{} {
	s.relayTargetMu.Lock()
	defer s.relayTargetMu.Unlock()
	if s.relayChanges == nil {
		s.relayChanges = make(chan struct{})
	}
	return s.relayChanges
}

func (s *controllerApplyState) publishRelayTargets(targets []nodeservice.RelayTarget) {
	s.relayTargetMu.Lock()
	defer s.relayTargetMu.Unlock()
	if slices.Equal(s.relayTargets, targets) {
		return
	}
	s.relayTargets = append([]nodeservice.RelayTarget(nil), targets...)
	if s.relayChanges != nil {
		close(s.relayChanges)
	}
	s.relayChanges = make(chan struct{})
}

type preparedControllerConfiguration struct {
	configuration   *lanewayv1.NodeConfiguration
	routes          []routing.Route
	snapshot        *routing.Snapshot
	osPlan          platform.RoutePlan
	policy          *policy.Engine
	denyPolicy      *policy.Engine
	forwarding      ipForwardFamilies
	subnetPlan      subnet.ForwardingPlan
	forwardPrefix   []netip.Prefix
	failClosing     bool
	revokedSerials  [][]byte
	authorityStatus nodeAuthorityStatus
	wireGuard       *wireguard.SecureSnapshot
}

func prepareControllerConfiguration(configuration *lanewayv1.NodeConfiguration, local identity.NodeIdentity, bypass []netip.Addr,
	subnetManager *daemonSubnetManager, exitManagers *daemonExitManagers,
) (*preparedControllerConfiguration, error) {
	if configuration == nil || configuration.GetConfigurationEpoch() == 0 || configuration.GetRoutes() == nil || configuration.GetPolicy() == nil {
		return nil, errors.New("controller returned an incomplete configuration")
	}
	if string(configuration.GetRoutes().GetNetworkId()) != string(local.NetworkID[:]) ||
		string(configuration.GetPolicy().GetNetworkId()) != string(local.NetworkID[:]) {
		return nil, errors.New("controller configuration belongs to another network")
	}
	if configuration.GetRoutes().GetConfigurationEpoch() != configuration.GetConfigurationEpoch() {
		return nil, errors.New("controller route epoch does not match configuration")
	}
	if configuration.GetPolicy().GetDefaultAction() != lanewayv1.PolicyAction_POLICY_ACTION_DENY {
		return nil, errors.New("controller node policy must default deny")
	}
	failClosing := configuration.GetValidUntilUnixSeconds() != 0 &&
		configuration.GetValidUntilUnixSeconds() <= uint64(time.Now().Unix()) &&
		len(configuration.GetRoutes().GetRoutes()) == 0 && len(configuration.GetPolicy().GetRules()) == 0 &&
		configuration.GetPolicy().GetDefaultAction() == lanewayv1.PolicyAction_POLICY_ACTION_DENY
	compiledPolicy, err := policy.Compile(configuration.GetPolicy())
	if err != nil {
		return nil, err
	}
	if compiledPolicy.Epoch() != configuration.GetConfigurationEpoch() {
		return nil, errors.New("controller policy epoch does not match configuration")
	}
	denyPolicy, err := policy.Compile(&lanewayv1.PolicySnapshot{
		NetworkId: append([]byte(nil), local.NetworkID[:]...), ConfigurationEpoch: configuration.GetConfigurationEpoch(),
		DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY,
	})
	if err != nil {
		return nil, fmt.Errorf("compile controller transition policy: %w", err)
	}
	if err := new(revocation.Set).Replace(configuration.GetRevokedCertificateSerials()); err != nil {
		return nil, fmt.Errorf("controller certificate revocations: %w", err)
	}
	allowedPolicyCapabilities := protocol.CapabilitySubnetRouterV1 | protocol.CapabilityExitNodeV1
	enabledPolicyCapabilities := protocol.Capability(configuration.GetEnabledCapabilities())
	if enabledPolicyCapabilities&^allowedPolicyCapabilities != 0 {
		return nil, fmt.Errorf("controller enabled non-policy capabilities %s", enabledPolicyCapabilities&^allowedPolicyCapabilities)
	}
	seenPeerIDs := make(map[identity.NodeID]struct{}, len(configuration.GetPeers()))
	seenPeerNames := make(map[string]struct{}, len(configuration.GetPeers()))
	overlayOwners := make(map[netip.Addr]identity.NodeID)
	for i, peer := range configuration.GetPeers() {
		if len(peer.GetNodeId()) != identity.IDSize || peer.GetName() == "" || peer.GetName() != strings.TrimSpace(peer.GetName()) || len(peer.GetName()) > 253 {
			return nil, fmt.Errorf("controller peer %d has an invalid identity or name", i)
		}
		var peerID identity.NodeID
		copy(peerID[:], peer.GetNodeId())
		if peerID.IsZero() {
			return nil, fmt.Errorf("controller peer %d has a zero node ID", i)
		}
		if _, duplicate := seenPeerIDs[peerID]; duplicate {
			return nil, fmt.Errorf("controller peer %d duplicates node ID %s", i, peerID)
		}
		if _, duplicate := seenPeerNames[peer.GetName()]; duplicate {
			return nil, fmt.Errorf("controller peer %d duplicates name %q", i, peer.GetName())
		}
		seenPeerIDs[peerID], seenPeerNames[peer.GetName()] = struct{}{}, struct{}{}
		for j, raw := range peer.GetOverlayAddresses() {
			address, ok := netip.AddrFromSlice(raw)
			if !ok || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() {
				return nil, fmt.Errorf("controller peer %d overlay address %d is invalid", i, j)
			}
			if owner, duplicate := overlayOwners[address]; duplicate {
				return nil, fmt.Errorf("controller peer %d overlay address %s duplicates owner %s", i, address, owner)
			}
			overlayOwners[address] = peerID
		}
	}
	if _, present := seenPeerIDs[local.NodeID]; !present && !failClosing {
		return nil, errors.New("controller peer snapshot omits the local node")
	}

	var routes []routing.Route
	var osRoutes []platform.Route
	seenOSPrefix := make(map[netip.Prefix]struct{})
	seenRouteIDs := make(map[identity.ID]struct{}, len(configuration.GetRoutes().GetRoutes()))
	type routeKey struct {
		prefix netip.Prefix
		metric uint32
	}
	seenRouteKeys := make(map[routeKey]struct{}, len(configuration.GetRoutes().GetRoutes()))
	for i, value := range configuration.GetRoutes().GetRoutes() {
		prefix, err := protoPrefix(value.GetDestination())
		if err != nil || len(value.GetRouteId()) != identity.IDSize || len(value.GetViaNodeId()) != identity.IDSize {
			return nil, fmt.Errorf("controller route %d is invalid", i)
		}
		var routeID identity.ID
		copy(routeID[:], value.GetRouteId())
		if routeID.IsZero() {
			return nil, fmt.Errorf("controller route %d has a zero route ID", i)
		}
		if _, duplicate := seenRouteIDs[routeID]; duplicate {
			return nil, fmt.Errorf("controller route %d duplicates route ID %s", i, routeID)
		}
		seenRouteIDs[routeID] = struct{}{}
		key := routeKey{prefix: prefix, metric: value.GetMetric()}
		if _, ambiguous := seenRouteKeys[key]; ambiguous {
			return nil, fmt.Errorf("controller route %d duplicates prefix %s and metric %d", i, prefix, value.GetMetric())
		}
		seenRouteKeys[key] = struct{}{}
		allowDefault := value.GetKind() == lanewayv1.RouteKind_ROUTE_KIND_EXIT
		if err := netvalidate.RoutablePrefix(prefix, allowDefault); err != nil {
			return nil, fmt.Errorf("controller route %d has an unroutable prefix: %w", i, err)
		}
		switch value.GetKind() {
		case lanewayv1.RouteKind_ROUTE_KIND_OVERLAY:
			if value.GetMode() != lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_UNSPECIFIED || prefix.Bits() != prefix.Addr().BitLen() {
				return nil, fmt.Errorf("controller overlay route %d is not a host route with no forwarding mode", i)
			}
		case lanewayv1.RouteKind_ROUTE_KIND_SUBNET:
			if _, err := subnetMode(value.GetMode()); err != nil {
				return nil, fmt.Errorf("controller subnet route %d: %w", i, err)
			}
		case lanewayv1.RouteKind_ROUTE_KIND_EXIT:
			if prefix.Bits() != 0 || (value.GetMode() != lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT &&
				value.GetMode() != lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_ROUTED) {
				return nil, fmt.Errorf("controller exit route %d is not a NAT or routed default", i)
			}
		default:
			return nil, fmt.Errorf("controller route %d has unknown kind %s", i, value.GetKind())
		}
		var nextHop identity.NodeID
		copy(nextHop[:], value.GetViaNodeId())
		if nextHop.IsZero() {
			return nil, fmt.Errorf("controller route %d has a zero next hop", i)
		}
		if _, present := seenPeerIDs[nextHop]; !present {
			return nil, fmt.Errorf("controller route %d references an absent peer %s", i, nextHop)
		}
		if value.GetKind() == lanewayv1.RouteKind_ROUTE_KIND_OVERLAY {
			if owner, present := overlayOwners[prefix.Addr()]; !present || owner != nextHop {
				return nil, fmt.Errorf("controller overlay route %d does not match peer ownership", i)
			}
		}
		if nextHop == local.NodeID && value.GetKind() == lanewayv1.RouteKind_ROUTE_KIND_SUBNET && !enabledPolicyCapabilities.Has(protocol.CapabilitySubnetRouterV1) {
			return nil, fmt.Errorf("controller route %d requires subnet-router policy capability", i)
		}
		if nextHop == local.NodeID && value.GetKind() == lanewayv1.RouteKind_ROUTE_KIND_EXIT && !enabledPolicyCapabilities.Has(protocol.CapabilityExitNodeV1) {
			return nil, fmt.Errorf("controller route %d requires exit-node policy capability", i)
		}
		if nextHop == local.NodeID || value.GetKind() == lanewayv1.RouteKind_ROUTE_KIND_EXIT {
			continue
		}
		routes = append(routes, routing.Route{Prefix: prefix, NextHop: nextHop, Metric: value.GetMetric()})
		if _, exists := seenOSPrefix[prefix]; !exists {
			seenOSPrefix[prefix] = struct{}{}
			osRoutes = append(osRoutes, platform.Route{Prefix: prefix})
		}
	}
	snapshot, err := routing.NewSnapshot(routes)
	if err != nil {
		return nil, err
	}
	osPlan := platform.RoutePlan{Routes: osRoutes, TransportBypass: append([]netip.Addr(nil), bypass...)}
	if err := platform.ValidateRoutePlan(osPlan); err != nil {
		return nil, err
	}
	forwarding, err := subnetManager.RequiredIPForwardFamilies(configuration, local)
	if err != nil {
		return nil, err
	}
	subnetPlan, forwardPrefixes, err := subnetManager.Prepare(configuration, local, true)
	if err != nil {
		return nil, err
	}
	if exitManagers != nil {
		if err := exitManagers.Validate(configuration, routes); err != nil {
			return nil, err
		}
	}
	return &preparedControllerConfiguration{
		configuration: configuration, routes: routes, snapshot: snapshot, osPlan: osPlan, policy: compiledPolicy, denyPolicy: denyPolicy,
		forwarding: forwarding, subnetPlan: subnetPlan, forwardPrefix: forwardPrefixes,
		revokedSerials: configuration.GetRevokedCertificateSerials(),
		failClosing:    failClosing,
	}, nil
}

func rollbackControllerConfiguration(ctx context.Context, previous *preparedControllerConfiguration, bypass []netip.Addr,
	routeManager platform.RouteManager, subnetManager *daemonSubnetManager, ipForwardManager *daemonIPForwardManager, exitManagers *daemonExitManagers,
) error {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = ctx // The apply context may be cancelled; rollback deliberately is not.
	var result error
	if exitManagers != nil {
		if previous == nil {
			result = errors.Join(result, exitManagers.Restore(rollbackCtx))
		} else {
			result = errors.Join(result, exitManagers.Apply(rollbackCtx, previous.configuration, previous.routes))
		}
	}
	if previous == nil {
		result = errors.Join(result, subnetManager.ApplyPlan(rollbackCtx, subnet.ForwardingPlan{}))
		result = errors.Join(result, routeManager.Apply(rollbackCtx, platform.RoutePlan{TransportBypass: bypass}))
		if ipForwardManager != nil {
			result = errors.Join(result, ipForwardManager.Apply(rollbackCtx, ipForwardFamilies{}))
		}
		return result
	}
	result = errors.Join(result, subnetManager.ApplyPlan(rollbackCtx, previous.subnetPlan))
	result = errors.Join(result, routeManager.Apply(rollbackCtx, previous.osPlan))
	if ipForwardManager != nil {
		result = errors.Join(result, ipForwardManager.Apply(rollbackCtx, previous.forwarding))
	}
	return result
}
