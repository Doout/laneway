package nodeapp

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/endpointpin"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/netvalidate"
	"laneway.dev/laneway/internal/nodeservice"
)

var errControllerRuntimeUnauthorized = errors.New("controller withdrew active runtime authority")

const controllerRelayResolveLimit = 5 * time.Second

type nodeRuntimeAuthority struct {
	relayServiceID        identity.ID
	relayEndpoint         string
	directEnabled         bool
	maxCandidates         int
	candidateTTL          time.Duration
	certificateSerial     []byte
	certificateNotAfter   uint64
	certificateRenewAfter uint64
}

type nodeAuthorityStatus struct {
	candidateEnabled      bool
	candidateMax          uint32
	candidateTTLSeconds   uint32
	renewalNeeded         bool
	certificateRenewAfter uint64
	certificateNotAfter   uint64
	relayTargets          []nodeservice.RelayTarget
	relayBypass           []netip.Addr
}

func newNodeRuntimeAuthority(relayServiceID identity.ID, relayEndpoint string, directEnabled bool,
	maxCandidates int, candidateTTL time.Duration, certificate *x509.Certificate,
) (*nodeRuntimeAuthority, error) {
	if relayServiceID.IsZero() || certificate == nil || certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 {
		return nil, errors.New("node runtime authority is incomplete")
	}
	endpoint, err := canonicalRelayEndpoint(relayEndpoint)
	if err != nil {
		return nil, fmt.Errorf("active relay endpoint: %w", err)
	}
	if certificate.NotAfter.Unix() <= 0 {
		return nil, errors.New("node certificate expiry is invalid")
	}
	lifetime := certificate.NotAfter.Sub(certificate.NotBefore)
	if lifetime <= 0 {
		return nil, errors.New("node certificate lifetime is invalid")
	}
	return &nodeRuntimeAuthority{
		relayServiceID: relayServiceID, relayEndpoint: endpoint,
		directEnabled: directEnabled, maxCandidates: maxCandidates, candidateTTL: candidateTTL,
		certificateSerial:     append([]byte(nil), certificate.SerialNumber.Bytes()...),
		certificateNotAfter:   uint64(certificate.NotAfter.Unix()),
		certificateRenewAfter: uint64(certificate.NotBefore.Add(lifetime * 2 / 3).Unix()),
	}, nil
}

func validateNodeRuntimeAuthority(configuration *lanewayv1.NodeConfiguration, authority *nodeRuntimeAuthority, now time.Time) (nodeAuthorityStatus, error) {
	if authority == nil {
		return nodeAuthorityStatus{}, nil
	}
	if len(configuration.GetRelays()) == 0 {
		return nodeAuthorityStatus{}, fmt.Errorf("%w: controller authorized no relays", errControllerRuntimeUnauthorized)
	}
	if len(configuration.GetRelays()) > netvalidate.MaxRelayEndpoints {
		return nodeAuthorityStatus{}, errors.New("controller relay snapshot exceeds limit")
	}
	seenRelayIDs := make(map[identity.ID]struct{}, len(configuration.GetRelays()))
	seenRelayNames := make(map[string]struct{}, len(configuration.GetRelays()))
	seenRelayTargets := make([]nodeservice.RelayTarget, 0, len(configuration.GetRelays()))
	for i, relay := range configuration.GetRelays() {
		if relay == nil || len(relay.GetServiceId()) != identity.IDSize || relay.GetName() == "" ||
			relay.GetName() != strings.TrimSpace(relay.GetName()) || len(relay.GetName()) > 253 {
			return nodeAuthorityStatus{}, fmt.Errorf("controller relay %d has an invalid identity or name", i)
		}
		var serviceID identity.ID
		copy(serviceID[:], relay.GetServiceId())
		endpoint, err := canonicalRelayEndpoint(relay.GetEndpoint())
		if serviceID.IsZero() || err != nil {
			return nodeAuthorityStatus{}, fmt.Errorf("controller relay %d is invalid", i)
		}
		if _, duplicate := seenRelayIDs[serviceID]; duplicate {
			return nodeAuthorityStatus{}, fmt.Errorf("controller relay %d duplicates service ID", i)
		}
		if _, duplicate := seenRelayNames[relay.GetName()]; duplicate {
			return nodeAuthorityStatus{}, fmt.Errorf("controller relay %d duplicates name", i)
		}
		seenRelayIDs[serviceID], seenRelayNames[relay.GetName()] = struct{}{}, struct{}{}
		statusTarget := nodeservice.RelayTarget{ServiceID: serviceID, Address: endpoint}
		seenRelayTargets = append(seenRelayTargets, statusTarget)
	}
	if len(seenRelayTargets) == 0 {
		return nodeAuthorityStatus{}, fmt.Errorf("%w: controller authorized no relays", errControllerRuntimeUnauthorized)
	}
	sort.Slice(seenRelayTargets, func(i, j int) bool {
		if seenRelayTargets[i].ServiceID != seenRelayTargets[j].ServiceID {
			return seenRelayTargets[i].ServiceID.String() < seenRelayTargets[j].ServiceID.String()
		}
		return seenRelayTargets[i].Address < seenRelayTargets[j].Address
	})

	candidate := configuration.GetCandidateExchange()
	if candidate == nil {
		return nodeAuthorityStatus{}, errors.New("controller omitted candidate exchange policy")
	}
	if candidate.GetMaxCandidates() > 32 || candidate.GetCandidateTtlSeconds() > 600 ||
		(candidate.GetEnabled() && (candidate.GetMaxCandidates() == 0 || candidate.GetCandidateTtlSeconds() == 0)) {
		return nodeAuthorityStatus{}, errors.New("controller candidate exchange policy is outside bounds")
	}

	exitPolicy := configuration.GetExitPolicy()
	if exitPolicy == nil {
		return nodeAuthorityStatus{}, errors.New("controller omitted exit policy")
	}
	authorizedExits := make(map[identity.NodeID]struct{}, len(exitPolicy.GetAuthorizedNodeIds()))
	for i, raw := range exitPolicy.GetAuthorizedNodeIds() {
		if len(raw) != identity.IDSize {
			return nodeAuthorityStatus{}, fmt.Errorf("controller exit policy node %d is invalid", i)
		}
		var node identity.NodeID
		copy(node[:], raw)
		if node.IsZero() {
			return nodeAuthorityStatus{}, fmt.Errorf("controller exit policy node %d is zero", i)
		}
		if _, duplicate := authorizedExits[node]; duplicate {
			return nodeAuthorityStatus{}, fmt.Errorf("controller exit policy node %d is duplicate", i)
		}
		authorizedExits[node] = struct{}{}
	}
	routeExits := make(map[identity.NodeID]struct{})
	for _, route := range configuration.GetRoutes().GetRoutes() {
		if route.GetKind() != lanewayv1.RouteKind_ROUTE_KIND_EXIT || len(route.GetViaNodeId()) != identity.IDSize {
			continue
		}
		var node identity.NodeID
		copy(node[:], route.GetViaNodeId())
		routeExits[node] = struct{}{}
	}
	if !sameNodeSet(authorizedExits, routeExits) {
		return nodeAuthorityStatus{}, errors.New("controller exit policy disagrees with approved exit routes")
	}

	health := configuration.GetCertificateHealth()
	if health == nil || !bytes.Equal(health.GetPresentedSerial(), authority.certificateSerial) ||
		health.GetNotAfterUnixSeconds() != authority.certificateNotAfter ||
		health.GetRenewAfterUnixSeconds() != authority.certificateRenewAfter {
		return nodeAuthorityStatus{}, errors.New("controller certificate health does not match the presented certificate")
	}
	revoked := false
	for _, serial := range configuration.GetRevokedCertificateSerials() {
		revoked = revoked || bytes.Equal(serial, authority.certificateSerial)
	}
	if health.GetRevoked() != revoked {
		return nodeAuthorityStatus{}, errors.New("controller certificate health disagrees with revocation snapshot")
	}
	if revoked || health.GetNotAfterUnixSeconds() <= uint64(now.Unix()) {
		return nodeAuthorityStatus{}, fmt.Errorf("%w: local certificate is revoked or expired", errControllerRuntimeUnauthorized)
	}
	return nodeAuthorityStatus{
		candidateEnabled:      candidate.GetEnabled(),
		candidateMax:          candidate.GetMaxCandidates(),
		candidateTTLSeconds:   candidate.GetCandidateTtlSeconds(),
		renewalNeeded:         uint64(now.Unix()) >= health.GetRenewAfterUnixSeconds(),
		certificateRenewAfter: health.GetRenewAfterUnixSeconds(),
		certificateNotAfter:   health.GetNotAfterUnixSeconds(),
		relayTargets:          seenRelayTargets,
	}, nil
}

func resolveNodeRelayTargets(ctx context.Context, targets []nodeservice.RelayTarget) ([]nodeservice.RelayTarget, []netip.Addr, error) {
	return resolveNodeRelayTargetsWithOptions(ctx, targets, endpointpin.Options{}, controllerRelayResolveLimit)
}

type relayResolution struct {
	target    nodeservice.RelayTarget
	endpoints []endpointpin.Endpoint
	err       error
}

func resolveNodeRelayTargetsWithOptions(ctx context.Context, targets []nodeservice.RelayTarget,
	options endpointpin.Options, timeout time.Duration,
) ([]nodeservice.RelayTarget, []netip.Addr, error) {
	if len(targets) == 0 || len(targets) > netvalidate.MaxRelayEndpoints {
		return nil, nil, errors.New("controller relay target set is outside bounds")
	}
	if timeout <= 0 {
		return nil, nil, errors.New("controller relay resolution timeout is invalid")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	results := make(chan relayResolution, len(targets))
	for _, target := range targets {
		target := target
		go func() {
			endpoints, err := endpointpin.HostPorts(resolveCtx, target.Address, options, netvalidate.MaxRelayAddressesPerEndpoint)
			// One buffered slot is reserved per lookup, so a resolver completing
			// after the global deadline cannot block while reporting its result.
			results <- relayResolution{target: target, endpoints: endpoints, err: err}
		}()
	}

	resolved := make([]nodeservice.RelayTarget, 0, len(targets))
	addresses := make([]netip.Addr, 0, len(targets))
	var firstError error
	collect := func(result relayResolution) {
		if result.err != nil {
			if firstError == nil {
				firstError = fmt.Errorf("resolve controller relay %s: %w", result.target.ServiceID, result.err)
			}
			return
		}
		for _, endpoint := range result.endpoints {
			target := result.target
			target.Address = endpoint.DialAddress
			resolved = append(resolved, target)
			addresses = append(addresses, endpoint.Address)
		}
	}
	remaining := len(targets)
collection:
	for remaining > 0 {
		select {
		case result := <-results:
			remaining--
			collect(result)
		case <-resolveCtx.Done():
			break collection
		}
	}
	if remaining > 0 {
		cancel()
		// Retain results already completed at the deadline without waiting on
		// a resolver that fails to honor context cancellation.
		for {
			select {
			case result := <-results:
				collect(result)
			default:
				goto collected
			}
		}
	}

collected:
	sort.Slice(resolved, func(i, j int) bool {
		if resolved[i].ServiceID != resolved[j].ServiceID {
			return resolved[i].ServiceID.String() < resolved[j].ServiceID.String()
		}
		return resolved[i].Address < resolved[j].Address
	})
	uniqueTargets := resolved[:0]
	for _, target := range resolved {
		if len(uniqueTargets) != 0 {
			previous := uniqueTargets[len(uniqueTargets)-1]
			if previous.ServiceID == target.ServiceID && previous.Address == target.Address {
				continue
			}
		}
		uniqueTargets = append(uniqueTargets, target)
	}
	resolved = uniqueTargets
	if len(resolved) == 0 {
		if resolveCtx.Err() != nil {
			return nil, nil, fmt.Errorf("controller relay authority resolved to no usable targets: %w", resolveCtx.Err())
		}
		if firstError != nil {
			return nil, nil, fmt.Errorf("controller relay authority resolved to no usable targets: %w", firstError)
		}
		return nil, nil, errors.New("controller relay authority resolved to no usable targets")
	}
	if len(resolved) > netvalidate.MaxRelayTargets {
		return nil, nil, errors.New("controller relay authority resolved outside target bounds")
	}
	uniqueAddresses := make(map[netip.Addr]struct{}, len(addresses))
	bypass := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if _, exists := uniqueAddresses[address]; exists {
			continue
		}
		uniqueAddresses[address] = struct{}{}
		bypass = append(bypass, address)
	}
	sort.Slice(bypass, func(i, j int) bool { return bypass[i].Compare(bypass[j]) < 0 })
	return resolved, bypass, nil
}

func canonicalRelayEndpoint(value string) (string, error) {
	return netvalidate.CanonicalHostPort(value)
}

func sameNodeSet(left, right map[identity.NodeID]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for node := range left {
		if _, ok := right[node]; !ok {
			return false
		}
	}
	return true
}
