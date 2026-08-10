package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/policy"
	"laneway.dev/laneway/internal/relayservice"
	"laneway.dev/laneway/internal/revocation"
)

type relayConfigurationSource interface {
	RelayConfiguration(context.Context, uint64) (*lanewayv1.RelayConfiguration, bool, error)
}

// controllerRelayState publishes the peer authorization set and ACL engine as
// one pointer swap. Calls already in flight may finish against the previous
// complete snapshot; no call can observe a half-installed controller update.
type controllerRelayState struct {
	network     identity.NetworkID
	revoked     *revocation.Set
	certificate *relayCertificateHealth
	current     atomic.Pointer[controllerRelaySnapshot]
}

type controllerRelaySnapshot struct {
	epoch                 uint64
	validUntil            int64
	authorizer            *relayservice.AtomicAuthorizer
	policy                *policy.Engine
	renewalNeeded         bool
	certificateRenewAfter uint64
	certificateNotAfter   uint64
}

type relayCertificateHealth struct {
	serial               []byte
	notAfter, renewAfter uint64
}

func (s *controllerRelayState) SetLocalCertificate(certificate *x509.Certificate) error {
	if certificate == nil || certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 || !certificate.NotAfter.After(certificate.NotBefore) || certificate.NotAfter.Unix() <= 0 {
		return errors.New("relay local certificate health is invalid")
	}
	lifetime := certificate.NotAfter.Sub(certificate.NotBefore)
	s.certificate = &relayCertificateHealth{serial: append([]byte(nil), certificate.SerialNumber.Bytes()...), notAfter: uint64(certificate.NotAfter.Unix()), renewAfter: uint64(certificate.NotBefore.Add(lifetime * 2 / 3).Unix())}
	return nil
}

func newControllerRelayState(network identity.NetworkID, revokedSets ...*revocation.Set) (*controllerRelayState, error) {
	if network.IsZero() {
		return nil, errors.New("relay controller state requires a network identity")
	}
	state := &controllerRelayState{network: network}
	if len(revokedSets) != 0 {
		state.revoked = revokedSets[0]
	}
	return state, nil
}

func (s *controllerRelayState) Replace(configuration *lanewayv1.RelayConfiguration) error {
	next, err := compileRelayConfiguration(configuration, s.network, s.certificate)
	if err != nil {
		return err
	}
	if current := s.current.Load(); current != nil && next.epoch <= current.epoch {
		return fmt.Errorf("controller relay configuration epoch %d did not advance from %d", next.epoch, current.epoch)
	}
	if s.revoked != nil {
		if err := s.revoked.Replace(configuration.GetRevokedCertificateSerials()); err != nil {
			return fmt.Errorf("install controller certificate revocations: %w", err)
		}
	}
	s.current.Store(next)
	return nil
}

func (s *controllerRelayState) Epoch() uint64 {
	if s == nil {
		return 0
	}
	snapshot := s.current.Load()
	if snapshot == nil {
		return 0
	}
	return snapshot.epoch
}

func (s *controllerRelayState) Authorize(ctx context.Context, node identity.NodeIdentity) (relayservice.Authorization, error) {
	if s == nil || node.NetworkID != s.network {
		return relayservice.Authorization{}, relayservice.ErrUnauthorized
	}
	snapshot := s.current.Load()
	if snapshot == nil || time.Now().Unix() >= snapshot.validUntil {
		return relayservice.Authorization{}, relayservice.ErrUnauthorized
	}
	return snapshot.authorizer.Authorize(ctx, node)
}

func (s *controllerRelayState) Allow(source, destination identity.NodeIdentity, packet []byte) bool {
	if s == nil || source.NetworkID != s.network || destination.NetworkID != s.network {
		return false
	}
	snapshot := s.current.Load()
	return snapshot != nil && time.Now().Unix() < snapshot.validUntil &&
		relayPacketAllowed(snapshot.policy, source.NodeID, destination.NodeID, packet)
}

func relayPacketAllowed(engine *policy.Engine, source, destination identity.NodeID, packet []byte) bool {
	result := engine.Evaluate(source, destination, packet)
	if result.Action == policy.Accept {
		return true
	}
	// Source-prefix validation has already bound this packet to the
	// authenticated sender. Preserve explicit direction-specific rules, but
	// allow an unmatched default denial to consult the initiating ACL in
	// reverse so replies from an authorized Connector can cross the relay.
	if result.Matched {
		return false
	}
	return engine.EvaluateReturn(source, destination, packet).Action == policy.Accept
}

func (s *controllerRelayState) Renew(validUntil uint64) error {
	deadline, err := relayConfigurationDeadline(validUntil)
	if err != nil {
		return err
	}
	for {
		current := s.current.Load()
		if current == nil {
			return errors.New("cannot renew an uninitialized relay configuration")
		}
		if deadline < current.validUntil {
			return fmt.Errorf("controller relay lease deadline %d moved backwards from %d", deadline, current.validUntil)
		}
		next := &controllerRelaySnapshot{epoch: current.epoch, validUntil: deadline, authorizer: current.authorizer, policy: current.policy, renewalNeeded: current.renewalNeeded, certificateRenewAfter: current.certificateRenewAfter, certificateNotAfter: current.certificateNotAfter}
		if s.current.CompareAndSwap(current, next) {
			return nil
		}
	}
}

func (s *controllerRelayState) ValidUntil() time.Time {
	if s == nil {
		return time.Time{}
	}
	current := s.current.Load()
	if current == nil {
		return time.Time{}
	}
	return time.Unix(current.validUntil, 0).UTC()
}

func relayConfigurationDeadline(seconds uint64) (int64, error) {
	if seconds == 0 || seconds > uint64(1<<63-1) || int64(seconds) <= time.Now().Unix() {
		return 0, errors.New("controller relay configuration snapshot is expired or has no validity deadline")
	}
	return int64(seconds), nil
}

func compileRelayConfiguration(configuration *lanewayv1.RelayConfiguration, expected identity.NetworkID, localHealth ...*relayCertificateHealth) (*controllerRelaySnapshot, error) {
	if configuration == nil || configuration.GetConfigurationEpoch() == 0 || configuration.GetPolicy() == nil ||
		len(configuration.GetNetworkId()) != identity.IDSize {
		return nil, errors.New("controller returned an incomplete relay configuration")
	}
	var network identity.NetworkID
	copy(network[:], configuration.GetNetworkId())
	if network.IsZero() || network != expected {
		return nil, errors.New("controller relay configuration belongs to another network")
	}
	validUntil, err := relayConfigurationDeadline(configuration.GetValidUntilUnixSeconds())
	if err != nil {
		return nil, err
	}
	if health := configuration.GetCertificateHealth(); health != nil {
		if len(health.GetPresentedSerial()) == 0 || len(health.GetPresentedSerial()) > 32 || health.GetRevoked() ||
			health.GetNotAfterUnixSeconds() <= uint64(time.Now().Unix()) || health.GetRenewAfterUnixSeconds() == 0 ||
			health.GetRenewAfterUnixSeconds() > health.GetNotAfterUnixSeconds() {
			return nil, errors.New("controller relay certificate health is invalid")
		}
		if len(localHealth) != 0 && localHealth[0] != nil {
			expectedHealth := localHealth[0]
			revoked := false
			for _, serial := range configuration.GetRevokedCertificateSerials() {
				revoked = revoked || bytes.Equal(serial, expectedHealth.serial)
			}
			if !bytes.Equal(health.GetPresentedSerial(), expectedHealth.serial) || health.GetNotAfterUnixSeconds() != expectedHealth.notAfter || health.GetRenewAfterUnixSeconds() != expectedHealth.renewAfter || health.GetRevoked() != revoked {
				return nil, errors.New("controller relay certificate health does not match local certificate")
			}
			if revoked {
				return nil, errors.New("controller revoked local relay certificate")
			}
		}
	}
	if len(localHealth) != 0 && localHealth[0] != nil && configuration.GetCertificateHealth() == nil {
		return nil, errors.New("controller omitted relay certificate health")
	}
	if err := new(revocation.Set).Replace(configuration.GetRevokedCertificateSerials()); err != nil {
		return nil, fmt.Errorf("controller relay revocations: %w", err)
	}
	if configuration.GetPolicy().GetDefaultAction() != lanewayv1.PolicyAction_POLICY_ACTION_DENY {
		return nil, errors.New("controller relay policy must default deny")
	}
	compiledPolicy, err := policy.Compile(configuration.GetPolicy())
	if err != nil {
		return nil, fmt.Errorf("compile controller relay policy: %w", err)
	}
	if compiledPolicy.NetworkID() != network || compiledPolicy.Epoch() != configuration.GetConfigurationEpoch() {
		return nil, errors.New("controller relay policy network or epoch does not match configuration")
	}

	assignments := make(map[identity.NodeIdentity]relayservice.Authorization, len(configuration.GetPeers()))
	overlayOwners := make(map[netip.Addr]identity.NodeID)
	for i, peer := range configuration.GetPeers() {
		if peer == nil || len(peer.GetNodeId()) != identity.IDSize {
			return nil, fmt.Errorf("controller relay peer %d has an invalid node ID", i)
		}
		var nodeID identity.NodeID
		copy(nodeID[:], peer.GetNodeId())
		if nodeID.IsZero() {
			return nil, fmt.Errorf("controller relay peer %d has a zero node ID", i)
		}
		node := identity.NodeIdentity{NetworkID: network, NodeID: nodeID}
		if _, duplicate := assignments[node]; duplicate {
			return nil, fmt.Errorf("controller relay peer %d duplicates node %s", i, nodeID)
		}
		authorization := relayservice.Authorization{}
		for j, raw := range peer.GetOverlayAddresses() {
			address, err := relayAddress(raw)
			if err != nil {
				return nil, fmt.Errorf("controller relay peer %d overlay %d: %w", i, j, err)
			}
			if owner, duplicate := overlayOwners[address]; duplicate {
				return nil, fmt.Errorf("controller relay overlay %s is assigned to nodes %s and %s", address, owner, nodeID)
			}
			overlayOwners[address] = nodeID
			authorization.OverlayAddresses = append(authorization.OverlayAddresses, address)
		}
		for j, raw := range peer.GetAuthorizedPrefixes() {
			prefix, err := relayPrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("controller relay peer %d prefix %d: %w", i, j, err)
			}
			authorization.AuthorizedPrefixes = append(authorization.AuthorizedPrefixes, prefix)
		}
		if len(authorization.OverlayAddresses) == 0 || len(authorization.AuthorizedPrefixes) == 0 {
			return nil, fmt.Errorf("controller relay peer %d has an incomplete authorization", i)
		}
		for _, address := range authorization.OverlayAddresses {
			host := netip.PrefixFrom(address, address.BitLen())
			found := false
			for _, prefix := range authorization.AuthorizedPrefixes {
				if prefix == host {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("controller relay peer %d does not own overlay host prefix %s", i, host)
			}
		}
		assignments[node] = authorization
	}
	authorizer := new(relayservice.AtomicAuthorizer)
	if err := authorizer.Replace(assignments); err != nil {
		return nil, fmt.Errorf("install controller relay authorizations: %w", err)
	}
	snapshot := &controllerRelaySnapshot{epoch: configuration.GetConfigurationEpoch(), validUntil: validUntil, authorizer: authorizer, policy: compiledPolicy}
	if health := configuration.GetCertificateHealth(); health != nil {
		snapshot.renewalNeeded = uint64(time.Now().Unix()) >= health.GetRenewAfterUnixSeconds()
		snapshot.certificateRenewAfter = health.GetRenewAfterUnixSeconds()
		snapshot.certificateNotAfter = health.GetNotAfterUnixSeconds()
	}
	return snapshot, nil
}

func (s *controllerRelayState) CertificateHealth() (bool, uint64, uint64) {
	return s.certificateHealthAt(time.Now())
}

func (s *controllerRelayState) certificateHealthAt(now time.Time) (bool, uint64, uint64) {
	current := s.current.Load()
	if current == nil {
		return false, 0, 0
	}
	renewalNeeded := current.renewalNeeded
	if current.certificateRenewAfter != 0 && now.Unix() >= 0 {
		renewalNeeded = renewalNeeded || uint64(now.Unix()) >= current.certificateRenewAfter
	}
	return renewalNeeded, current.certificateRenewAfter, current.certificateNotAfter
}

func relayAddress(raw []byte) (netip.Addr, error) {
	address, ok := netip.AddrFromSlice(raw)
	if !ok || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() {
		return netip.Addr{}, errors.New("address is not a canonical unicast IP address")
	}
	return address, nil
}

func relayPrefix(value *lanewayv1.IpPrefix) (netip.Prefix, error) {
	if value == nil {
		return netip.Prefix{}, errors.New("prefix is nil")
	}
	address, ok := netip.AddrFromSlice(value.GetAddress())
	if !ok || address.Is4In6() || value.GetPrefixLength() > uint32(address.BitLen()) {
		return netip.Prefix{}, errors.New("prefix address or length is invalid")
	}
	prefix := netip.PrefixFrom(address, int(value.GetPrefixLength()))
	if prefix != prefix.Masked() {
		return netip.Prefix{}, errors.New("prefix is noncanonical")
	}
	return prefix, nil
}

// runRelayConfigurationUpdates retries controller failures with a capped
// exponential delay, publishes readiness only after a complete initial
// snapshot, and then polls by epoch for the lifetime of the relay.
func runRelayConfigurationUpdates(ctx context.Context, interval time.Duration, source relayConfigurationSource,
	state *controllerRelayState, reauthorize func(context.Context) error, ready chan<- error, report func(error),
) error {
	if ctx == nil || source == nil || state == nil || interval <= 0 {
		err := errors.New("invalid relay controller update configuration")
		if ready != nil {
			ready <- err
		}
		return err
	}
	if report == nil {
		report = func(error) {}
	}
	readySent := state.Epoch() != 0
	expiryApplied := false
	delay := time.Duration(0)
	for {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				if !readySent && ready != nil {
					ready <- ctx.Err()
				}
				return ctx.Err()
			case <-timer.C:
			}
		}

		configuration, unchanged, err := source.RelayConfiguration(ctx, state.Epoch())
		if err == nil {
			switch {
			case unchanged && state.Epoch() == 0:
				err = errors.New("controller returned not-modified before the initial relay configuration")
			case unchanged:
				if configuration == nil {
					err = errors.New("controller not-modified response omitted snapshot validity")
				} else {
					err = state.Renew(configuration.GetValidUntilUnixSeconds())
				}
			case !unchanged:
				err = state.Replace(configuration)
				if err == nil && reauthorize != nil {
					err = reauthorize(ctx)
				}
			}
		}
		if err == nil {
			expiryApplied = false
			if !readySent {
				readySent = true
				if ready != nil {
					ready <- nil
				}
			}
			delay = interval
			if until := time.Until(state.ValidUntil()); until > 0 && until < delay {
				delay = until
			}
			continue
		}
		if ctx.Err() != nil {
			if !readySent && ready != nil {
				ready <- ctx.Err()
			}
			return ctx.Err()
		}
		report(err)
		if !expiryApplied && !state.ValidUntil().IsZero() && !state.ValidUntil().After(time.Now()) {
			if reauthorize != nil {
				if expiryErr := reauthorize(ctx); expiryErr != nil {
					report(fmt.Errorf("expire controller relay snapshot: %w", expiryErr))
				}
			}
			expiryApplied = true
		}
		if delay == 0 || delay >= interval {
			delay = min(time.Second, interval)
		} else {
			delay = min(delay*2, interval)
		}
		if until := time.Until(state.ValidUntil()); until > 0 && until < delay {
			delay = until
		}
	}
}
