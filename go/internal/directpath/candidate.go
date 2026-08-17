// Package directpath provides authenticated, direct node-to-node packet paths.
package directpath

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/identity"
)

const (
	DefaultMaxCandidates  = 8
	AbsoluteMaxCandidates = 32
	DefaultCandidateTTL   = 2 * time.Minute
)

var (
	ErrInvalidCandidate  = errors.New("directpath: invalid endpoint candidate")
	ErrTooManyCandidates = errors.New("directpath: too many endpoint candidates")
	ErrUnauthorizedPeer  = errors.New("directpath: peer is not authorized for rendezvous")
)

// Candidate is a controller/relay-distributed endpoint for one authenticated
// node. Addresses are canonical unicast IP address/port pairs.
type Candidate struct {
	NodeID   identity.NodeID
	Address  netip.AddrPort
	Priority uint32
}

type CandidatePolicy struct {
	MaxCandidates  int
	AllowLoopback  bool
	AllowLinkLocal bool
}

func (p CandidatePolicy) normalized() (CandidatePolicy, error) {
	if p.MaxCandidates == 0 {
		p.MaxCandidates = DefaultMaxCandidates
	}
	if p.MaxCandidates < 1 || p.MaxCandidates > AbsoluteMaxCandidates {
		return CandidatePolicy{}, fmt.Errorf("%w: max candidates must be in [1,%d]", ErrInvalidCandidate, AbsoluteMaxCandidates)
	}
	return p, nil
}

func (p CandidatePolicy) Validate(candidate Candidate, expected identity.NodeID) error {
	if _, err := p.normalized(); err != nil {
		return err
	}
	if candidate.NodeID.IsZero() || (!expected.IsZero() && candidate.NodeID != expected) {
		return fmt.Errorf("%w: node identity mismatch", ErrInvalidCandidate)
	}
	address := candidate.Address.Addr()
	if !candidate.Address.IsValid() || candidate.Address.Port() == 0 || !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return fmt.Errorf("%w: address must be a specified unicast IP and nonzero port", ErrInvalidCandidate)
	}
	if address.Is4In6() {
		return fmt.Errorf("%w: IPv4-mapped IPv6 address is not canonical", ErrInvalidCandidate)
	}
	if address == netip.MustParseAddr("255.255.255.255") {
		return fmt.Errorf("%w: broadcast address is not permitted", ErrInvalidCandidate)
	}
	if address.IsLoopback() && !p.AllowLoopback {
		return fmt.Errorf("%w: loopback address is not permitted", ErrInvalidCandidate)
	}
	if address.IsLinkLocalUnicast() && !p.AllowLinkLocal {
		return fmt.Errorf("%w: link-local address is not permitted", ErrInvalidCandidate)
	}
	return nil
}

func CandidateFromProto(message *lanewayv1.EndpointCandidate, expected identity.NodeID, policy CandidatePolicy) (Candidate, error) {
	if message == nil || len(message.NodeId) != identity.IDSize || (len(message.IpAddress) != 4 && len(message.IpAddress) != 16) || message.Port == 0 || message.Port > 65535 || message.Transport != lanewayv1.EndpointTransport_ENDPOINT_TRANSPORT_QUIC_UDP {
		return Candidate{}, ErrInvalidCandidate
	}
	var nodeID identity.NodeID
	copy(nodeID[:], message.NodeId)
	address, ok := netip.AddrFromSlice(message.IpAddress)
	if !ok {
		return Candidate{}, ErrInvalidCandidate
	}
	candidate := Candidate{NodeID: nodeID, Address: netip.AddrPortFrom(address, uint16(message.Port)), Priority: message.Priority}
	if err := policy.Validate(candidate, expected); err != nil {
		return Candidate{}, err
	}
	return candidate, nil
}

func (c Candidate) Proto() *lanewayv1.EndpointCandidate {
	address := c.Address.Addr()
	return &lanewayv1.EndpointCandidate{
		NodeId:    append([]byte(nil), c.NodeID[:]...),
		IpAddress: append([]byte(nil), address.AsSlice()...),
		Port:      uint32(c.Address.Port()),
		Transport: lanewayv1.EndpointTransport_ENDPOINT_TRANSPORT_QUIC_UDP,
		Priority:  c.Priority,
	}
}

// ValidateCandidates validates, deduplicates, and orders a complete candidate
// update. Invalid updates are rejected atomically rather than partially used.
func ValidateCandidates(candidates []Candidate, expected identity.NodeID, policy CandidatePolicy) ([]Candidate, error) {
	policy, err := policy.normalized()
	if err != nil {
		return nil, err
	}
	if len(candidates) > policy.MaxCandidates {
		return nil, ErrTooManyCandidates
	}
	seen := make(map[netip.AddrPort]struct{}, len(candidates))
	out := make([]Candidate, len(candidates))
	for i, candidate := range candidates {
		if err := policy.Validate(candidate, expected); err != nil {
			return nil, fmt.Errorf("candidate %d: %w", i, err)
		}
		if _, exists := seen[candidate.Address]; exists {
			return nil, fmt.Errorf("%w: duplicate address %s", ErrInvalidCandidate, candidate.Address)
		}
		seen[candidate.Address] = struct{}{}
		out[i] = candidate
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].Address.String() < out[j].Address.String()
	})
	return out, nil
}
