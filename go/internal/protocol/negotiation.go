package protocol

import (
	"errors"
	"fmt"
	"strings"
)

type Capability uint64

const (
	CapabilityRelayV1 Capability = 1 << iota
	CapabilityQUICDatagramV1
	CapabilityDirectPeerV1
	CapabilitySubnetRouterV1
	CapabilityExitNodeV1
	CapabilityTCPFallbackV1
	CapabilityIPv6V1
	CapabilityE2EPacketV1
)

const KnownCapabilities = CapabilityRelayV1 |
	CapabilityQUICDatagramV1 |
	CapabilityDirectPeerV1 |
	CapabilitySubnetRouterV1 |
	CapabilityExitNodeV1 |
	CapabilityTCPFallbackV1 |
	CapabilityIPv6V1 |
	CapabilityE2EPacketV1

func (c Capability) Has(want Capability) bool              { return c&want == want }
func (c Capability) Intersect(other Capability) Capability { return c & other }
func (c Capability) Unknown() Capability                   { return c &^ KnownCapabilities }

func (c Capability) String() string {
	if c == 0 {
		return "none"
	}
	names := []struct {
		bit  Capability
		name string
	}{
		{CapabilityRelayV1, "relay-v1"},
		{CapabilityQUICDatagramV1, "quic-datagram-v1"},
		{CapabilityDirectPeerV1, "direct-peer-v1"},
		{CapabilitySubnetRouterV1, "subnet-router-v1"},
		{CapabilityExitNodeV1, "exit-node-v1"},
		{CapabilityTCPFallbackV1, "tcp-fallback-v1"},
		{CapabilityIPv6V1, "ipv6-v1"},
		{CapabilityE2EPacketV1, "e2e-packet-v1"},
	}
	parts := make([]string, 0, len(names)+1)
	for _, n := range names {
		if c.Has(n.bit) {
			parts = append(parts, n.name)
		}
	}
	if unknown := c.Unknown(); unknown != 0 {
		parts = append(parts, fmt.Sprintf("unknown(%#x)", uint64(unknown)))
	}
	return strings.Join(parts, ",")
}

type Version struct {
	Major uint32
	Minor uint32
}

const ProtocolMajor1 = uint32(1)

var ErrIncompatibleVersion = errors.New("incompatible Laneway protocol version")

type Negotiated struct {
	Version      Version
	Capabilities Capability
}

// Negotiate requires equal, non-zero major versions, selects the lower minor
// version, and enables only capabilities advertised by both endpoints. Unknown
// bits are deliberately removed so future peers fail closed on new features.
func Negotiate(local, remote Version, localCaps, remoteCaps Capability) (Negotiated, error) {
	if local.Major != ProtocolMajor1 || remote.Major != ProtocolMajor1 {
		return Negotiated{}, fmt.Errorf("%w: local %d.%d, remote %d.%d", ErrIncompatibleVersion,
			local.Major, local.Minor, remote.Major, remote.Minor)
	}
	minor := local.Minor
	if remote.Minor < minor {
		minor = remote.Minor
	}
	return Negotiated{
		Version:      Version{Major: local.Major, Minor: minor},
		Capabilities: localCaps.Intersect(remoteCaps).Intersect(KnownCapabilities),
	}, nil
}
