package agent

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
)

const (
	RequiredRelayCapabilities       = protocol.CapabilityRelayV1 | protocol.CapabilityQUICDatagramV1
	RequiredTCPFallbackCapabilities = protocol.CapabilityRelayV1 | protocol.CapabilityTCPFallbackV1
)

func hasRequiredTransport(capabilities protocol.Capability) bool {
	return capabilities.Has(RequiredRelayCapabilities) || capabilities.Has(RequiredTCPFallbackCapabilities)
}

type HelloResult struct {
	BootID     identity.ID
	Negotiated protocol.Negotiated
}

type SessionParameters struct {
	SessionID                  identity.ID
	ConfigurationEpoch         uint64
	OverlayAddresses           []netip.Addr
	Capabilities               protocol.Capability
	EffectiveMaxControlPayload uint32
	MaxPacketPayload           uint32
}

func (p SessionParameters) ControlFramer() protocol.ControlFramer {
	return protocol.ControlFramer{MaxPayload: p.EffectiveMaxControlPayload}
}

func exactNonzeroID(field string, raw []byte) (identity.ID, error) {
	if len(raw) != identity.IDSize {
		return identity.ID{}, malformed(ErrInvalidIdentifier, "%s length %d, expected %d", field, len(raw), identity.IDSize)
	}
	var id identity.ID
	copy(id[:], raw)
	if id.IsZero() {
		return identity.ID{}, malformed(ErrInvalidIdentifier, "%s is zero", field)
	}
	return id, nil
}

// NewHello constructs the client's identity-bound session greeting. Unknown
// capability bits are cleared before transmission.
func NewHello(authenticated identity.NodeIdentity, bootID identity.ID, version protocol.Version, capabilities protocol.Capability) (*lanewayv1.Hello, error) {
	if err := authenticated.Validate(); err != nil {
		return nil, sessionError(lanewayv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED, ErrUnauthenticated, "invalid local identity: %v", err)
	}
	if bootID.IsZero() {
		return nil, malformed(ErrInvalidIdentifier, "boot_id is zero")
	}
	if version.Major != protocol.ProtocolMajor1 {
		return nil, unsupported(ErrUnsupportedVersion, "local protocol version %d.%d", version.Major, version.Minor)
	}
	capabilities = capabilities.Intersect(protocol.KnownCapabilities)
	if !hasRequiredTransport(capabilities) {
		return nil, unsupported(ErrRequiredCapabilities, "local capabilities %s lack a supported relay transport", capabilities)
	}
	return &lanewayv1.Hello{
		NetworkId:     append([]byte(nil), authenticated.NetworkID[:]...),
		NodeId:        append([]byte(nil), authenticated.NodeID[:]...),
		BootId:        append([]byte(nil), bootID[:]...),
		ProtocolMajor: version.Major,
		ProtocolMinor: version.Minor,
		Capabilities:  uint64(capabilities),
	}, nil
}

// ValidateHello authenticates the claimed IDs and negotiates the relay's
// supported version and capabilities. It does not allocate a session.
func ValidateHello(hello *lanewayv1.Hello, authenticated identity.NodeIdentity, localVersion protocol.Version, localCapabilities protocol.Capability) (HelloResult, error) {
	if hello == nil {
		return HelloResult{}, malformed(ErrMalformed, "Hello is nil")
	}
	networkID, err := exactNonzeroID("network_id", hello.GetNetworkId())
	if err != nil {
		return HelloResult{}, err
	}
	nodeID, err := exactNonzeroID("node_id", hello.GetNodeId())
	if err != nil {
		return HelloResult{}, err
	}
	bootID, err := exactNonzeroID("boot_id", hello.GetBootId())
	if err != nil {
		return HelloResult{}, err
	}
	if err := authenticated.Validate(); err != nil {
		return HelloResult{}, sessionError(lanewayv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED, ErrUnauthenticated, "invalid authenticated identity: %v", err)
	}
	if authenticated.NetworkID != identity.NetworkID(networkID) || authenticated.NodeID != identity.NodeID(nodeID) {
		return HelloResult{}, sessionError(lanewayv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED, ErrIdentityMismatch, "claimed network/node IDs differ from certificate")
	}
	negotiated, err := protocol.Negotiate(
		localVersion,
		protocol.Version{Major: hello.GetProtocolMajor(), Minor: hello.GetProtocolMinor()},
		localCapabilities,
		protocol.Capability(hello.GetCapabilities()),
	)
	if err != nil {
		return HelloResult{}, unsupported(ErrUnsupportedVersion, "%v", err)
	}
	if !hasRequiredTransport(negotiated.Capabilities) {
		return HelloResult{}, unsupported(ErrRequiredCapabilities, "intersection %s lacks a supported relay transport", negotiated.Capabilities)
	}
	return HelloResult{BootID: bootID, Negotiated: negotiated}, nil
}

type WelcomeConfig struct {
	SessionID          identity.ID
	ConfigurationEpoch uint64
	OverlayAddresses   []netip.Addr
	MaxControlPayload  uint32
	MaxPacketPayload   uint32
}

func validateControlLimit(limit uint32) error {
	if limit == 0 || limit > protocol.DefaultMaxControlFrame {
		return malformed(ErrInvalidControlLimit, "max_control_payload %d outside [1,%d]", limit, protocol.DefaultMaxControlFrame)
	}
	return nil
}

func validatePacketLimit(limit uint32) error {
	if limit == 0 || limit > uint32(protocol.MaxPacketPayload) {
		return malformed(ErrInvalidPacketLimit, "max_packet_payload %d outside [1,%d]", limit, protocol.MaxPacketPayload)
	}
	return nil
}

// NewWelcome constructs the relay response from a completed Hello
// negotiation. The caller supplies a fresh random, nonzero SessionID.
func NewWelcome(config WelcomeConfig, negotiated protocol.Negotiated) (*lanewayv1.Welcome, error) {
	if config.SessionID.IsZero() {
		return nil, malformed(ErrInvalidIdentifier, "session_id is zero")
	}
	if negotiated.Version.Major != protocol.ProtocolMajor1 {
		return nil, unsupported(ErrUnsupportedVersion, "negotiated protocol major %d", negotiated.Version.Major)
	}
	capabilities := negotiated.Capabilities.Intersect(protocol.KnownCapabilities)
	if !hasRequiredTransport(capabilities) {
		return nil, unsupported(ErrRequiredCapabilities, "intersection %s lacks a supported relay transport", capabilities)
	}
	if err := validateControlLimit(config.MaxControlPayload); err != nil {
		return nil, err
	}
	if err := validatePacketLimit(config.MaxPacketPayload); err != nil {
		return nil, err
	}
	addresses := make([][]byte, 0, len(config.OverlayAddresses))
	for i, address := range config.OverlayAddresses {
		if !address.IsValid() {
			return nil, malformed(ErrInvalidOverlayAddress, "overlay_addresses[%d] is invalid", i)
		}
		address = address.Unmap()
		if address.Is6() && !capabilities.Has(protocol.CapabilityIPv6V1) {
			continue
		}
		addresses = append(addresses, append([]byte(nil), address.AsSlice()...))
	}
	return &lanewayv1.Welcome{
		SessionId:          append([]byte(nil), config.SessionID[:]...),
		ConfigurationEpoch: config.ConfigurationEpoch,
		OverlayAddresses:   addresses,
		Capabilities:       uint64(capabilities),
		MaxControlPayload:  config.MaxControlPayload,
		MaxPacketPayload:   config.MaxPacketPayload,
	}, nil
}

func decodeOverlayAddresses(raw [][]byte) ([]netip.Addr, error) {
	addresses := make([]netip.Addr, 0, len(raw))
	for i, packed := range raw {
		var address netip.Addr
		switch len(packed) {
		case 4:
			var bytes4 [4]byte
			copy(bytes4[:], packed)
			address = netip.AddrFrom4(bytes4)
		case 16:
			var bytes16 [16]byte
			copy(bytes16[:], packed)
			address = netip.AddrFrom16(bytes16)
			if address.Is4In6() {
				return nil, malformed(ErrInvalidOverlayAddress, "overlay_addresses[%d] encodes IPv4 in non-canonical 16-byte form", i)
			}
		default:
			return nil, malformed(ErrInvalidOverlayAddress, "overlay_addresses[%d] length %d", i, len(packed))
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

// ValidateWelcome verifies all server-controlled bounds and that capabilities
// are a known subset of the exact Hello advertisement.
func ValidateWelcome(welcome *lanewayv1.Welcome, hello *lanewayv1.Hello, localMaxControlPayload uint32) (SessionParameters, error) {
	if welcome == nil || hello == nil {
		return SessionParameters{}, malformed(ErrMalformed, "Welcome or original Hello is nil")
	}
	sessionID, err := exactNonzeroID("session_id", welcome.GetSessionId())
	if err != nil {
		return SessionParameters{}, err
	}
	if err := validateControlLimit(welcome.GetMaxControlPayload()); err != nil {
		return SessionParameters{}, err
	}
	if localMaxControlPayload == 0 {
		localMaxControlPayload = protocol.DefaultMaxControlFrame
	}
	if err := validateControlLimit(localMaxControlPayload); err != nil {
		return SessionParameters{}, fmt.Errorf("local control limit: %w", err)
	}
	if err := validatePacketLimit(welcome.GetMaxPacketPayload()); err != nil {
		return SessionParameters{}, err
	}
	capabilities := protocol.Capability(welcome.GetCapabilities())
	advertised := protocol.Capability(hello.GetCapabilities()).Intersect(protocol.KnownCapabilities)
	if capabilities.Unknown() != 0 || capabilities&^advertised != 0 {
		return SessionParameters{}, malformed(ErrRequiredCapabilities, "Welcome capabilities %#x are not a known subset of Hello %#x", uint64(capabilities), uint64(advertised))
	}
	if !hasRequiredTransport(capabilities) {
		return SessionParameters{}, unsupported(ErrRequiredCapabilities, "Welcome capabilities %s lack a supported relay transport", capabilities)
	}
	addresses, err := decodeOverlayAddresses(welcome.GetOverlayAddresses())
	if err != nil {
		return SessionParameters{}, err
	}
	if !capabilities.Has(protocol.CapabilityIPv6V1) {
		for _, address := range addresses {
			if address.Is6() {
				return SessionParameters{}, malformed(ErrRequiredCapabilities, "Welcome includes IPv6 overlay address without IPv6 capability")
			}
		}
	}
	effective := localMaxControlPayload
	if welcome.GetMaxControlPayload() < effective {
		effective = welcome.GetMaxControlPayload()
	}
	return SessionParameters{
		SessionID:                  sessionID,
		ConfigurationEpoch:         welcome.GetConfigurationEpoch(),
		OverlayAddresses:           addresses,
		Capabilities:               capabilities,
		EffectiveMaxControlPayload: effective,
		MaxPacketPayload:           welcome.GetMaxPacketPayload(),
	}, nil
}

type ClientHandshake struct {
	hello    *lanewayv1.Hello
	inbound  SequenceValidator
	outbound SequenceGenerator
	started  bool
	finished bool
}

func NewClientHandshake(authenticated identity.NodeIdentity, bootID identity.ID, version protocol.Version, capabilities protocol.Capability) (*ClientHandshake, error) {
	hello, err := NewHello(authenticated, bootID, version, capabilities)
	if err != nil {
		return nil, err
	}
	return &ClientHandshake{hello: hello}, nil
}

func (h *ClientHandshake) HelloEnvelope() (*lanewayv1.ControlEnvelope, error) {
	if h == nil || h.started || h.finished {
		return nil, malformed(ErrHandshakeState, "Hello already sent or handshake unavailable")
	}
	h.started = true
	return h.outbound.Next(h.hello)
}

func (h *ClientHandshake) AcceptWelcome(env *lanewayv1.ControlEnvelope, localMaxControlPayload uint32) (SessionParameters, error) {
	if h == nil || !h.started || h.finished {
		return SessionParameters{}, malformed(ErrHandshakeState, "client is not awaiting Welcome")
	}
	h.finished = true
	if err := h.inbound.Validate(env, BodyWelcome, BodyError); err != nil {
		return SessionParameters{}, err
	}
	if protocolError := env.GetError(); protocolError != nil {
		return SessionParameters{}, RemoteError(protocolError)
	}
	return ValidateWelcome(env.GetWelcome(), h.hello, localMaxControlPayload)
}

type RelayHandshake struct {
	authenticated identity.NodeIdentity
	version       protocol.Version
	capabilities  protocol.Capability
	welcome       WelcomeConfig
	inbound       SequenceValidator
	outbound      SequenceGenerator
	finished      bool
}

func NewRelayHandshake(authenticated identity.NodeIdentity, version protocol.Version, capabilities protocol.Capability, welcome WelcomeConfig) (*RelayHandshake, error) {
	if err := authenticated.Validate(); err != nil {
		return nil, sessionError(lanewayv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED, ErrUnauthenticated, "invalid authenticated identity: %v", err)
	}
	if welcome.SessionID.IsZero() {
		return nil, malformed(ErrInvalidIdentifier, "session_id is zero")
	}
	return &RelayHandshake{authenticated: authenticated, version: version, capabilities: capabilities, welcome: welcome}, nil
}

func (h *RelayHandshake) AcceptHello(env *lanewayv1.ControlEnvelope) (*lanewayv1.ControlEnvelope, HelloResult, error) {
	if h == nil || h.finished {
		return nil, HelloResult{}, malformed(ErrHandshakeState, "relay already processed Hello or handshake unavailable")
	}
	h.finished = true
	if err := h.inbound.Validate(env, BodyHello); err != nil {
		return nil, HelloResult{}, err
	}
	result, err := ValidateHello(env.GetHello(), h.authenticated, h.version, h.capabilities)
	if err != nil {
		return nil, HelloResult{}, err
	}
	welcome, err := NewWelcome(h.welcome, result.Negotiated)
	if err != nil {
		return nil, HelloResult{}, err
	}
	welcomeEnvelope, err := h.outbound.Next(welcome)
	return welcomeEnvelope, result, err
}

// ErrorEnvelope converts a stable local session error to the next outbound
// envelope. Unknown errors are intentionally reduced to INTERNAL.
func ErrorEnvelope(sequence *SequenceGenerator, err error) (*lanewayv1.ControlEnvelope, error) {
	var sessionErr *SessionError
	if !errors.As(err, &sessionErr) {
		sessionErr = &SessionError{Code: lanewayv1.ErrorCode_ERROR_CODE_INTERNAL, Kind: ErrInternal, Detail: "internal error"}
	} else if !validErrorCode(sessionErr.Code) {
		sessionErr = &SessionError{Code: lanewayv1.ErrorCode_ERROR_CODE_INTERNAL, Kind: ErrInternal, Detail: "internal error"}
	}
	return sequence.Next(sessionErr.ProtocolError())
}

// SameSessionID performs the byte-exact comparison required by subsequent
// relay registration without accepting malformed identifiers.
func SameSessionID(expected identity.ID, claimed []byte) error {
	parsed, err := exactNonzeroID("session_id", claimed)
	if err != nil {
		return err
	}
	if !bytes.Equal(expected[:], parsed[:]) {
		return malformed(ErrInvalidIdentifier, "session_id does not match active session")
	}
	return nil
}
