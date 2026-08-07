package agent

import (
	"errors"
	"net/netip"
	"testing"

	"google.golang.org/protobuf/proto"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/protocol"
)

func testID(value byte) identity.ID {
	var id identity.ID
	for i := range id {
		id[i] = value
	}
	return id
}

func testIdentity() identity.NodeIdentity {
	return identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
}

func requiredCaps() protocol.Capability {
	return RequiredRelayCapabilities | protocol.CapabilityIPv6V1
}

func validHello(t *testing.T) *lanewayv1.Hello {
	t.Helper()
	hello, err := NewHello(testIdentity(), testID(3), protocol.Version{Major: 1, Minor: 4}, requiredCaps())
	if err != nil {
		t.Fatal(err)
	}
	return hello
}

func validWelcome(t *testing.T) *lanewayv1.Welcome {
	t.Helper()
	welcome, err := NewWelcome(WelcomeConfig{
		SessionID:          testID(4),
		ConfigurationEpoch: 9,
		OverlayAddresses:   []netip.Addr{netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("fd00::2")},
		MaxControlPayload:  64 << 10,
		MaxPacketPayload:   1400,
	}, protocol.Negotiated{Version: protocol.Version{Major: 1, Minor: 2}, Capabilities: requiredCaps()})
	if err != nil {
		t.Fatal(err)
	}
	return welcome
}

func TestNewAndValidateHello(t *testing.T) {
	hello, err := NewHello(testIdentity(), testID(3), protocol.Version{Major: 1, Minor: 5}, requiredCaps()|protocol.Capability(1<<63))
	if err != nil {
		t.Fatal(err)
	}
	if len(hello.NetworkId) != 16 || len(hello.NodeId) != 16 || len(hello.BootId) != 16 {
		t.Fatalf("invalid ID sizes: %+v", hello)
	}
	if hello.Capabilities&(1<<63) != 0 {
		t.Fatal("NewHello sent unknown capability")
	}
	result, err := ValidateHello(hello, testIdentity(), protocol.Version{Major: 1, Minor: 2}, RequiredRelayCapabilities)
	if err != nil {
		t.Fatal(err)
	}
	if result.BootID != testID(3) || result.Negotiated.Version.Minor != 2 || result.Negotiated.Capabilities != RequiredRelayCapabilities {
		t.Fatalf("unexpected result: %+v", result)
	}

	hello.NetworkId[0] = 99
	if _, err := ValidateHello(hello, testIdentity(), protocol.Version{Major: 1}, requiredCaps()); !errors.Is(err, ErrIdentityMismatch) || ErrorCode(err) != lanewayv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED {
		t.Fatalf("identity mismatch error = %v", err)
	}
}

func TestTCPFallbackNegotiatesWithoutQUICCapability(t *testing.T) {
	hello, err := NewHello(testIdentity(), testID(3), protocol.Version{Major: 1}, RequiredTCPFallbackCapabilities)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ValidateHello(hello, testIdentity(), protocol.Version{Major: 1},
		RequiredRelayCapabilities|protocol.CapabilityTCPFallbackV1)
	if err != nil {
		t.Fatal(err)
	}
	if result.Negotiated.Capabilities != RequiredTCPFallbackCapabilities ||
		result.Negotiated.Capabilities.Has(protocol.CapabilityQUICDatagramV1) {
		t.Fatalf("fallback negotiated capabilities = %s", result.Negotiated.Capabilities)
	}
	welcome, err := NewWelcome(WelcomeConfig{
		SessionID: testID(4), OverlayAddresses: []netip.Addr{netip.MustParseAddr("100.96.0.2")},
		MaxControlPayload: 4096, MaxPacketPayload: 1200,
	}, result.Negotiated)
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := ValidateWelcome(welcome, hello, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if parameters.Capabilities != RequiredTCPFallbackCapabilities {
		t.Fatalf("Welcome capabilities = %s", parameters.Capabilities)
	}
}

func TestWelcomeFiltersAndRejectsUnnegotiatedIPv6Addresses(t *testing.T) {
	negotiated := protocol.Negotiated{Version: protocol.Version{Major: 1}, Capabilities: RequiredRelayCapabilities}
	welcome, err := NewWelcome(WelcomeConfig{
		SessionID: testID(4), OverlayAddresses: []netip.Addr{netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("fd00::2")},
		MaxControlPayload: 4096, MaxPacketPayload: 1280,
	}, negotiated)
	if err != nil {
		t.Fatal(err)
	}
	if len(welcome.GetOverlayAddresses()) != 1 || len(welcome.GetOverlayAddresses()[0]) != 4 {
		t.Fatalf("filtered overlay addresses = %x", welcome.GetOverlayAddresses())
	}
	hello, err := NewHello(testIdentity(), testID(3), protocol.Version{Major: 1}, RequiredRelayCapabilities)
	if err != nil {
		t.Fatal(err)
	}
	welcome.OverlayAddresses = append(welcome.OverlayAddresses, netip.MustParseAddr("fd00::2").AsSlice())
	if _, err := ValidateWelcome(welcome, hello, 4096); !errors.Is(err, ErrRequiredCapabilities) {
		t.Fatalf("ValidateWelcome error = %v, want ErrRequiredCapabilities", err)
	}
}

func TestNewHelloRejectsInvalidLocalState(t *testing.T) {
	tests := []struct {
		name string
		id   identity.NodeIdentity
		boot identity.ID
		ver  protocol.Version
		caps protocol.Capability
		want error
	}{
		{"zero identity", identity.NodeIdentity{}, testID(3), protocol.Version{Major: 1}, requiredCaps(), ErrUnauthenticated},
		{"zero boot", testIdentity(), identity.ID{}, protocol.Version{Major: 1}, requiredCaps(), ErrInvalidIdentifier},
		{"bad major", testIdentity(), testID(3), protocol.Version{Major: 2}, requiredCaps(), ErrUnsupportedVersion},
		{"missing datagram", testIdentity(), testID(3), protocol.Version{Major: 1}, protocol.CapabilityRelayV1, ErrRequiredCapabilities},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewHello(tt.id, tt.boot, tt.ver, tt.caps)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestValidateHelloRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*lanewayv1.Hello)
		want   error
		code   lanewayv1.ErrorCode
	}{
		{"nil network", func(h *lanewayv1.Hello) { h.NetworkId = nil }, ErrInvalidIdentifier, lanewayv1.ErrorCode_ERROR_CODE_MALFORMED},
		{"long node", func(h *lanewayv1.Hello) { h.NodeId = make([]byte, 17) }, ErrInvalidIdentifier, lanewayv1.ErrorCode_ERROR_CODE_MALFORMED},
		{"zero boot", func(h *lanewayv1.Hello) { h.BootId = make([]byte, 16) }, ErrInvalidIdentifier, lanewayv1.ErrorCode_ERROR_CODE_MALFORMED},
		{"bad major", func(h *lanewayv1.Hello) { h.ProtocolMajor = 2 }, ErrUnsupportedVersion, lanewayv1.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION},
		{"missing relay", func(h *lanewayv1.Hello) { h.Capabilities = uint64(protocol.CapabilityQUICDatagramV1) }, ErrRequiredCapabilities, lanewayv1.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hello := proto.Clone(validHello(t)).(*lanewayv1.Hello)
			tt.mutate(hello)
			_, err := ValidateHello(hello, testIdentity(), protocol.Version{Major: 1, Minor: 1}, requiredCaps())
			if !errors.Is(err, tt.want) || ErrorCode(err) != tt.code {
				t.Fatalf("error = %v (%v), want %v (%v)", err, ErrorCode(err), tt.want, tt.code)
			}
		})
	}
}

func TestNewAndValidateWelcome(t *testing.T) {
	hello := validHello(t)
	welcome := validWelcome(t)
	parameters, err := ValidateWelcome(welcome, hello, 32<<10)
	if err != nil {
		t.Fatal(err)
	}
	if parameters.SessionID != testID(4) || parameters.ConfigurationEpoch != 9 || parameters.EffectiveMaxControlPayload != 32<<10 || parameters.MaxPacketPayload != 1400 {
		t.Fatalf("unexpected parameters: %+v", parameters)
	}
	if len(parameters.OverlayAddresses) != 2 || parameters.OverlayAddresses[0].String() != "100.96.0.2" || parameters.OverlayAddresses[1].String() != "fd00::2" {
		t.Fatalf("unexpected addresses: %v", parameters.OverlayAddresses)
	}

	parameters, err = ValidateWelcome(welcome, hello, 0)
	if err != nil || parameters.EffectiveMaxControlPayload != welcome.MaxControlPayload {
		t.Fatalf("default local control limit: parameters=%+v err=%v", parameters, err)
	}
}

func TestWelcomeValidationFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*lanewayv1.Welcome)
		want   error
	}{
		{"short session", func(w *lanewayv1.Welcome) { w.SessionId = []byte{1} }, ErrInvalidIdentifier},
		{"zero session", func(w *lanewayv1.Welcome) { w.SessionId = make([]byte, 16) }, ErrInvalidIdentifier},
		{"zero control", func(w *lanewayv1.Welcome) { w.MaxControlPayload = 0 }, ErrInvalidControlLimit},
		{"huge control", func(w *lanewayv1.Welcome) { w.MaxControlPayload = protocol.DefaultMaxControlFrame + 1 }, ErrInvalidControlLimit},
		{"zero packet", func(w *lanewayv1.Welcome) { w.MaxPacketPayload = 0 }, ErrInvalidPacketLimit},
		{"huge packet", func(w *lanewayv1.Welcome) { w.MaxPacketPayload = uint32(protocol.MaxPacketPayload + 1) }, ErrInvalidPacketLimit},
		{"unknown capability", func(w *lanewayv1.Welcome) { w.Capabilities |= 1 << 63 }, ErrRequiredCapabilities},
		{"not advertised", func(w *lanewayv1.Welcome) { w.Capabilities |= uint64(protocol.CapabilityDirectPeerV1) }, ErrRequiredCapabilities},
		{"missing required", func(w *lanewayv1.Welcome) { w.Capabilities = uint64(protocol.CapabilityRelayV1) }, ErrRequiredCapabilities},
		{"bad address length", func(w *lanewayv1.Welcome) { w.OverlayAddresses = [][]byte{{1, 2, 3}} }, ErrInvalidOverlayAddress},
		{"mapped v4", func(w *lanewayv1.Welcome) {
			w.OverlayAddresses = [][]byte{netip.MustParseAddr("::ffff:192.0.2.1").AsSlice()}
		}, ErrInvalidOverlayAddress},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			welcome := proto.Clone(validWelcome(t)).(*lanewayv1.Welcome)
			tt.mutate(welcome)
			_, err := ValidateWelcome(welcome, validHello(t), 1024)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestHandshakeEndToEndAndOneShot(t *testing.T) {
	client, err := NewClientHandshake(testIdentity(), testID(3), protocol.Version{Major: 1, Minor: 3}, requiredCaps())
	if err != nil {
		t.Fatal(err)
	}
	helloEnvelope, err := client.HelloEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.HelloEnvelope(); !errors.Is(err, ErrHandshakeState) {
		t.Fatalf("duplicate Hello error = %v", err)
	}
	relay, err := NewRelayHandshake(testIdentity(), protocol.Version{Major: 1, Minor: 1}, requiredCaps(), WelcomeConfig{
		SessionID: testID(4), MaxControlPayload: 65536, MaxPacketPayload: 1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	welcomeEnvelope, result, err := relay.AcceptHello(helloEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if result.Negotiated.Version.Minor != 1 || welcomeEnvelope.Sequence != 1 {
		t.Fatalf("result=%+v envelope=%+v", result, welcomeEnvelope)
	}
	parameters, err := client.AcceptWelcome(welcomeEnvelope, 32768)
	if err != nil {
		t.Fatal(err)
	}
	if parameters.SessionID != testID(4) || parameters.EffectiveMaxControlPayload != 32768 {
		t.Fatalf("parameters=%+v", parameters)
	}
	if _, _, err := relay.AcceptHello(helloEnvelope); !errors.Is(err, ErrHandshakeState) {
		t.Fatalf("duplicate relay Hello error = %v", err)
	}
}

func TestClientAcceptsStableProtocolError(t *testing.T) {
	client, err := NewClientHandshake(testIdentity(), testID(3), protocol.Version{Major: 1}, requiredCaps())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.HelloEnvelope(); err != nil {
		t.Fatal(err)
	}
	var outbound SequenceGenerator
	env, err := outbound.Next(&lanewayv1.ProtocolError{Code: lanewayv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, Detail: "not allowed"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AcceptWelcome(env, 0)
	if !errors.Is(err, ErrPermissionDenied) || ErrorCode(err) != lanewayv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED {
		t.Fatalf("remote error = %v", err)
	}
}

func TestErrorEnvelopeAndSameSessionID(t *testing.T) {
	input := sessionError(lanewayv1.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED, ErrResourceExhausted, "too many routes")
	var sequence SequenceGenerator
	env, err := ErrorEnvelope(&sequence, input)
	if err != nil {
		t.Fatal(err)
	}
	if env.GetError().GetCode() != lanewayv1.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED {
		t.Fatalf("error envelope = %v", env)
	}
	matching := testID(4)
	mismatching := testID(5)
	if err := SameSessionID(testID(4), matching[:]); err != nil {
		t.Fatal(err)
	}
	if err := SameSessionID(testID(4), mismatching[:]); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("mismatch error = %v", err)
	}
}

func FuzzValidateHello(f *testing.F) {
	seed, _ := proto.Marshal(validHelloForFuzz())
	f.Add(seed)
	f.Fuzz(func(t *testing.T, raw []byte) {
		hello := new(lanewayv1.Hello)
		if proto.Unmarshal(raw, hello) != nil {
			return
		}
		result, err := ValidateHello(hello, testIdentity(), protocol.Version{Major: 1, Minor: 2}, requiredCaps())
		if err == nil && (!result.Negotiated.Capabilities.Has(RequiredRelayCapabilities) || result.BootID.IsZero()) {
			t.Fatalf("successful invalid negotiation: %+v", result)
		}
	})
}

func validHelloForFuzz() *lanewayv1.Hello {
	hello, _ := NewHello(testIdentity(), testID(3), protocol.Version{Major: 1, Minor: 2}, requiredCaps())
	return hello
}

func FuzzValidateWelcome(f *testing.F) {
	welcome, _ := NewWelcome(WelcomeConfig{SessionID: testID(4), MaxControlPayload: 1024, MaxPacketPayload: 1400}, protocol.Negotiated{Version: protocol.Version{Major: 1}, Capabilities: requiredCaps()})
	seed, _ := proto.Marshal(welcome)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, raw []byte) {
		welcome := new(lanewayv1.Welcome)
		if proto.Unmarshal(raw, welcome) != nil {
			return
		}
		parameters, err := ValidateWelcome(welcome, validHelloForFuzz(), 2048)
		if err == nil {
			if parameters.SessionID.IsZero() || parameters.EffectiveMaxControlPayload == 0 || parameters.EffectiveMaxControlPayload > 2048 || !parameters.Capabilities.Has(RequiredRelayCapabilities) {
				t.Fatalf("successful invalid Welcome: %+v", parameters)
			}
		}
	})
}
