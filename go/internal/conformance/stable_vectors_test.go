package conformance

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"google.golang.org/protobuf/proto"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/directpath"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/protocol"
	"laneway.dev/laneway/internal/routing"
)

func TestStableControlVectors(t *testing.T) {
	helloPayload := readHexFixture(t, "control/hello.payload.hex")
	hello := new(lanewayv1.Hello)
	if err := proto.Unmarshal(helloPayload, hello); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(hello.GetNetworkId()) != "000102030405060708090a0b0c0d0e0f" ||
		hex.EncodeToString(hello.GetNodeId()) != "101112131415161718191a1b1c1d1e1f" ||
		hex.EncodeToString(hello.GetBootId()) != "202122232425262728292a2b2c2d2e2f" ||
		hello.GetProtocolMajor() != 1 || hello.GetProtocolMinor() != 0 || hello.GetCapabilities() != 3 {
		t.Fatalf("hello = %#v", hello)
	}
	assertEnvelopeFrame(t, "control/hello", func(envelope *lanewayv1.ControlEnvelope) bool {
		return envelope.GetSchemaVersion() == 1 && envelope.GetSequence() == 1 && proto.Equal(envelope.GetHello(), hello)
	})
	welcomePayload := readHexFixture(t, "control/welcome.payload.hex")
	welcome := new(lanewayv1.Welcome)
	if err := proto.Unmarshal(welcomePayload, welcome); err != nil {
		t.Fatal(err)
	}
	if len(welcome.GetSessionId()) != identity.IDSize || welcome.GetConfigurationEpoch() != 7 ||
		welcome.GetCapabilities() != 3 || welcome.GetMaxControlPayload() != protocol.DefaultMaxControlFrame || welcome.GetMaxPacketPayload() != 1200 {
		t.Fatalf("welcome = %#v", welcome)
	}
	assertEnvelopeFrame(t, "control/welcome", func(envelope *lanewayv1.ControlEnvelope) bool {
		return envelope.GetSchemaVersion() == 1 && envelope.GetSequence() == 1 && proto.Equal(envelope.GetWelcome(), welcome)
	})
	assertEnvelopeFrame(t, "control/permission-denied", func(envelope *lanewayv1.ControlEnvelope) bool {
		remote := envelope.GetError()
		return envelope.GetSchemaVersion() == 1 && envelope.GetSequence() == 2 &&
			remote.GetCode() == lanewayv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED && remote.GetDetail() == "denied" && !remote.GetRetryable()
	})
}

func assertEnvelopeFrame(t *testing.T, base string, valid func(*lanewayv1.ControlEnvelope) bool) {
	t.Helper()
	envelopeBytes := readHexFixture(t, base+".envelope.hex")
	envelope := new(lanewayv1.ControlEnvelope)
	if err := proto.Unmarshal(envelopeBytes, envelope); err != nil || !valid(envelope) {
		t.Fatalf("%s envelope = %#v, %v", base, envelope, err)
	}
	frame := readHexFixture(t, base+".frame.hex")
	if len(frame) < 4 || int(binary.BigEndian.Uint32(frame[:4])) != len(envelopeBytes) || !bytes.Equal(frame[4:], envelopeBytes) {
		t.Fatalf("%s frame does not contain its envelope", base)
	}
}

func TestStableIPv6PacketVector(t *testing.T) {
	wire := readHexFixture(t, "packets/relay-ipv6-empty.hex")
	header, packet, err := protocol.DecodePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	if header.RouteHandle != 0x0a0b0c0d || len(packet) != 40 || packet[0]>>4 != 6 {
		t.Fatalf("header=%#v packet=%x", header, packet)
	}
}

func TestStableOpaqueWireGuardPacketVector(t *testing.T) {
	wire := readHexFixture(t, "packets/relay-wireguard-initiation.hex")
	header, packet, err := protocol.DecodeFrame(wire)
	if err != nil {
		t.Fatal(err)
	}
	if header.Flags != protocol.PacketFlagE2EEncrypted || header.RouteHandle != 0x01020304 || len(packet) != 148 || packet[0] != 1 {
		t.Fatalf("header=%#v packet_length=%d packet_type=%d", header, len(packet), packet[0])
	}
	if _, _, err := protocol.DecodePacket(wire); !errors.Is(err, protocol.ErrInvalidPacketFlags) {
		t.Fatalf("plaintext decoder error = %v", err)
	}
}

func TestStableDirectProbeVector(t *testing.T) {
	local, _ := identity.ParseNodeID("202122232425262728292a2b2c2d2e2f")
	peer, _ := identity.ParseNodeID("101112131415161718191a1b1c1d1e1f")
	var token directpath.ProbeToken
	tokenBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	copy(token[:], tokenBytes)
	probe, err := directpath.ParseProbePacket(readHexFixture(t, "direct/probe-request.hex"), local, peer, token)
	if err != nil || probe.Response || probe.Sender != peer || probe.Recipient != local || probe.Token != token {
		t.Fatalf("probe=%#v error=%v", probe, err)
	}
}

func TestStableTCPPacketRecordVector(t *testing.T) {
	record := readHexFixture(t, "tcp/packet-record.hex")
	if len(record) < 5 || int(binary.BigEndian.Uint32(record[:4])) != len(record)-4 || record[4] != 2 {
		t.Fatalf("invalid record framing: %x", record)
	}
	header, packet, err := protocol.DecodePacket(record[5:])
	if err != nil || header.RouteHandle != 0x01020304 || len(packet) != 20 {
		t.Fatalf("packet header=%#v length=%d error=%v", header, len(packet), err)
	}
	if !bytes.Equal(packet[12:20], []byte{100, 96, 0, 1, 100, 96, 0, 2}) {
		t.Fatalf("unexpected TCP packet addresses %v", packet[12:20])
	}
}

type capabilityCases struct {
	KnownMask uint64 `json:"known_mask"`
	Cases     []struct {
		Name            string            `json:"name"`
		Local           uint64            `json:"local"`
		Remote          uint64            `json:"remote"`
		Required        uint64            `json:"required"`
		Expected        uint64            `json:"expected"`
		ExpectedError   string            `json:"expected_error"`
		LocalVersion    protocol.Version  `json:"local_version"`
		RemoteVersion   protocol.Version  `json:"remote_version"`
		ExpectedVersion *protocol.Version `json:"expected_version"`
	} `json:"cases"`
}

func TestStableCapabilityCases(t *testing.T) {
	var cases capabilityCases
	if err := json.Unmarshal(readFixture(t, "control/capability-cases.json"), &cases); err != nil {
		t.Fatal(err)
	}
	if protocol.Capability(cases.KnownMask) != protocol.KnownCapabilities {
		t.Fatalf("known mask = %#x", cases.KnownMask)
	}
	for _, testCase := range cases.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			negotiated, err := protocol.Negotiate(testCase.LocalVersion, testCase.RemoteVersion,
				protocol.Capability(testCase.Local), protocol.Capability(testCase.Remote))
			if testCase.ExpectedError == "incompatible_version" {
				if !errors.Is(err, protocol.ErrIncompatibleVersion) {
					t.Fatalf("error=%v, want incompatible_version", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			missingRequired := !negotiated.Capabilities.Has(protocol.Capability(testCase.Required))
			if testCase.ExpectedError != "" {
				if !missingRequired {
					t.Fatalf("capabilities=%#x, want %s", negotiated.Capabilities, testCase.ExpectedError)
				}
				return
			}
			if missingRequired || uint64(negotiated.Capabilities) != testCase.Expected {
				t.Fatalf("capabilities=%#x, want %#x", negotiated.Capabilities, testCase.Expected)
			}
			if testCase.ExpectedVersion == nil || negotiated.Version != *testCase.ExpectedVersion {
				t.Fatalf("version=%#v, want %#v", negotiated.Version, testCase.ExpectedVersion)
			}
		})
	}
}

type identityCases struct {
	NetworkIDHex           string `json:"network_id_hex"`
	AuthenticatedNodeIDHex string `json:"authenticated_node_id_hex"`
	Cases                  []struct {
		Name             string   `json:"name"`
		URISANs          []string `json:"uri_sans"`
		MessageNodeIDHex string   `json:"message_node_id_hex"`
		Expected         string   `json:"expected"`
	} `json:"cases"`
}

// TestStableIdentityCases executes the shared certificate-identity cases
// through the production Go certificate and claim validators. The manifest
// hash test alone is not semantic conformance.
func TestStableIdentityCases(t *testing.T) {
	var cases identityCases
	if err := json.Unmarshal(readFixture(t, "certificates/identity-cases.json"), &cases); err != nil {
		t.Fatal(err)
	}
	expectedNetwork, err := identity.ParseNetworkID(cases.NetworkIDHex)
	if err != nil {
		t.Fatal(err)
	}
	expectedNode, err := identity.ParseNodeID(cases.AuthenticatedNodeIDHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range cases.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			certificate := &x509.Certificate{}
			for _, raw := range testCase.URISANs {
				parsed, parseErr := url.Parse(raw)
				if parseErr != nil {
					t.Fatalf("fixture URI: %v", parseErr)
				}
				certificate.URIs = append(certificate.URIs, parsed)
			}
			authenticated, authErr := identity.AuthenticatedIdentityFromCertificate(certificate)
			outcome := "accept"
			switch {
			case errors.Is(authErr, identity.ErrIdentitySANMissing):
				outcome = "reject_missing_identity"
			case authErr != nil:
				outcome = "reject_malformed_identity"
			case authenticated.NetworkID != expectedNetwork:
				outcome = "reject_network_mismatch"
			default:
				messageNode, parseErr := identity.ParseNodeID(testCase.MessageNodeIDHex)
				if parseErr != nil {
					outcome = "reject_node_mismatch"
				} else if node, ok := authenticated.NodeIdentity(); !ok || node.NodeID != expectedNode || node.ValidateClaim(expectedNetwork, messageNode) != nil {
					outcome = "reject_node_mismatch"
				}
			}
			if outcome != testCase.Expected {
				t.Fatalf("outcome = %q, want %q (auth error %v)", outcome, testCase.Expected, authErr)
			}
		})
	}
}

type certificateDERCases struct {
	Cases []struct {
		Name         string `json:"name"`
		DERBase64    string `json:"der_base64"`
		Expected     string `json:"expected"`
		NetworkIDHex string `json:"network_id_hex"`
		Role         string `json:"role"`
		SubjectIDHex string `json:"subject_id_hex"`
	} `json:"cases"`
}

// TestStableCertificateDERCases runs the exact shared certificate bytes
// through Go's production DER and Laneway URI-SAN parsers. These vectors catch
// parser differences that synthetic x509.Certificate values cannot expose.
func TestStableCertificateDERCases(t *testing.T) {
	var cases certificateDERCases
	if err := json.Unmarshal(readFixture(t, "certificates/der-cases.json"), &cases); err != nil {
		t.Fatal(err)
	}
	for _, testCase := range cases.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			der, err := base64.StdEncoding.DecodeString(testCase.DERBase64)
			if err != nil {
				t.Fatalf("fixture base64: %v", err)
			}
			certificate, parseErr := x509.ParseCertificate(der)
			outcome := "accept"
			var authenticated identity.AuthenticatedIdentity
			var authErr error
			switch {
			case parseErr != nil:
				outcome = "reject_invalid_certificate"
			default:
				authenticated, authErr = identity.AuthenticatedIdentityFromCertificate(certificate)
				switch {
				case errors.Is(authErr, identity.ErrIdentitySANMissing), errors.Is(authErr, identity.ErrMultipleIdentitySANs):
					outcome = "reject_identity_san_count"
				case authErr != nil:
					outcome = "reject_malformed_identity"
				}
			}
			if outcome != testCase.Expected {
				t.Fatalf("outcome=%q, want %q (parse=%v auth=%v)", outcome, testCase.Expected, parseErr, authErr)
			}
			if outcome != "accept" {
				return
			}
			if authenticated.NetworkID.String() != testCase.NetworkIDHex ||
				string(authenticated.Role) != testCase.Role || authenticated.SubjectID.String() != testCase.SubjectIDHex {
				t.Fatalf("identity=%#v, want network=%s role=%s subject=%s", authenticated,
					testCase.NetworkIDHex, testCase.Role, testCase.SubjectIDHex)
			}
		})
	}
}

type packetRejectCases struct {
	Cases []struct {
		Name          string `json:"name"`
		WireHex       string `json:"wire_hex"`
		ExpectedError string `json:"expected_error"`
	} `json:"cases"`
}

func TestStablePacketRejectCases(t *testing.T) {
	var cases packetRejectCases
	if err := json.Unmarshal(readFixture(t, "packets/reject-cases.json"), &cases); err != nil {
		t.Fatal(err)
	}
	want := map[string]error{
		"packet_too_short":     protocol.ErrShortPacket,
		"unsupported_version":  protocol.ErrUnsupportedVersion,
		"invalid_route_handle": protocol.ErrInvalidRouteHandle,
		"invalid_packet_flags": protocol.ErrInvalidPacketFlags,
		"packet_too_large":     protocol.ErrPacketTooLarge,
		"invalid_ip_packet":    protocol.ErrInvalidIPPacket,
	}
	for _, testCase := range cases.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			wire, err := hex.DecodeString(testCase.WireHex)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = protocol.DecodePacket(wire)
			expected, ok := want[testCase.ExpectedError]
			if !ok {
				t.Fatalf("unknown expected error label %q", testCase.ExpectedError)
			}
			if !errors.Is(err, expected) {
				t.Fatalf("error = %v, want %v", err, expected)
			}
		})
	}
}

type packetHeaderCases struct {
	Cases []struct {
		Name          string               `json:"name"`
		Version       uint8                `json:"version"`
		Flags         protocol.PacketFlags `json:"flags"`
		RouteHandle   uint32               `json:"route_handle"`
		ExpectedHex   string               `json:"expected_hex"`
		ExpectedError string               `json:"expected_error"`
	} `json:"cases"`
}

func TestStablePacketHeaderCases(t *testing.T) {
	var cases packetHeaderCases
	if err := json.Unmarshal(readFixture(t, "packets/header-cases.json"), &cases); err != nil {
		t.Fatal(err)
	}
	want := map[string]error{
		"unsupported_version":  protocol.ErrUnsupportedVersion,
		"invalid_packet_flags": protocol.ErrInvalidPacketFlags,
		"invalid_route_handle": protocol.ErrInvalidRouteHandle,
	}
	for _, testCase := range cases.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			wire := make([]byte, protocol.PacketHeaderSize)
			header := protocol.PacketHeader{Version: testCase.Version, Flags: testCase.Flags, RouteHandle: testCase.RouteHandle}
			err := protocol.EncodePacketHeader(wire, header)
			if testCase.ExpectedError != "" {
				if !errors.Is(err, want[testCase.ExpectedError]) {
					t.Fatalf("error=%v, want=%s", err, testCase.ExpectedError)
				}
				return
			}
			if err != nil || hex.EncodeToString(wire) != testCase.ExpectedHex {
				t.Fatalf("wire=%x error=%v, want=%s", wire, err, testCase.ExpectedHex)
			}
			decoded, err := protocol.DecodePacketHeader(wire)
			if err != nil || decoded != header {
				t.Fatalf("decoded=%#v error=%v, want=%#v", decoded, err, header)
			}
		})
	}
}

type packetBoundaryCases struct {
	RouteHandle uint32 `json:"route_handle"`
	Cases       []struct {
		Name          string `json:"name"`
		Family        string `json:"family"`
		PayloadLength int    `json:"payload_length"`
		Expected      string `json:"expected"`
		ExpectedError string `json:"expected_error"`
	} `json:"cases"`
}

func generatedIP(family string, length int) []byte {
	packet := make([]byte, length)
	switch family {
	case "ipv4":
		if length >= 4 {
			packet[0] = 0x45
			binary.BigEndian.PutUint16(packet[2:4], uint16(length))
		}
	case "ipv6":
		if length >= 6 {
			packet[0] = 0x60
			binary.BigEndian.PutUint16(packet[4:6], uint16(length-40))
		}
	default:
		panic("unknown packet family")
	}
	return packet
}

func TestStablePacketBoundaryCases(t *testing.T) {
	var cases packetBoundaryCases
	if err := json.Unmarshal(readFixture(t, "packets/boundary-cases.json"), &cases); err != nil {
		t.Fatal(err)
	}
	want := map[string]error{"packet_too_large": protocol.ErrPacketTooLarge, "invalid_ip_packet": protocol.ErrInvalidIPPacket}
	for _, testCase := range cases.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			packet := generatedIP(testCase.Family, testCase.PayloadLength)
			wire, err := protocol.EncodePacket(nil, protocol.PacketHeader{Version: 1, RouteHandle: cases.RouteHandle}, packet)
			if testCase.ExpectedError != "" {
				if !errors.Is(err, want[testCase.ExpectedError]) || len(wire) != 0 {
					t.Fatalf("wire length=%d error=%v, want=%s", len(wire), err, testCase.ExpectedError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			header, decoded, err := protocol.DecodePacket(wire)
			if err != nil || header.RouteHandle != cases.RouteHandle || len(decoded) != testCase.PayloadLength {
				t.Fatalf("header=%#v length=%d error=%v", header, len(decoded), err)
			}
		})
	}
}

type routingCases struct {
	Routes []struct {
		ID     string `json:"id"`
		Prefix string `json:"prefix"`
		Metric uint32 `json:"metric"`
	} `json:"routes"`
	Cases []struct {
		Destination     string `json:"destination"`
		ExpectedRouteID string `json:"expected_route_id"`
	} `json:"cases"`
}

func TestStableRoutingSelectionCases(t *testing.T) {
	var cases routingCases
	if err := json.Unmarshal(readFixture(t, "routing/selection-cases.json"), &cases); err != nil {
		t.Fatal(err)
	}
	routes := make([]routing.Route, 0, len(cases.Routes))
	ids := make(map[identity.NodeID]string, len(cases.Routes))
	for index, fixture := range cases.Routes {
		var nextHop identity.NodeID
		nextHop[len(nextHop)-1] = byte(index + 1)
		prefix, err := netip.ParsePrefix(fixture.Prefix)
		if err != nil {
			t.Fatal(err)
		}
		routes = append(routes, routing.Route{Prefix: prefix, NextHop: nextHop, Metric: fixture.Metric})
		ids[nextHop] = fixture.ID
	}
	snapshot, err := routing.NewSnapshot(routes)
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range cases.Cases {
		t.Run(testCase.Destination, func(t *testing.T) {
			route, ok := snapshot.Lookup(netip.MustParseAddr(testCase.Destination))
			if !ok || ids[route.NextHop] != testCase.ExpectedRouteID {
				t.Fatalf("route = %q, found=%v, want %q", ids[route.NextHop], ok, testCase.ExpectedRouteID)
			}
		})
	}
}

type routingSemanticCases struct {
	Routes  []routingSemanticRoute `json:"routes"`
	Lookups []struct {
		Name            string `json:"name"`
		Destination     string `json:"destination"`
		ExpectedRouteID string `json:"expected_route_id"`
		Expected        string `json:"expected"`
	} `json:"lookups"`
	SourceAuthorization []struct {
		Name     string `json:"name"`
		Source   string `json:"source"`
		Peer     string `json:"peer"`
		Expected bool   `json:"expected"`
	} `json:"source_authorization"`
	InvalidSets []struct {
		Name          string                 `json:"name"`
		ExpectedError string                 `json:"expected_error"`
		Routes        []routingSemanticRoute `json:"routes"`
	} `json:"invalid_sets"`
}

type routingSemanticRoute struct {
	ID      string `json:"id"`
	Prefix  string `json:"prefix"`
	Metric  uint32 `json:"metric"`
	NextHop string `json:"next_hop"`
	Handle  uint32 `json:"handle"`
}

func semanticRoutes(fixtures []routingSemanticRoute) ([]routing.Route, map[identity.NodeID]string, error) {
	routes := make([]routing.Route, 0, len(fixtures))
	ids := make(map[identity.NodeID]string, len(fixtures))
	for _, fixture := range fixtures {
		prefix, err := netip.ParsePrefix(fixture.Prefix)
		if err != nil {
			return nil, nil, err
		}
		nextHop, err := identity.ParseNodeID(fixture.NextHop)
		if err != nil {
			return nil, nil, err
		}
		routes = append(routes, routing.Route{Prefix: prefix, NextHop: nextHop, Metric: fixture.Metric, RouteHandle: fixture.Handle})
		ids[nextHop] = fixture.ID
	}
	return routes, ids, nil
}

func TestStableRoutingSemanticCases(t *testing.T) {
	var cases routingSemanticCases
	if err := json.Unmarshal(readFixture(t, "routing/semantic-cases.json"), &cases); err != nil {
		t.Fatal(err)
	}
	routes, ids, err := semanticRoutes(cases.Routes)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := routing.NewSnapshot(routes)
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range cases.Lookups {
		t.Run(testCase.Name, func(t *testing.T) {
			route, ok := snapshot.Lookup(netip.MustParseAddr(testCase.Destination))
			if testCase.Expected == "no_match" {
				if ok {
					t.Fatalf("unexpected route %#v", route)
				}
				return
			}
			if !ok || ids[route.NextHop] != testCase.ExpectedRouteID {
				t.Fatalf("route=%q found=%v, want=%q", ids[route.NextHop], ok, testCase.ExpectedRouteID)
			}
		})
	}
	for _, testCase := range cases.SourceAuthorization {
		t.Run(testCase.Name, func(t *testing.T) {
			peer, err := identity.ParseNodeID(testCase.Peer)
			if err != nil {
				t.Fatal(err)
			}
			route, ok := snapshot.Lookup(netip.MustParseAddr(testCase.Source))
			authorized := ok && route.NextHop == peer
			if authorized != testCase.Expected {
				t.Fatalf("authorized=%v, want=%v route=%#v", authorized, testCase.Expected, route)
			}
		})
	}
	for _, testCase := range cases.InvalidSets {
		t.Run(testCase.Name, func(t *testing.T) {
			routes, _, err := semanticRoutes(testCase.Routes)
			if err != nil {
				t.Fatal(err)
			}
			_, err = routing.NewSnapshot(routes)
			want := map[string]error{"invalid_prefix": routing.ErrInvalidPrefix, "ambiguous_route": routing.ErrAmbiguousRoute}[testCase.ExpectedError]
			if !errors.Is(err, want) {
				t.Fatalf("error=%v, want=%s", err, testCase.ExpectedError)
			}
		})
	}
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "..", "testvectors"))
	contents, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
