package conformance

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/protocol"
	"google.golang.org/protobuf/proto"
)

func TestPacketGoldenVector(t *testing.T) {
	wire := readHexFixture(t, "packets/relay-ipv4-icmp.hex")
	header, payload, err := protocol.DecodePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	if header.Version != 1 || header.Flags != 0 || header.RouteHandle != 0x01020304 {
		t.Fatalf("unexpected header: %#v", header)
	}
	if len(payload) != 35 || payload[0]>>4 != 4 {
		t.Fatalf("unexpected IP payload: length=%d first=%#x", len(payload), payload[0])
	}
	encoded, err := protocol.EncodePacket(nil, header, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, wire) {
		t.Fatalf("re-encoded packet differs: %x", encoded)
	}
}

func TestControlFrameGoldenVector(t *testing.T) {
	frame := readHexFixture(t, "control/hello.frame.hex")
	wantEnvelope := readHexFixture(t, "control/hello.envelope.hex")
	if got := binary.BigEndian.Uint32(frame[:4]); got != uint32(len(wantEnvelope)) {
		t.Fatalf("frame length = %d, want %d", got, len(wantEnvelope))
	}
	got, err := protocol.ReadControlFrame(bytes.NewReader(frame), protocol.DefaultMaxControlFrame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantEnvelope) {
		t.Fatal("decoded frame does not match envelope fixture")
	}
}

func TestRouteControllerFrameGoldenVector(t *testing.T) {
	frame := readHexFixture(t, "routing/overlay-route-controller.frame.hex")
	if len(frame) < protocol.ControlLengthSize {
		t.Fatalf("frame length = %d, want at least %d", len(frame), protocol.ControlLengthSize)
	}
	if got, want := binary.BigEndian.Uint32(frame[:protocol.ControlLengthSize]), uint32(len(frame)-protocol.ControlLengthSize); got != want {
		t.Fatalf("frame length prefix = %d, want %d", got, want)
	}
	payload, err := protocol.ReadControlFrame(bytes.NewReader(frame), protocol.DefaultMaxControlFrame)
	if err != nil {
		t.Fatal(err)
	}
	envelope := new(lanewayv1.ControllerEnvelope)
	if err := proto.Unmarshal(payload, envelope); err != nil {
		t.Fatal(err)
	}
	configuration := envelope.GetNodeConfiguration()
	if envelope.GetSchemaVersion() != 1 || envelope.GetRequestId() != 42 || configuration == nil {
		t.Fatalf("unexpected controller envelope: %#v", envelope)
	}
	routes := configuration.GetRoutes()
	if configuration.GetConfigurationEpoch() != 7 || configuration.GetValidUntilUnixSeconds() != 4_102_444_800 || routes == nil {
		t.Fatalf("unexpected node configuration: %#v", configuration)
	}
	if got, want := routes.GetNetworkId(), []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}; !bytes.Equal(got, want) {
		t.Fatalf("route network ID = %x, want %x", got, want)
	}
	if routes.GetConfigurationEpoch() != 7 || len(routes.GetRoutes()) != 1 {
		t.Fatalf("unexpected route snapshot: %#v", routes)
	}
	route := routes.GetRoutes()[0]
	if got, want := route.GetDestination().GetAddress(), []byte{100, 96, 0, 2}; !bytes.Equal(got, want) || route.GetDestination().GetPrefixLength() != 32 || route.GetKind() != lanewayv1.RouteKind_ROUTE_KIND_OVERLAY || route.GetMetric() != 10 {
		t.Fatalf("unexpected overlay route: %#v", route)
	}
	if got, want := hex.EncodeToString(route.GetViaNodeId()), "101112131415161718191a1b1c1d1e1f"; got != want {
		t.Fatalf("route via node ID = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(route.GetRouteId()), "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"; got != want {
		t.Fatalf("route ID = %s, want %s", got, want)
	}
	reencoded, err := proto.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, payload) {
		t.Fatalf("re-encoded controller envelope differs: %x", reencoded)
	}
}

func readHexFixture(t *testing.T, path string) []byte {
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
	decoded, err := hex.DecodeString(strings.Join(strings.Fields(string(contents)), ""))
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return decoded
}
