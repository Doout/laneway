package protocol

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestPacketGolden(t *testing.T) {
	header := PacketHeader{Version: PacketVersion1, RouteHandle: 0x01020304}
	ip := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 100, 96, 0, 1, 100, 96, 0, 2}
	got, err := EncodePacket([]byte{0xaa}, header, ip)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0xaa, 0x10, 1, 2, 3, 4}, ip...)
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded %x, want %x", got, want)
	}
	decoded, payload, err := DecodePacket(got[1:])
	if err != nil {
		t.Fatal(err)
	}
	if decoded != header || !bytes.Equal(payload, ip) {
		t.Fatalf("decoded %#v %x", decoded, payload)
	}
	payload[0] = 0x60
	if got[6] != 0x60 {
		t.Fatal("DecodePacket payload should alias the input")
	}
}

func TestPacketErrors(t *testing.T) {
	if err := EncodePacketHeader(make([]byte, 4), PacketHeader{Version: 1, RouteHandle: 1}); !errors.Is(err, ErrShortPacket) {
		t.Fatalf("short encode: %v", err)
	}
	for _, test := range []struct {
		name string
		data []byte
		err  error
	}{
		{"short", []byte{0x10}, ErrShortPacket},
		{"version zero", append([]byte{0, 0, 0, 0, 1}, make([]byte, 20)...), ErrUnsupportedVersion},
		{"version two", append([]byte{0x20, 0, 0, 0, 1}, make([]byte, 20)...), ErrUnsupportedVersion},
		{"header only", []byte{0x10, 0, 0, 0, 1}, ErrShortPacket},
		{"zero handle", append([]byte{0x10, 0, 0, 0, 0}, make([]byte, 20)...), ErrInvalidRouteHandle},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := DecodePacket(test.data)
			if !errors.Is(err, test.err) {
				t.Fatalf("got %v, want %v", err, test.err)
			}
		})
	}
	if _, err := EncodePacket(nil, PacketHeader{Version: 1, Flags: PacketFlagE2EEncrypted, RouteHandle: 1}, make([]byte, 20)); !errors.Is(err, ErrInvalidPacketFlags) {
		t.Fatalf("flags: %v", err)
	}
	if _, _, err := DecodeFrame(append([]byte{0x12, 0, 0, 0, 1}, make([]byte, 20)...)); !errors.Is(err, ErrInvalidPacketFlags) {
		t.Fatalf("reserved flags: %v", err)
	}
	if _, err := EncodePacket(nil, PacketHeader{Version: 1, RouteHandle: 1}, make([]byte, MaxPacketPayload+1)); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("oversize: %v", err)
	}
}

func TestWireGuardPacketRoundTripAndStrictShapes(t *testing.T) {
	payload := make([]byte, 148)
	payload[0] = 1
	frame, err := EncodeWireGuardPacket(nil, 0x01020304, payload)
	if err != nil {
		t.Fatal(err)
	}
	header, got, err := DecodeFrame(frame)
	if err != nil || header.Flags != PacketFlagE2EEncrypted || header.RouteHandle != 0x01020304 || !bytes.Equal(got, payload) {
		t.Fatalf("decoded header=%+v payload=%x error=%v", header, got, err)
	}
	if _, _, err := DecodePacket(frame); !errors.Is(err, ErrInvalidPacketFlags) {
		t.Fatalf("plaintext decoder accepted encrypted payload: %v", err)
	}
	for _, invalid := range [][]byte{
		{}, {1, 0, 0, 0}, append([]byte{1, 0, 0, 0}, make([]byte, 143)...),
		append([]byte{4, 0, 0, 0}, make([]byte, 29)...), {5, 0, 0, 0}, {1, 1, 0, 0},
	} {
		if err := ValidateWireGuardPayload(invalid); !errors.Is(err, ErrInvalidWireGuard) {
			t.Fatalf("invalid WireGuard shape length=%d accepted: %v", len(invalid), err)
		}
	}
	for messageType, size := range map[byte]int{1: 148, 2: 92, 3: 64, 4: 32} {
		valid := make([]byte, size)
		valid[0] = messageType
		if err := ValidateWireGuardPayload(valid); err != nil {
			t.Fatalf("type %d size %d rejected: %v", messageType, size, err)
		}
	}
}

func FuzzPacketRoundTrip(f *testing.F) {
	f.Add(uint8(1), uint8(0), uint32(42), []byte("packet"))
	f.Add(uint8(2), uint8(0), uint32(0), []byte{})
	f.Fuzz(func(t *testing.T, version, flags uint8, handle uint32, payload []byte) {
		if len(payload) > MaxPacketPayload {
			return
		}
		ip := make([]byte, 20+len(payload))
		ip[0] = 0x45
		ip[2], ip[3] = byte(len(ip)>>8), byte(len(ip))
		copy(ip[20:], payload)
		h := PacketHeader{Version: version, Flags: PacketFlags(flags), RouteHandle: handle}
		encoded, err := EncodePacket(nil, h, ip)
		if version != PacketVersion1 || flags != 0 || handle == 0 {
			if err == nil {
				t.Fatal("invalid header encoded")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		gotHeader, gotPayload, err := DecodePacket(encoded)
		if err != nil || gotHeader != h || !reflect.DeepEqual(gotPayload, ip) {
			t.Fatalf("round trip: %#v %x %v", gotHeader, gotPayload, err)
		}
	})
}

func FuzzDecodePacket(f *testing.F) {
	f.Add([]byte{0x10, 0, 0, 0, 1})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DecodePacket(data)
	})
}
