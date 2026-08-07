package protocol

import "testing"

func BenchmarkPacketEncodeDecode1200(b *testing.B) {
	payload := make([]byte, 1195)
	payload[0], payload[2], payload[3] = 0x45, byte(len(payload)>>8), byte(len(payload))
	frame, err := EncodePacket(nil, PacketHeader{Version: PacketVersion1, RouteHandle: 1}, payload)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for range b.N {
		header, decoded, err := DecodePacket(frame)
		if err != nil || header.RouteHandle != 1 || len(decoded) != len(payload) {
			b.Fatal("packet round trip failed")
		}
	}
}

func BenchmarkPacketHeaderEncode(b *testing.B) {
	buffer := make([]byte, PacketHeaderSize)
	header := PacketHeader{Version: PacketVersion1, RouteHandle: 42}
	b.ReportAllocs()
	for range b.N {
		if err := EncodePacketHeader(buffer, header); err != nil {
			b.Fatal(err)
		}
	}
}
