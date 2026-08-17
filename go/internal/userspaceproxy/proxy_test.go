package userspaceproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/protocol"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestAuthorizedPacketsDialFromUserspaceWithoutHostPrivileges(t *testing.T) {
	tests := []struct {
		name, network string
		protocol      tcpip.TransportProtocolNumber
		packet        func(tcpip.Address, tcpip.Address, uint16) []byte
	}{
		{"TCP", "tcp", header.TCPProtocolNumber, tcpSYN},
		{"UDP", "udp", header.UDPProtocolNumber, udpDatagram},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dialed := make(chan string, 1)
			proxy, err := New(Config{MTU: 1280, DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
				dialed <- network + " " + address
				return nil, errors.New("fixture stops before opening a host socket")
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			source := tcpip.AddrFrom4([4]byte{100, 96, 0, 10})
			destination := tcpip.AddrFrom4([4]byte{192, 0, 2, 20})
			packet := test.packet(source, destination, 8443)
			if err := protocol.ValidateIPPayload(packet); err != nil {
				t.Fatalf("fixture packet is invalid: %v", err)
			}
			ip := header.IPv4(packet)
			if !ip.IsChecksumValid() {
				t.Fatal("fixture IPv4 checksum is invalid")
			}
			transport := packet[header.IPv4MinimumSize:]
			if test.protocol == header.TCPProtocolNumber && !header.TCP(transport).IsChecksumValid(source, destination, 0, 0) {
				t.Fatal("fixture TCP checksum is invalid")
			}
			if test.protocol == header.UDPProtocolNumber && !header.UDP(transport).IsChecksumValid(source, destination, 0) {
				t.Fatal("fixture UDP checksum is invalid")
			}
			if err := proxy.WritePacket(context.Background(), packet); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-dialed:
				want := fmt.Sprintf("%s 192.0.2.20:8443", test.network)
				if got != want {
					t.Fatalf("dial = %q, want %q", got, want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("userspace forwarder did not dial the packet destination")
			}
		})
	}
}

func tcpSYN(source, destination tcpip.Address, port uint16) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	tcpHeader := header.TCP(packet[header.IPv4MinimumSize:])
	tcpHeader.Encode(&header.TCPFields{SrcPort: 49152, DstPort: port, SeqNum: 1, DataOffset: header.TCPMinimumSize, Flags: header.TCPFlagSyn, WindowSize: 65535})
	pseudo := header.PseudoHeaderChecksum(header.TCPProtocolNumber, source, destination, header.TCPMinimumSize)
	tcpHeader.SetChecksum(^tcpHeader.CalculateChecksum(pseudo))
	encodeIPv4(packet, source, destination, header.TCPProtocolNumber)
	return packet
}

func udpDatagram(source, destination tcpip.Address, port uint16) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize)
	udpHeader := header.UDP(packet[header.IPv4MinimumSize:])
	udpHeader.Encode(&header.UDPFields{SrcPort: 49152, DstPort: port, Length: header.UDPMinimumSize})
	pseudo := header.PseudoHeaderChecksum(header.UDPProtocolNumber, source, destination, header.UDPMinimumSize)
	udpHeader.SetChecksum(^udpHeader.CalculateChecksum(pseudo))
	encodeIPv4(packet, source, destination, header.UDPProtocolNumber)
	return packet
}

func encodeIPv4(packet []byte, source, destination tcpip.Address, protocol tcpip.TransportProtocolNumber) {
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 64, Protocol: uint8(protocol), SrcAddr: source, DstAddr: destination})
	ip.SetChecksum(^ip.CalculateChecksum())
}
