// Package userspaceproxy terminates authorized IP flows in-process and dials
// their destinations with ordinary host sockets. It is the unprivileged
// Connector dataplane: no TUN device, route mutation, forwarding sysctl, or
// network capability is required.
package userspaceproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID              = tcpip.NICID(1)
	defaultQueueDepth  = 1024
	defaultMaxInFlight = 1024
	defaultIdleTimeout = 2 * time.Minute
)

type Config struct {
	MTU         int
	QueueDepth  int
	MaxInFlight int
	DialTimeout time.Duration
	IdleTimeout time.Duration
	DialContext func(context.Context, string, string) (net.Conn, error)
}

type Proxy struct {
	stack       *stack.Stack
	endpoint    *channel.Endpoint
	dialContext func(context.Context, string, string) (net.Conn, error)
	idleTimeout time.Duration
	addressesMu sync.Mutex
	addresses   map[string]struct{}
	closeOnce   sync.Once
}

func New(config Config) (*Proxy, error) {
	if config.MTU == 0 {
		config.MTU = 1280
	}
	if config.MTU < 576 || config.MTU > 65535 {
		return nil, errors.New("userspace proxy MTU must be between 576 and 65535")
	}
	if config.QueueDepth == 0 {
		config.QueueDepth = defaultQueueDepth
	}
	if config.MaxInFlight == 0 {
		config.MaxInFlight = defaultMaxInFlight
	}
	if config.QueueDepth < 1 || config.MaxInFlight < 1 {
		return nil, errors.New("userspace proxy queue and in-flight limits must be positive")
	}
	if config.DialTimeout == 0 {
		config.DialTimeout = 10 * time.Second
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = defaultIdleTimeout
	}
	if config.DialContext == nil {
		dialer := &net.Dialer{Timeout: config.DialTimeout, KeepAlive: 30 * time.Second}
		config.DialContext = dialer.DialContext
	}

	networkStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	endpoint := channel.New(config.QueueDepth, uint32(config.MTU), "")
	if err := networkStack.CreateNIC(nicID, endpoint); err != nil {
		return nil, fmt.Errorf("create userspace proxy NIC: %s", err)
	}
	if err := networkStack.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("enable userspace proxy promiscuous mode: %s", err)
	}
	if err := networkStack.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("enable userspace proxy address spoofing: %s", err)
	}
	networkStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	networkStack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})

	proxy := &Proxy{stack: networkStack, endpoint: endpoint, dialContext: config.DialContext, idleTimeout: config.IdleTimeout, addresses: make(map[string]struct{})}
	tcpForwarder := tcp.NewForwarder(networkStack, 0, config.MaxInFlight, proxy.forwardTCP)
	udpForwarder := udp.NewForwarder(networkStack, proxy.forwardUDP)
	networkStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	networkStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	return proxy, nil
}

func (p *Proxy) ReadPacket(ctx context.Context, destination []byte) (int, error) {
	packet := p.endpoint.ReadContext(ctx)
	if packet.IsNil() {
		return 0, ctx.Err()
	}
	defer packet.DecRef()
	view := packet.ToView()
	defer view.Release()
	if view.Size() > len(destination) {
		return 0, io.ErrShortBuffer
	}
	return view.Read(destination)
}

func (p *Proxy) WritePacket(_ context.Context, packet []byte) error {
	if len(packet) == 0 {
		return errors.New("userspace proxy received an empty packet")
	}
	var protocol tcpip.NetworkProtocolNumber
	var destination tcpip.Address
	var prefixLength int
	switch packet[0] >> 4 {
	case 4:
		protocol = ipv4.ProtocolNumber
		destination = header.IPv4(packet).DestinationAddress()
		prefixLength = 32
	case 6:
		protocol = ipv6.ProtocolNumber
		destination = header.IPv6(packet).DestinationAddress()
		prefixLength = 128
	default:
		return syscall.EAFNOSUPPORT
	}
	if err := p.ensureLocalAddress(protocol, destination, prefixLength); err != nil {
		return err
	}
	buffer := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	p.endpoint.InjectInbound(protocol, buffer)
	return nil
}

func (p *Proxy) ensureLocalAddress(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, prefixLength int) error {
	key := fmt.Sprintf("%d/%s", protocol, address)
	p.addressesMu.Lock()
	defer p.addressesMu.Unlock()
	if _, exists := p.addresses[key]; exists {
		return nil
	}
	if len(p.addresses) >= 65536 {
		return errors.New("userspace proxy destination limit reached")
	}
	err := p.stack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: tcpip.AddressWithPrefix{Address: address, PrefixLen: prefixLength}}, stack.AddressProperties{})
	if err != nil {
		return fmt.Errorf("register userspace proxy destination: %s", err)
	}
	p.addresses[key] = struct{}{}
	return nil
}

func (p *Proxy) Close() error {
	p.closeOnce.Do(func() {
		p.stack.RemoveNIC(nicID)
		p.endpoint.Close()
	})
	return nil
}

func (p *Proxy) forwardTCP(request *tcp.ForwarderRequest) {
	id := request.ID()
	destination := tcpAddress(id.LocalAddress, id.LocalPort)
	upstream, err := p.dialContext(context.Background(), "tcp", destination)
	if err != nil {
		request.Complete(true)
		return
	}
	var queue waiter.Queue
	endpoint, tcpipErr := request.CreateEndpoint(&queue)
	if tcpipErr != nil {
		request.Complete(true)
		_ = upstream.Close()
		return
	}
	request.Complete(false)
	downstream := gonet.NewTCPConn(&queue, endpoint)
	p.splice(downstream, upstream)
}

func (p *Proxy) forwardUDP(request *udp.ForwarderRequest) {
	id := request.ID()
	destination := tcpAddress(id.LocalAddress, id.LocalPort)
	upstream, err := p.dialContext(context.Background(), "udp", destination)
	if err != nil {
		return
	}
	var queue waiter.Queue
	endpoint, tcpipErr := request.CreateEndpoint(&queue)
	if tcpipErr != nil {
		_ = upstream.Close()
		return
	}
	downstream := gonet.NewUDPConn(p.stack, &queue, endpoint)
	go p.splice(downstream, upstream)
}

func (p *Proxy) splice(downstream, upstream net.Conn) {
	defer downstream.Close()
	defer upstream.Close()
	downstreamIdle := idleConn{Conn: downstream, timeout: p.idleTimeout}
	upstreamIdle := idleConn{Conn: upstream, timeout: p.idleTimeout}
	done := make(chan struct{}, 2)
	copyDirection := func(destination, source net.Conn) {
		_, _ = io.Copy(destination, source)
		done <- struct{}{}
	}
	go copyDirection(upstreamIdle, downstreamIdle)
	go copyDirection(downstreamIdle, upstreamIdle)
	<-done
}

type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c idleConn) Read(buffer []byte) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(buffer)
}

func (c idleConn) Write(buffer []byte) (int, error) {
	_ = c.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(buffer)
}

func tcpAddress(address tcpip.Address, port uint16) string {
	return net.JoinHostPort(net.IP(address.AsSlice()).String(), fmt.Sprintf("%d", port))
}
