package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Doout/laneway/go/internal/agent"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/nodeservice"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/Doout/laneway/go/internal/relay"
	"github.com/Doout/laneway/go/internal/relayservice"
	"github.com/Doout/laneway/go/internal/routing"
	"github.com/Doout/laneway/go/internal/tcpfallback"
	"github.com/Doout/laneway/go/internal/transport"
)

const (
	benchmarkSourceAddress = "100.96.0.1"
	benchmarkSinkAddress   = "100.96.0.2"
	maxQUICPacketSize      = 1200
)

type quicBenchmarkOptions struct {
	duration    time.Duration
	packetSize  int
	packetsPS   uint64
	queue       int
	flows       int
	profile     string
	delay       time.Duration
	loss        float64
	burstLoss   int
	seed        int64
	output      io.Writer
	relayBinary string
}

type quicBenchmarkResult struct {
	scenario        string
	transport       string
	scope           string
	profile         string
	flows           int
	packetSize      int
	duration        time.Duration
	generated       uint64
	sent            uint64
	received        uint64
	bytes           uint64
	dropped         uint64
	bad             uint64
	p50             time.Duration
	p95             time.Duration
	p99             time.Duration
	resources       benchmarkResources
	relayCPU        float64
	relayRSS        uint64
	relayAllocs     uint64
	relayAllocBytes uint64
	queueCapacity   int
	queueDepth      uint64
	queuePeak       uint64
	queuePeakScope  string
}

func runQUICRelay(parent context.Context, args []string) error {
	return runRelayCarrier(parent, args, false)
}

func runTCPRelay(parent context.Context, args []string) error {
	return runRelayCarrier(parent, args, true)
}

func runRelayCarrier(parent context.Context, args []string, tcp bool) error {
	name := "quic-relay"
	if tcp {
		name = "relay-tcp"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	duration := fs.Duration("duration", 3*time.Second, "measurement duration (zero runs until interrupted)")
	size := fs.Int("size", 1200, "raw IP packet size; Laneway adds its packet header")
	rate := fs.Uint64("pps", 0, "packet rate limit; zero sends as fast as possible")
	queue := fs.Int("queue", 4096, "relay outbound packet queue capacity")
	flows := fs.Int("flows", 1, "logical flows (1, 10, or 100)")
	profile := fs.String("profile", "lan", "impairment profile: lan or wan")
	delay := fs.Duration("delay", -1, "one-way packet delay override")
	loss := fs.Float64("loss", 0, "deterministic random loss percentage [0,100]")
	burst := fs.Int("burst-loss", 0, "drop this many packets after each 100 offered packets")
	seed := fs.Int64("seed", 1, "loss PRNG seed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *duration < 0 {
		return errors.New("duration must not be negative")
	}
	if *size < ipv4HeaderLen+benchmarkMetaLen || *size > maxQUICPacketSize {
		return fmt.Errorf("size must be between %d and %d", ipv4HeaderLen+benchmarkMetaLen, maxQUICPacketSize)
	}
	if *queue <= 0 || *queue > 65536 || (tcp && *queue > 4096) {
		return errors.New("queue must be in [1,65536] (TCP fallback maximum: 4096)")
	}
	resolvedDelay, err := validateMatrixDimensions(*flows, *profile, *delay, *loss, *burst)
	if err != nil {
		return err
	}

	result, err := runAuthenticatedRelayBenchmark(parent, quicBenchmarkOptions{
		duration: *duration, packetSize: *size, packetsPS: *rate, queue: *queue,
		flows: *flows, profile: *profile, delay: resolvedDelay, loss: *loss, burstLoss: *burst, seed: *seed, output: os.Stdout,
	}, tcp)
	if err != nil {
		return err
	}
	printBenchmarkSummary(os.Stdout, result)
	return nil
}

func runAuthenticatedQUICBenchmark(parent context.Context, options quicBenchmarkOptions) (quicBenchmarkResult, error) {
	return runAuthenticatedRelayBenchmark(parent, options, false)
}

func runAuthenticatedRelayBenchmark(parent context.Context, options quicBenchmarkOptions, tcp bool) (quicBenchmarkResult, error) {
	if options.flows == 0 {
		options.flows = 1
	}
	if options.profile == "" {
		options.profile = "lan"
	}
	if options.duration < 0 || options.packetSize < ipv4HeaderLen+benchmarkMetaLen ||
		options.packetSize > maxQUICPacketSize || options.queue <= 0 || !validFlowCount(options.flows) {
		return quicBenchmarkResult{}, errors.New("invalid authenticated QUIC benchmark options")
	}
	material, err := newBenchmarkIdentityMaterial()
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	sourceAddress := netip.MustParseAddr(benchmarkSourceAddress)
	sinkAddress := netip.MustParseAddr(benchmarkSinkAddress)

	var listener *transport.Listener
	var tcpListener *tcpfallback.Listener
	tcpConfig := &tcpfallback.Config{QueueDepth: options.queue, MaxPacketPayload: options.packetSize + 5}
	if tcp {
		tcpListener, err = tcpfallback.Listen("127.0.0.1:0", material.relayTLS, tcpConfig)
		if err != nil {
			return quicBenchmarkResult{}, fmt.Errorf("listen for benchmark TCP relay: %w", err)
		}
		defer tcpListener.Close()
	} else {
		listener, err = transport.Listen("127.0.0.1:0", material.relayTLS, nil)
		if err != nil {
			return quicBenchmarkResult{}, fmt.Errorf("listen for benchmark relay: %w", err)
		}
		defer listener.Close()
	}

	capabilities := agent.RequiredRelayCapabilities
	if tcp {
		capabilities = agent.RequiredTCPFallbackCapabilities
	}
	relayServer, err := relayservice.New(relayservice.Config{
		Authorizer: relayservice.StaticAuthorizer{
			material.sourceIdentity: {
				OverlayAddresses:   []netip.Addr{sourceAddress},
				AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(sourceAddress, 32)},
			},
			material.sinkIdentity: {
				OverlayAddresses:   []netip.Addr{sinkAddress},
				AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(sinkAddress, 32)},
			},
		},
		Registry: relay.Config{
			MaxSessions: 4, MaxHandlesPerSession: 4,
			OutboundQueueCapacity: options.queue, MaxPacketPayload: options.packetSize,
			DuplicatePolicy: relay.RejectDuplicate, QueuePolicy: relay.DropNewest,
		},
		MaxPacketPayload:   uint32(options.packetSize),
		ConfigurationEpoch: 1,
		Capabilities:       capabilities,
		TCPFallback: func() *tcpfallback.Config {
			if tcp {
				return tcpConfig
			}
			return nil
		}(),
	})
	if err != nil {
		return quicBenchmarkResult{}, fmt.Errorf("create benchmark relay: %w", err)
	}

	sourceStats := &counters{}
	receiverStats := &counters{}
	sourcePackets := newBenchmarkSource(options.packetSize, options.packetsPS, sourceStats)
	sourcePackets.flows = options.flows
	sourcePackets.impairment = newBenchmarkImpairment(options.delay, options.loss, options.burstLoss, options.seed, sourceStats)
	defer sourcePackets.stop()
	sinkPackets := &benchmarkSink{stats: receiverStats, packetSize: options.packetSize}
	sourceRoutes := routing.NewTable(routing.MustSnapshot([]routing.Route{{
		Prefix: netip.PrefixFrom(sinkAddress, 32), NextHop: material.sinkIdentity.NodeID, RouteHandle: 1,
	}}))
	sinkRoutes := routing.NewTable(routing.MustSnapshot([]routing.Route{{
		Prefix: netip.PrefixFrom(sourceAddress, 32), NextHop: material.sourceIdentity.NodeID, RouteHandle: 1,
	}}))

	relayAddress := "127.0.0.1:1"
	tcpAddress := ""
	if tcp {
		tcpAddress = tcpListener.Addr().String()
	} else {
		relayAddress = listener.Addr().String()
	}
	sourceService, err := newBenchmarkNode(material.sourceIdentity, relayAddress, tcpAddress, material.sourceTLS, tcpConfig, sourceRoutes, sourcePackets)
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	sinkService, err := newBenchmarkNode(material.sinkIdentity, relayAddress, tcpAddress, material.sinkTLS, tcpConfig, sinkRoutes, sinkPackets)
	if err != nil {
		return quicBenchmarkResult{}, err
	}

	sessionCtx, cancelSessions := context.WithCancel(parent)
	defer cancelSessions()
	componentErrors := make(chan error, 3)
	go runBenchmarkComponent(sessionCtx, "relay", componentErrors, func() error {
		if tcp {
			return relayServer.ServeTCP(sessionCtx, tcpListener)
		}
		return relayServer.Serve(sessionCtx, listener)
	})
	go runBenchmarkComponent(sessionCtx, "source node", componentErrors, func() error {
		return sourceService.RunSession(sessionCtx)
	})
	go runBenchmarkComponent(sessionCtx, "sink node", componentErrors, func() error {
		return sinkService.RunSession(sessionCtx)
	})

	readyCtx, cancelReady := context.WithTimeout(parent, 10*time.Second)
	err = waitForBenchmarkRoutes(readyCtx, sourceService, material.sinkIdentity.NodeID, sinkService, material.sourceIdentity.NodeID, componentErrors)
	cancelReady()
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	measurement := beginBenchmarkMeasurement()

	measurementCtx := parent
	cancelMeasurement := func() {}
	if options.duration > 0 {
		measurementCtx, cancelMeasurement = context.WithTimeout(parent, options.duration)
	}
	started := time.Now()
	sourcePackets.start(measurementCtx)
	progressScenario := "relay-quic"
	if tcp {
		progressScenario = "relay-tcp"
	}
	progressDone := startBenchmarkProgress(measurementCtx, options.output, receiverStats, progressScenario)
	var queuePeak atomic.Uint64
	queueDone := sampleRelayQueue(measurementCtx, relayServer, &queuePeak)

	select {
	case <-measurementCtx.Done():
	case componentErr := <-componentErrors:
		cancelMeasurement()
		return quicBenchmarkResult{}, componentErr
	}
	cancelMeasurement()
	elapsed := time.Since(started)
	<-progressDone
	<-queueDone
	sourcePackets.waitForHalt(100 * time.Millisecond)

	// QUIC datagrams already accepted by the sender can still be queued at the
	// relay. Give that bounded queue a short opportunity to drain before loss
	// is calculated and the authenticated sessions are closed.
	sent := sourceService.Metrics().PacketsSent
	waitForBenchmarkDrain(parent, receiverStats, sent, 250*time.Millisecond)
	received := receiverStats.packets.Load()
	generated := sourceStats.packets.Load()
	var dropped uint64
	if generated > received {
		dropped = generated - received
	}
	receiverStats.drops.Store(dropped)

	result := quicBenchmarkResult{
		scenario: func() string {
			if tcp {
				return "relay-tcp"
			}
			return "relay-quic"
		}(),
		transport: func() string {
			if tcp {
				return "tls1.3-tcp"
			}
			return "quic-datagram"
		}(),
		scope: "authenticated-relay", profile: options.profile, flows: options.flows, packetSize: options.packetSize,
		duration: elapsed, generated: generated, sent: sent,
		received: received, bytes: receiverStats.bytes.Load(), dropped: dropped,
		bad: receiverStats.bad.Load(), p50: receiverStats.percentile(50),
		p95: receiverStats.percentile(95), p99: receiverStats.percentile(99),
		queueCapacity: options.queue, queueDepth: relayServer.Registry().Metrics().QueuedPackets,
		queuePeak: queuePeak.Load(), queuePeakScope: "sampled-1ms",
	}
	result.resources = measurement.finish()
	cancelSessions()
	if result.generated == 0 && parent.Err() == nil {
		return quicBenchmarkResult{}, errors.New("authenticated relay benchmark generated no packets")
	}
	return result, nil
}

func newBenchmarkNode(id identity.NodeIdentity, relayAddress, tcpAddress string, tlsConfig *tls.Config, tcpConfig *tcpfallback.Config, routes *routing.Table, packets nodeservice.PacketIO) (*nodeservice.Service, error) {
	bootID, err := identity.NewID()
	if err != nil {
		return nil, fmt.Errorf("generate benchmark boot ID: %w", err)
	}
	service, err := nodeservice.New(nodeservice.Config{
		Identity: id, BootID: bootID, RelayAddress: relayAddress, TLSConfig: tlsConfig,
		TCPFallbackAddress: tcpAddress, TCPFallback: func() *tcpfallback.Config {
			if tcpAddress != "" {
				return tcpConfig
			}
			return nil
		}(),
		Transport: func() *transport.Config {
			if tcpAddress != "" {
				return &transport.Config{HandshakeIdleTimeout: 50 * time.Millisecond, MaxIdleTimeout: time.Second, KeepAlivePeriod: 100 * time.Millisecond}
			}
			return nil
		}(),
		Routes: routes, Packets: packets, MaxRoutes: 4,
	})
	if err != nil {
		return nil, fmt.Errorf("create benchmark node: %w", err)
	}
	return service, nil
}

func runBenchmarkComponent(ctx context.Context, name string, errorsOut chan<- error, run func() error) {
	err := run()
	if ctx.Err() != nil {
		return
	}
	if err == nil {
		err = errors.New("stopped unexpectedly")
	}
	errorsOut <- fmt.Errorf("%s: %w", name, err)
}

func waitForBenchmarkRoutes(ctx context.Context, source *nodeservice.Service, sinkID identity.NodeID, sink *nodeservice.Service, sourceID identity.NodeID, errorsIn <-chan error) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if source.PathAvailable(sinkID) && sink.PathAvailable(sourceID) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for authenticated relay route bindings: %w", ctx.Err())
		case err := <-errorsIn:
			return err
		case <-ticker.C:
		}
	}
}

func waitForBenchmarkDrain(ctx context.Context, stats *counters, sent uint64, maximum time.Duration) {
	timer := time.NewTimer(maximum)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for stats.packets.Load() < sent {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			return
		case <-ticker.C:
		}
	}
}

type benchmarkSource struct {
	packetSize  int
	packetsPS   uint64
	stats       *counters
	started     chan struct{}
	halted      chan struct{}
	startOnce   sync.Once
	haltOnce    sync.Once
	active      context.Context
	ticker      *time.Ticker
	flows       int
	impairment  *benchmarkImpairment
	source      netip.Addr
	destination netip.Addr
}

func newBenchmarkSource(packetSize int, packetsPS uint64, stats *counters) *benchmarkSource {
	return &benchmarkSource{
		packetSize: packetSize, packetsPS: packetsPS, stats: stats,
		started: make(chan struct{}), halted: make(chan struct{}),
	}
}

func (s *benchmarkSource) start(ctx context.Context) {
	s.startOnce.Do(func() {
		s.active = ctx
		if s.packetsPS > 0 {
			interval := time.Second / time.Duration(s.packetsPS)
			if interval <= 0 {
				interval = time.Nanosecond
			}
			s.ticker = time.NewTicker(interval)
		}
		close(s.started)
	})
}

func (s *benchmarkSource) stop() {
	if s.ticker != nil {
		s.ticker.Stop()
	}
}

func (s *benchmarkSource) halt(sessionCtx context.Context) (int, error) {
	s.haltOnce.Do(func() { close(s.halted) })
	<-sessionCtx.Done()
	return 0, sessionCtx.Err()
}

func (s *benchmarkSource) waitForHalt(maximum time.Duration) {
	timer := time.NewTimer(maximum)
	defer timer.Stop()
	select {
	case <-s.halted:
	case <-timer.C:
	}
}

func (s *benchmarkSource) ReadPacket(sessionCtx context.Context, buffer []byte) (int, error) {
	for {
		n, err := s.readPacket(sessionCtx, buffer)
		if err != nil || n != 0 {
			return n, err
		}
	}
}

func (s *benchmarkSource) readPacket(sessionCtx context.Context, buffer []byte) (int, error) {
	select {
	case <-sessionCtx.Done():
		s.haltOnce.Do(func() { close(s.halted) })
		return 0, sessionCtx.Err()
	case <-s.started:
	}
	if s.active.Err() != nil {
		return s.halt(sessionCtx)
	}
	if s.ticker != nil {
		select {
		case <-sessionCtx.Done():
			s.haltOnce.Do(func() { close(s.halted) })
			return 0, sessionCtx.Err()
		case <-s.active.Done():
			return s.halt(sessionCtx)
		case <-s.ticker.C:
		}
	} else {
		select {
		case <-s.active.Done():
			return s.halt(sessionCtx)
		default:
		}
	}
	if s.active.Err() != nil {
		return s.halt(sessionCtx)
	}
	if len(buffer) < s.packetSize {
		return 0, io.ErrShortBuffer
	}
	packet := buffer[:s.packetSize]
	clear(packet)
	initializeIPv4(packet)
	sequence := s.stats.packets.Load()
	if s.source.Is4() {
		value := s.source.As4()
		copy(packet[12:16], value[:])
	}
	if s.destination.Is4() {
		value := s.destination.As4()
		if s.flows > 1 {
			value[3] += byte(sequence % uint64(s.flows))
		}
		copy(packet[16:20], value[:])
	}
	metadata := packet[ipv4HeaderLen:]
	flows := s.flows
	if flows <= 0 {
		flows = 1
	}
	// The IPv4 ID makes logical flows visible to packet captures without
	// changing the controller-authorized overlay addresses.
	binary.BigEndian.PutUint16(packet[4:6], uint16(sequence%uint64(flows)))
	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:ipv4HeaderLen]))
	binary.BigEndian.PutUint64(metadata, sequence)
	s.stats.packets.Add(1)
	s.stats.bytes.Add(uint64(len(packet)))
	if s.impairment != nil {
		if s.impairment.drop() {
			return 0, nil
		}
		if err := s.impairment.wait(s.active); err != nil {
			return s.halt(sessionCtx)
		}
	}
	binary.BigEndian.PutUint64(metadata[8:], uint64(time.Now().Add(-func() time.Duration {
		if s.impairment != nil {
			return s.impairment.delay
		}
		return 0
	}()).UnixNano()))
	return len(packet), nil
}

func (*benchmarkSource) WritePacket(context.Context, []byte) error { return nil }

type benchmarkSink struct {
	stats      *counters
	packetSize int
}

func (*benchmarkSink) ReadPacket(ctx context.Context, _ []byte) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func (s *benchmarkSink) WritePacket(_ context.Context, packet []byte) error {
	if len(packet) != s.packetSize {
		s.stats.bad.Add(1)
		return nil
	}
	metadata, err := benchmarkMetadata(packet)
	if err != nil {
		s.stats.bad.Add(1)
		return nil
	}
	sentAt := int64(binary.BigEndian.Uint64(metadata[8:]))
	if latency := time.Since(time.Unix(0, sentAt)); latency >= 0 {
		s.stats.observeLatency(latency)
	} else {
		s.stats.bad.Add(1)
	}
	s.stats.packets.Add(1)
	s.stats.bytes.Add(uint64(len(packet)))
	return nil
}

type benchmarkIdentityMaterial struct {
	sourceIdentity identity.NodeIdentity
	sinkIdentity   identity.NodeIdentity
	networkID      identity.NetworkID
	relayID        identity.ID
	caCertificate  *x509.Certificate
	relayMaterial  pki.Material
	relayTLS       *tls.Config
	sourceTLS      *tls.Config
	sinkTLS        *tls.Config
	roots          *x509.CertPool
}

func newBenchmarkIdentityMaterial() (benchmarkIdentityMaterial, error) {
	now := time.Now()
	caMaterial, caCertificate, err := pki.NewAuthority("laneway benchmark CA", now, time.Hour)
	if err != nil {
		return benchmarkIdentityMaterial{}, fmt.Errorf("create benchmark CA: %w", err)
	}
	networkID, err := identity.NewNetworkID()
	if err != nil {
		return benchmarkIdentityMaterial{}, err
	}
	sourceID, err := identity.NewNodeID()
	if err != nil {
		return benchmarkIdentityMaterial{}, err
	}
	sinkID, err := identity.NewNodeID()
	if err != nil {
		return benchmarkIdentityMaterial{}, err
	}
	relayID, err := identity.NewID()
	if err != nil {
		return benchmarkIdentityMaterial{}, err
	}
	sourceIdentity := identity.NodeIdentity{NetworkID: networkID, NodeID: sourceID}
	sinkIdentity := identity.NodeIdentity{NetworkID: networkID, NodeID: sinkID}
	relayMaterial, relayCertificate, err := pki.IssueService(caCertificate, caMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: networkID, ServiceID: relayID, Role: pki.RoleRelay,
	}, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, now, 30*time.Minute)
	if err != nil {
		return benchmarkIdentityMaterial{}, fmt.Errorf("issue benchmark relay certificate: %w", err)
	}
	sourceMaterial, sourceCertificate, err := pki.IssueNode(caCertificate, caMaterial.PrivateKey, sourceIdentity, now, 30*time.Minute)
	if err != nil {
		return benchmarkIdentityMaterial{}, fmt.Errorf("issue benchmark source certificate: %w", err)
	}
	sinkMaterial, sinkCertificate, err := pki.IssueNode(caCertificate, caMaterial.PrivateKey, sinkIdentity, now, 30*time.Minute)
	if err != nil {
		return benchmarkIdentityMaterial{}, fmt.Errorf("issue benchmark sink certificate: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	return benchmarkIdentityMaterial{
		sourceIdentity: sourceIdentity,
		sinkIdentity:   sinkIdentity,
		networkID:      networkID,
		relayID:        relayID,
		caCertificate:  caCertificate,
		relayMaterial:  relayMaterial,
		relayTLS: &tls.Config{
			Certificates: []tls.Certificate{tlsCertificate(relayMaterial, relayCertificate)},
			ClientCAs:    roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13,
		},
		sourceTLS: benchmarkClientTLS(roots, tlsCertificate(sourceMaterial, sourceCertificate)),
		sinkTLS:   benchmarkClientTLS(roots, tlsCertificate(sinkMaterial, sinkCertificate)),
		roots:     roots,
	}, nil
}

func tlsCertificate(material pki.Material, certificate *x509.Certificate) tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{material.CertificateDER}, PrivateKey: material.PrivateKey, Leaf: certificate}
}

func benchmarkClientTLS(roots *x509.CertPool, certificate tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{certificate}, RootCAs: roots,
		ServerName: "localhost", MinVersion: tls.VersionTLS13,
	}
}

func startBenchmarkProgress(ctx context.Context, output io.Writer, stats *counters, scenario string) <-chan struct{} {
	done := make(chan struct{})
	if output == nil {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var previousPackets, previousBytes uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				packets, bytes := stats.packets.Load(), stats.bytes.Load()
				fmt.Fprintf(output, "%s received_pps=%s throughput_Gbps=%.4f throughput_MiBps=%.2f total=%s bad=%s\n", scenario,
					formatUint(packets-previousPackets),
					float64(bytes-previousBytes)*8/1_000_000_000,
					float64(bytes-previousBytes)/(1024*1024),
					formatUint(packets), formatUint(stats.bad.Load()))
				previousPackets, previousBytes = packets, bytes
			}
		}
	}()
	return done
}

func sampleRelayQueue(ctx context.Context, server *relayservice.Server, peak *atomic.Uint64) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			queued := server.Registry().Metrics().QueuedPackets
			for current := peak.Load(); queued > current && !peak.CompareAndSwap(current, queued); current = peak.Load() {
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}
