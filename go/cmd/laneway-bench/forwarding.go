package main

import (
	"context"
	"errors"
	"flag"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"laneway.dev/laneway/internal/dataplane"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pathmanager"
	"laneway.dev/laneway/internal/routing"
)

func runForwarding(parent context.Context, args []string, exit bool) error {
	name := "subnet-forward"
	if exit {
		name = "exit-forward"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	duration := fs.Duration("duration", 3*time.Second, "measurement duration")
	size := fs.Int("size", 1200, "raw IP packet size")
	rate := fs.Uint64("pps", 0, "packet rate limit; zero sends as fast as possible")
	queue := fs.Int("queue", 4096, "bounded in-memory packet-path queue")
	flows := fs.Int("flows", 1, "logical flows (1, 10, or 100)")
	profile := fs.String("profile", "lan", "impairment profile: lan or wan")
	delay := fs.Duration("delay", -1, "one-way packet delay override")
	loss := fs.Float64("loss", 0, "deterministic random loss percentage [0,100]")
	burst := fs.Int("burst-loss", 0, "drop this many packets after each 100 offered packets")
	seed := fs.Int64("seed", 1, "loss PRNG seed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *duration <= 0 || *size < ipv4HeaderLen+benchmarkMetaLen || *size > maxQUICPacketSize || *queue <= 0 || *queue > 65536 {
		return errors.New("duration, size, or queue is outside the supported range")
	}
	resolvedDelay, err := validateMatrixDimensions(*flows, *profile, *delay, *loss, *burst)
	if err != nil {
		return err
	}
	result, err := runDataplaneForwardingBenchmark(parent, quicBenchmarkOptions{
		duration: *duration, packetSize: *size, packetsPS: *rate, queue: *queue, flows: *flows,
		profile: *profile, delay: resolvedDelay, loss: *loss, burstLoss: *burst, seed: *seed, output: os.Stdout,
	}, exit)
	if err == nil {
		printBenchmarkSummary(os.Stdout, result)
	}
	return err
}

func runDataplaneForwardingBenchmark(parent context.Context, options quicBenchmarkOptions, exit bool) (quicBenchmarkResult, error) {
	if options.flows == 0 {
		options.flows = 1
	}
	if options.profile == "" {
		options.profile = "lan"
	}
	if options.duration <= 0 || options.packetSize < ipv4HeaderLen+benchmarkMetaLen || options.packetSize > maxQUICPacketSize || options.queue <= 0 || options.queue > 65536 || !validFlowCount(options.flows) {
		return quicBenchmarkResult{}, errors.New("invalid forwarding benchmark options")
	}
	material, err := newBenchmarkIdentityMaterial()
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	sourceAddress := netip.MustParseAddr(benchmarkSourceAddress)
	destination := netip.MustParseAddr("192.168.50.10")
	prefix := netip.MustParsePrefix("192.168.50.0/24")
	scenario, scope := "subnet-forward", "tunless-subnet-routing-policy"
	if exit {
		destination = netip.MustParseAddr("203.0.113.10")
		prefix = netip.MustParsePrefix("0.0.0.0/0")
		scenario, scope = "exit-forward", "tunless-default-route-policy-no-nat"
	}
	sourceStats, sinkStats := &counters{}, &counters{}
	packets := newBenchmarkSource(options.packetSize, options.packetsPS, sourceStats)
	packets.flows = options.flows
	packets.source = sourceAddress
	packets.destination = destination
	defer packets.stop()
	path := newBenchmarkMemoryPath(options.queue, options.packetSize, material.sinkIdentity.NodeID,
		newBenchmarkImpairment(options.delay, options.loss, options.burstLoss, options.seed, nil), sinkStats)
	defer path.Close()
	manager := pathmanager.MustNew(pathmanager.Config{})
	routes := routing.NewTable(routing.MustSnapshot([]routing.Route{{Prefix: prefix, NextHop: material.sinkIdentity.NodeID, RouteHandle: 1}}))
	engine, err := dataplane.New(dataplane.Config{
		Identity: material.sourceIdentity, Routes: routes, Packets: packets, Paths: manager,
		Policy: dataplane.PacketPolicyFunc(func(source, destination identity.NodeID, _ []byte) bool {
			return source == material.sourceIdentity.NodeID && destination == material.sinkIdentity.NodeID
		}),
		LocalAddresses: []netip.Addr{sourceAddress}, ForwardPrefixes: []netip.Prefix{prefix}, MaxPacketSize: max(576, options.packetSize),
	})
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	if err := engine.Attach(material.sinkIdentity.NodeID, pathmanager.PathRelayQUIC, path); err != nil {
		return quicBenchmarkResult{}, err
	}
	measurement := beginBenchmarkMeasurement()
	ctx, cancel := context.WithTimeout(parent, options.duration)
	defer cancel()
	packets.start(ctx)
	progressDone := startBenchmarkProgress(ctx, options.output, sinkStats, scenario)
	engineDone := make(chan error, 1)
	started := time.Now()
	go func() { engineDone <- engine.Run(ctx) }()
	<-ctx.Done()
	elapsed := time.Since(started)
	resources := measurement.finish()
	engine.Close()
	<-engineDone
	<-progressDone
	packets.waitForHalt(100 * time.Millisecond)
	path.waitDrain(250 * time.Millisecond)
	generated, received := sourceStats.packets.Load(), sinkStats.packets.Load()
	dropped := uint64(0)
	if generated > received {
		dropped = generated - received
	}
	metrics := engine.Metrics()
	result := quicBenchmarkResult{
		scenario: scenario, transport: "in-memory-packet-path", scope: scope,
		profile: options.profile, flows: options.flows, packetSize: options.packetSize,
		duration: elapsed, generated: generated, sent: metrics.PacketsSent, received: received,
		bytes: sinkStats.bytes.Load(), dropped: dropped, bad: sinkStats.bad.Load() + metrics.MalformedPackets,
		p50: sinkStats.percentile(50), p95: sinkStats.percentile(95), p99: sinkStats.percentile(99),
		queueCapacity: options.queue, queueDepth: uint64(len(path.queue)), queuePeak: path.peak.Load(),
		queuePeakScope: "in-process-counter",
	}
	result.resources = resources
	return result, nil
}

type benchmarkQueuedPacket struct {
	peer   identity.NodeID
	packet []byte
}

type benchmarkMemoryPath struct {
	peer       identity.NodeID
	maxPayload int
	queue      chan benchmarkQueuedPacket
	impairment *benchmarkImpairment
	stats      *counters
	cancel     context.CancelFunc
	done       chan struct{}
	closed     sync.Once
	peak       atomic.Uint64
	active     atomic.Int64
}

func newBenchmarkMemoryPath(capacity, maxPayload int, peer identity.NodeID, impairment *benchmarkImpairment, stats *counters) *benchmarkMemoryPath {
	ctx, cancel := context.WithCancel(context.Background())
	p := &benchmarkMemoryPath{peer: peer, maxPayload: maxPayload, queue: make(chan benchmarkQueuedPacket, capacity), impairment: impairment, stats: stats, cancel: cancel, done: make(chan struct{})}
	go p.run(ctx)
	return p
}

func (*benchmarkMemoryPath) Name() string { return "benchmark-memory-path" }
func (p *benchmarkMemoryPath) MaxPayload(peer identity.NodeID) int {
	if peer != p.peer {
		return 0
	}
	return p.maxPayload
}
func (p *benchmarkMemoryPath) Send(ctx context.Context, peer identity.NodeID, packet pathmanager.PacketBuffer) error {
	if peer != p.peer {
		return errors.New("benchmark memory path: wrong peer")
	}
	copyPacket := append([]byte(nil), packet...)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.queue <- benchmarkQueuedPacket{peer: peer, packet: copyPacket}:
		depth := uint64(len(p.queue))
		if depth == 0 {
			// A receiver may dequeue between the send and the gauge read, but
			// successful enqueue proves that depth reached at least one.
			depth = 1
		}
		for current := p.peak.Load(); depth > current && !p.peak.CompareAndSwap(current, depth); current = p.peak.Load() {
		}
		return nil
	default:
		p.stats.drops.Add(1)
		return nil
	}
}
func (p *benchmarkMemoryPath) Receive(ctx context.Context) (pathmanager.ReceivedPacket, error) {
	<-ctx.Done()
	return pathmanager.ReceivedPacket{}, ctx.Err()
}
func (p *benchmarkMemoryPath) Health(peer identity.NodeID) pathmanager.PathHealth {
	if peer != p.peer {
		return pathmanager.PathHealth{State: pathmanager.HealthUnknown}
	}
	return pathmanager.PathHealth{State: pathmanager.HealthHealthy}
}
func (p *benchmarkMemoryPath) Close() error { p.closed.Do(p.cancel); return nil }
func (p *benchmarkMemoryPath) waitDrain(maximum time.Duration) {
	timer := time.NewTimer(maximum)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for len(p.queue) > 0 || p.active.Load() > 0 {
		select {
		case <-timer.C:
			return
		case <-ticker.C:
		}
	}
}
func (p *benchmarkMemoryPath) run(ctx context.Context) {
	defer close(p.done)
	for {
		select {
		case <-ctx.Done():
			return
		case item := <-p.queue:
			p.active.Add(1)
			if p.impairment.drop() {
				p.stats.drops.Add(1)
				p.active.Add(-1)
				continue
			}
			if p.impairment.wait(ctx) != nil {
				p.active.Add(-1)
				return
			}
			observeBenchmarkPacket(p.stats, item.packet, p.maxPayload)
			p.active.Add(-1)
		}
	}
}

var _ pathmanager.PacketPath = (*benchmarkMemoryPath)(nil)
