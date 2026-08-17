package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/Doout/laneway/go/internal/directpath"
	"github.com/Doout/laneway/go/internal/pathmanager"
)

func runDirectQUIC(parent context.Context, args []string) error {
	fs := flag.NewFlagSet("direct-quic", flag.ContinueOnError)
	duration := fs.Duration("duration", 3*time.Second, "measurement duration")
	size := fs.Int("size", 1200, "raw IP packet size")
	rate := fs.Uint64("pps", 0, "packet rate limit; zero sends as fast as possible")
	flows := fs.Int("flows", 1, "logical flows (1, 10, or 100)")
	profile := fs.String("profile", "lan", "impairment profile: lan or wan")
	delay := fs.Duration("delay", -1, "one-way packet delay override")
	loss := fs.Float64("loss", 0, "deterministic random loss percentage [0,100]")
	burst := fs.Int("burst-loss", 0, "drop this many packets after each 100 offered packets")
	seed := fs.Int64("seed", 1, "loss PRNG seed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *duration <= 0 || *size < ipv4HeaderLen+benchmarkMetaLen || *size > maxQUICPacketSize {
		return fmt.Errorf("duration must be positive and size must be between %d and %d", ipv4HeaderLen+benchmarkMetaLen, maxQUICPacketSize)
	}
	resolvedDelay, err := validateMatrixDimensions(*flows, *profile, *delay, *loss, *burst)
	if err != nil {
		return err
	}
	result, err := runAuthenticatedDirectBenchmark(parent, quicBenchmarkOptions{
		duration: *duration, packetSize: *size, packetsPS: *rate, flows: *flows,
		profile: *profile, delay: resolvedDelay, loss: *loss, burstLoss: *burst, seed: *seed, output: os.Stdout,
	})
	if err == nil {
		printBenchmarkSummary(os.Stdout, result)
	}
	return err
}

func runAuthenticatedDirectBenchmark(parent context.Context, options quicBenchmarkOptions) (quicBenchmarkResult, error) {
	if options.flows == 0 {
		options.flows = 1
	}
	if options.profile == "" {
		options.profile = "lan"
	}
	if options.duration <= 0 || options.packetSize < ipv4HeaderLen+benchmarkMetaLen || options.packetSize > maxQUICPacketSize || !validFlowCount(options.flows) {
		return quicBenchmarkResult{}, errors.New("invalid authenticated direct QUIC benchmark options")
	}
	material, err := newBenchmarkIdentityMaterial()
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	sourceSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	sinkSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		_ = sourceSocket.Close()
		return quicBenchmarkResult{}, err
	}
	maximum := options.packetSize
	if maximum < 576 {
		maximum = 576
	}
	config := directpath.Config{MaxPacketPayload: maximum, CandidatePolicy: directpath.CandidatePolicy{AllowLoopback: true}}
	sourceEndpoint, err := directpath.NewEndpoint(sourceSocket, material.sourceIdentity, directpath.Credentials{
		Roots: material.roots, Certificate: material.sourceTLS.Certificates[0],
	}, config)
	if err != nil {
		_ = sourceSocket.Close()
		_ = sinkSocket.Close()
		return quicBenchmarkResult{}, err
	}
	defer sourceEndpoint.Close()
	sinkEndpoint, err := directpath.NewEndpoint(sinkSocket, material.sinkIdentity, directpath.Credentials{
		Roots: material.roots, Certificate: material.sinkTLS.Certificates[0],
	}, config)
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	defer sinkEndpoint.Close()

	dialAddress, ok := udpAddrPort(sinkEndpoint.Addr())
	if !ok {
		return quicBenchmarkResult{}, errors.New("direct benchmark endpoint did not expose a UDP address")
	}
	setupCtx, cancelSetup := context.WithTimeout(parent, 5*time.Second)
	defer cancelSetup()
	accepted := make(chan directAccept, 1)
	go func() {
		path, acceptErr := sinkEndpoint.Accept(setupCtx)
		accepted <- directAccept{path: path, err: acceptErr}
	}()
	sourcePath, err := sourceEndpoint.Dial(setupCtx, directpath.Candidate{
		NodeID: material.sinkIdentity.NodeID, Address: dialAddress,
	}, material.sinkIdentity)
	if err != nil {
		return quicBenchmarkResult{}, fmt.Errorf("dial direct benchmark path: %w", err)
	}
	defer sourcePath.Close()
	acceptedPath := <-accepted
	if acceptedPath.err != nil {
		return quicBenchmarkResult{}, fmt.Errorf("accept direct benchmark path: %w", acceptedPath.err)
	}
	sinkPath := acceptedPath.path
	defer sinkPath.Close()

	measurement := beginBenchmarkMeasurement()
	sessionCtx, cancelSession := context.WithCancel(parent)
	defer cancelSession()
	ctx, cancelMeasurement := context.WithTimeout(parent, options.duration)
	defer cancelMeasurement()
	sourceStats, sinkStats := &counters{}, &counters{}
	impairment := newBenchmarkImpairment(options.delay, options.loss, options.burstLoss, options.seed, sourceStats)
	receiverDone := make(chan struct{})
	go func() {
		defer close(receiverDone)
		for {
			received, receiveErr := sinkPath.Receive(sessionCtx)
			if receiveErr != nil {
				return
			}
			observeBenchmarkPacket(sinkStats, received.Packet, options.packetSize)
		}
	}()
	progressDone := startBenchmarkProgress(ctx, options.output, sinkStats, "direct-quic")
	started := time.Now()
	packet := make([]byte, options.packetSize)
	var sent uint64
	var ticker *time.Ticker
	if options.packetsPS > 0 {
		interval := time.Second / time.Duration(options.packetsPS)
		if interval < time.Nanosecond {
			interval = time.Nanosecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}
	for ctx.Err() == nil {
		if ticker != nil {
			select {
			case <-ctx.Done():
				break
			case <-ticker.C:
			}
			if ctx.Err() != nil {
				break
			}
		}
		sequence := sourceStats.packets.Load()
		initializeFlowPacket(packet, sequence, options.flows)
		sourceStats.packets.Add(1)
		sourceStats.bytes.Add(uint64(len(packet)))
		if impairment.drop() {
			continue
		}
		if err := impairment.wait(ctx); err != nil {
			break
		}
		binary.BigEndian.PutUint64(packet[ipv4HeaderLen+8:], uint64(time.Now().Add(-options.delay).UnixNano()))
		if err := sourcePath.Send(ctx, material.sinkIdentity.NodeID, pathmanager.PacketBuffer(packet)); err != nil {
			if ctx.Err() == nil {
				return quicBenchmarkResult{}, err
			}
			break
		}
		sent++
	}
	elapsed := time.Since(started)
	waitForBenchmarkDrain(parent, sinkStats, sent, 250*time.Millisecond)
	cancelSession()
	<-receiverDone
	<-progressDone
	generated, received := sourceStats.packets.Load(), sinkStats.packets.Load()
	dropped := uint64(0)
	if generated > received {
		dropped = generated - received
	}
	result := quicBenchmarkResult{
		scenario: "direct-quic", transport: "quic-datagram", scope: "authenticated-direct",
		profile: options.profile, flows: options.flows, packetSize: options.packetSize,
		duration: elapsed, generated: generated, sent: sent, received: received,
		bytes: sinkStats.bytes.Load(), dropped: dropped, bad: sinkStats.bad.Load(),
		p50: sinkStats.percentile(50), p95: sinkStats.percentile(95), p99: sinkStats.percentile(99),
	}
	result.resources = measurement.finish()
	return result, nil
}

type directAccept struct {
	path *directpath.Path
	err  error
}

func udpAddrPort(address net.Addr) (netip.AddrPort, bool) {
	udp, ok := address.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	return udp.AddrPort(), true
}

func initializeFlowPacket(packet []byte, sequence uint64, flows int) {
	clear(packet)
	initializeIPv4(packet)
	binary.BigEndian.PutUint16(packet[4:6], uint16(sequence%uint64(flows)))
	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:ipv4HeaderLen]))
	binary.BigEndian.PutUint64(packet[ipv4HeaderLen:], sequence)
}

func observeBenchmarkPacket(stats *counters, packet []byte, expectedSize int) {
	if len(packet) != expectedSize {
		stats.bad.Add(1)
		return
	}
	metadata, err := benchmarkMetadata(packet)
	if err != nil {
		stats.bad.Add(1)
		return
	}
	sentAt := int64(binary.BigEndian.Uint64(metadata[8:]))
	if latency := time.Since(time.Unix(0, sentAt)); latency >= 0 {
		stats.observeLatency(latency)
	} else {
		stats.bad.Add(1)
	}
	stats.packets.Add(1)
	stats.bytes.Add(uint64(len(packet)))
}
