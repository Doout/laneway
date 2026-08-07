package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

const benchmarkStreamALPN = "laneway-bench-stream/1"

func runNativeUDP(parent context.Context, args []string) error {
	options, err := parseBaselineOptions("native-udp", args)
	if err != nil {
		return err
	}
	result, err := runNativeUDPBenchmark(parent, options)
	if err == nil {
		printBenchmarkSummary(os.Stdout, result)
	}
	return err
}

func runQUICStream(parent context.Context, args []string) error {
	options, err := parseBaselineOptions("quic-stream", args)
	if err != nil {
		return err
	}
	result, err := runAuthenticatedQUICStreamBenchmark(parent, options)
	if err == nil {
		printBenchmarkSummary(os.Stdout, result)
	}
	return err
}

func parseBaselineOptions(name string, args []string) (quicBenchmarkOptions, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
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
		return quicBenchmarkOptions{}, err
	}
	if *duration <= 0 || *size < ipv4HeaderLen+benchmarkMetaLen || *size > maxQUICPacketSize {
		return quicBenchmarkOptions{}, errors.New("duration or size is outside the supported range")
	}
	resolvedDelay, err := validateMatrixDimensions(*flows, *profile, *delay, *loss, *burst)
	if err != nil {
		return quicBenchmarkOptions{}, err
	}
	return quicBenchmarkOptions{
		duration: *duration, packetSize: *size, packetsPS: *rate, flows: *flows,
		profile: *profile, delay: resolvedDelay, loss: *loss, burstLoss: *burst, seed: *seed, output: os.Stdout,
	}, nil
}

func runNativeUDPBenchmark(parent context.Context, options quicBenchmarkOptions) (quicBenchmarkResult, error) {
	if options.flows == 0 {
		options.flows = 1
	}
	if err := validateBaselineOptions(options); err != nil {
		return quicBenchmarkResult{}, err
	}
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return quicBenchmarkResult{}, fmt.Errorf("native UDP listen: %w", err)
	}
	defer listener.Close()
	client, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return quicBenchmarkResult{}, fmt.Errorf("native UDP dial: %w", err)
	}
	defer client.Close()

	measurement := beginBenchmarkMeasurement()
	ctx, cancel := context.WithTimeout(parent, options.duration)
	defer cancel()
	sourceStats, sinkStats := &counters{}, &counters{}
	impairment := newBenchmarkImpairment(options.delay, options.loss, options.burstLoss, options.seed, sourceStats)
	receiverDone := make(chan struct{})
	go func() {
		defer close(receiverDone)
		buffer := make([]byte, options.packetSize+1)
		for {
			n, _, readErr := listener.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			observeBenchmarkPacket(sinkStats, buffer[:n], options.packetSize)
		}
	}()
	progressDone := startBenchmarkProgress(ctx, options.output, sinkStats, "native-udp")
	started := time.Now()
	packet := make([]byte, options.packetSize)
	ticker := benchmarkTicker(options.packetsPS)
	if ticker != nil {
		defer ticker.Stop()
	}
	var sent uint64
	for ctx.Err() == nil {
		if !waitBenchmarkTick(ctx, ticker) {
			break
		}
		sequence := sourceStats.packets.Load()
		initializeFlowPacket(packet, sequence, options.flows)
		sourceStats.packets.Add(1)
		sourceStats.bytes.Add(uint64(len(packet)))
		if impairment.drop() {
			continue
		}
		if impairment.wait(ctx) != nil {
			break
		}
		binary.BigEndian.PutUint64(packet[ipv4HeaderLen+8:], uint64(time.Now().Add(-options.delay).UnixNano()))
		if _, err := client.Write(packet); err != nil {
			if ctx.Err() == nil {
				return quicBenchmarkResult{}, err
			}
			break
		}
		sent++
	}
	elapsed := time.Since(started)
	waitForBenchmarkDrain(parent, sinkStats, sent, 250*time.Millisecond)
	resources := measurement.finish()
	_ = listener.Close()
	<-receiverDone
	<-progressDone
	return baselineResult("native-udp", "udp", "unauthenticated-loopback-baseline", options, elapsed, sent, sourceStats, sinkStats, resources), nil
}

func runAuthenticatedQUICStreamBenchmark(parent context.Context, options quicBenchmarkOptions) (quicBenchmarkResult, error) {
	if options.flows == 0 {
		options.flows = 1
	}
	if err := validateBaselineOptions(options); err != nil {
		return quicBenchmarkResult{}, err
	}
	material, err := newBenchmarkIdentityMaterial()
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	serverTLS := material.relayTLS.Clone()
	serverTLS.NextProtos = []string{benchmarkStreamALPN}
	clientTLS := material.sourceTLS.Clone()
	clientTLS.NextProtos = []string{benchmarkStreamALPN}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{})
	if err != nil {
		return quicBenchmarkResult{}, fmt.Errorf("QUIC stream listen: %w", err)
	}
	defer listener.Close()
	setupCtx, cancelSetup := context.WithTimeout(parent, 5*time.Second)
	defer cancelSetup()
	accepted := make(chan quicAccept, 1)
	go func() {
		conn, acceptErr := listener.Accept(setupCtx)
		accepted <- quicAccept{conn: conn, err: acceptErr}
	}()
	clientConn, err := quic.DialAddr(setupCtx, listener.Addr().String(), clientTLS, &quic.Config{})
	if err != nil {
		return quicBenchmarkResult{}, fmt.Errorf("QUIC stream dial: %w", err)
	}
	defer clientConn.CloseWithError(0, "benchmark complete")
	serverAccepted := <-accepted
	if serverAccepted.err != nil {
		return quicBenchmarkResult{}, fmt.Errorf("QUIC stream accept: %w", serverAccepted.err)
	}
	defer serverAccepted.conn.CloseWithError(0, "benchmark complete")
	clientStream, err := clientConn.OpenStreamSync(setupCtx)
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	if err := writeAll(clientStream, []byte("LWBS")); err != nil {
		return quicBenchmarkResult{}, err
	}
	serverStream, err := serverAccepted.conn.AcceptStream(setupCtx)
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	preface := make([]byte, 4)
	if _, err := io.ReadFull(serverStream, preface); err != nil || string(preface) != "LWBS" {
		return quicBenchmarkResult{}, errors.New("QUIC stream benchmark preface failed")
	}

	measurement := beginBenchmarkMeasurement()
	ctx, cancel := context.WithTimeout(parent, options.duration)
	defer cancel()
	sourceStats, sinkStats := &counters{}, &counters{}
	impairment := newBenchmarkImpairment(options.delay, options.loss, options.burstLoss, options.seed, sourceStats)
	receiverDone := make(chan error, 1)
	go func() { receiverDone <- receiveQUICStream(serverStream, sinkStats, options.packetSize) }()
	progressDone := startBenchmarkProgress(ctx, options.output, sinkStats, "quic-stream")
	started := time.Now()
	packet := make([]byte, options.packetSize)
	frame := make([]byte, 4+options.packetSize)
	ticker := benchmarkTicker(options.packetsPS)
	if ticker != nil {
		defer ticker.Stop()
	}
	var sent uint64
	for ctx.Err() == nil {
		if !waitBenchmarkTick(ctx, ticker) {
			break
		}
		sequence := sourceStats.packets.Load()
		initializeFlowPacket(packet, sequence, options.flows)
		sourceStats.packets.Add(1)
		sourceStats.bytes.Add(uint64(len(packet)))
		if impairment.drop() {
			continue
		}
		if impairment.wait(ctx) != nil {
			break
		}
		binary.BigEndian.PutUint64(packet[ipv4HeaderLen+8:], uint64(time.Now().Add(-options.delay).UnixNano()))
		binary.BigEndian.PutUint32(frame[:4], uint32(len(packet)))
		copy(frame[4:], packet)
		if err := writeAll(clientStream, frame); err != nil {
			if ctx.Err() == nil {
				return quicBenchmarkResult{}, err
			}
			break
		}
		sent++
	}
	elapsed := time.Since(started)
	_ = clientStream.Close()
	_ = serverStream.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	receiveErr := <-receiverDone
	if receiveErr != nil && !errors.Is(receiveErr, io.EOF) && !errors.Is(receiveErr, os.ErrDeadlineExceeded) {
		return quicBenchmarkResult{}, receiveErr
	}
	resources := measurement.finish()
	<-progressDone
	return baselineResult("quic-stream", "quic-stream", "tls1.3-mtls-stream-baseline", options, elapsed, sent, sourceStats, sinkStats, resources), nil
}

type quicAccept struct {
	conn *quic.Conn
	err  error
}

func receiveQUICStream(stream *quic.Stream, stats *counters, packetSize int) error {
	header := make([]byte, 4)
	packet := make([]byte, packetSize+1)
	for {
		if _, err := io.ReadFull(stream, header); err != nil {
			return err
		}
		length := int(binary.BigEndian.Uint32(header))
		if length <= 0 || length > len(packet) {
			return errors.New("QUIC stream benchmark received an invalid frame length")
		}
		if _, err := io.ReadFull(stream, packet[:length]); err != nil {
			return err
		}
		observeBenchmarkPacket(stats, packet[:length], packetSize)
	}
}

func writeAll(writer io.Writer, buffer []byte) error {
	for len(buffer) > 0 {
		n, err := writer.Write(buffer)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		buffer = buffer[n:]
	}
	return nil
}

func benchmarkTicker(packetsPS uint64) *time.Ticker {
	if packetsPS == 0 {
		return nil
	}
	interval := time.Second / time.Duration(packetsPS)
	if interval < time.Nanosecond {
		interval = time.Nanosecond
	}
	return time.NewTicker(interval)
}

func waitBenchmarkTick(ctx context.Context, ticker *time.Ticker) bool {
	if ticker == nil {
		return ctx.Err() == nil
	}
	select {
	case <-ctx.Done():
		return false
	case <-ticker.C:
		return true
	}
}

func validateBaselineOptions(options quicBenchmarkOptions) error {
	if options.flows == 0 {
		options.flows = 1
	}
	if options.duration <= 0 || options.packetSize < ipv4HeaderLen+benchmarkMetaLen || options.packetSize > maxQUICPacketSize || !validFlowCount(options.flows) {
		return errors.New("invalid baseline benchmark options")
	}
	return nil
}

func baselineResult(scenario, transportName, scope string, options quicBenchmarkOptions, duration time.Duration, sent uint64, source, sink *counters, resources benchmarkResources) quicBenchmarkResult {
	generated, received := source.packets.Load(), sink.packets.Load()
	dropped := uint64(0)
	if generated > received {
		dropped = generated - received
	}
	return quicBenchmarkResult{
		scenario: scenario, transport: transportName, scope: scope, profile: options.profile,
		flows: options.flows, packetSize: options.packetSize, duration: duration,
		generated: generated, sent: sent, received: received, bytes: sink.bytes.Load(), dropped: dropped, bad: sink.bad.Load(),
		p50: sink.percentile(50), p95: sink.percentile(95), p99: sink.percentile(99), resources: resources,
	}
}
