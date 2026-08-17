package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Doout/laneway/go/internal/routing"
	"github.com/Doout/laneway/go/internal/tcpfallback"
)

type rustRelayProcess struct {
	command *exec.Cmd
	output  lockedBuffer
	done    chan error
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(value)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func runExternalRustRelay(parent context.Context, args []string, tcp bool) error {
	name := "rust-relay-quic"
	if tcp {
		name = "rust-relay-tcp"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	binary := fs.String("relay-binary", "", "path to a release laneway-relay Rust binary")
	duration := fs.Duration("duration", 3*time.Second, "measurement duration")
	size := fs.Int("size", 1200, "raw IP packet size")
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
	if strings.TrimSpace(*binary) == "" {
		return errors.New("-relay-binary is required")
	}
	if *duration <= 0 || *size < ipv4HeaderLen+benchmarkMetaLen || *size > maxQUICPacketSize {
		return errors.New("duration and packet size are outside benchmark bounds")
	}
	if *queue <= 0 || *queue > 4096 {
		return errors.New("queue must be in [1,4096]")
	}
	resolvedDelay, err := validateMatrixDimensions(*flows, *profile, *delay, *loss, *burst)
	if err != nil {
		return err
	}
	result, err := runAuthenticatedExternalRustRelayBenchmark(parent, quicBenchmarkOptions{
		duration: *duration, packetSize: *size, packetsPS: *rate, queue: *queue,
		flows: *flows, profile: *profile, delay: resolvedDelay, loss: *loss,
		burstLoss: *burst, seed: *seed, output: os.Stdout,
	}, tcp, *binary)
	if err != nil {
		return err
	}
	printBenchmarkSummary(os.Stdout, result)
	return nil
}

func runAuthenticatedExternalRustRelayBenchmark(parent context.Context, options quicBenchmarkOptions, tcp bool, binary string) (quicBenchmarkResult, error) {
	if strings.TrimSpace(binary) == "" {
		return quicBenchmarkResult{}, errors.New("external Rust relay binary path is required")
	}
	material, err := newBenchmarkIdentityMaterial()
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	temporary, err := os.MkdirTemp("", "laneway-rust-relay-benchmark-")
	if err != nil {
		return quicBenchmarkResult{}, fmt.Errorf("create benchmark directory: %w", err)
	}
	defer os.RemoveAll(temporary)

	udpAddress, err := reserveBenchmarkAddress("udp")
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	tcpAddress, err := reserveBenchmarkAddress("tcp")
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	metricsAddress, err := reserveBenchmarkAddress("tcp")
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	configPath, err := writeRustRelayBenchmarkConfig(temporary, material, options, udpAddress, tcpAddress, metricsAddress, tcp)
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	relayContext, cancelRelay := context.WithCancel(parent)
	defer cancelRelay()
	process, err := startRustRelayBenchmarkProcess(relayContext, binary, configPath)
	if err != nil {
		return quicBenchmarkResult{}, err
	}

	sourceAddress := netip.MustParseAddr(benchmarkSourceAddress)
	sinkAddress := netip.MustParseAddr(benchmarkSinkAddress)
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
	tcpConfig := &tcpfallback.Config{QueueDepth: options.queue, MaxPacketPayload: options.packetSize + 5}
	nodeUDPAddress, nodeTCPAddress := udpAddress, ""
	if tcp {
		nodeUDPAddress, nodeTCPAddress = "127.0.0.1:1", tcpAddress
	}
	sourceService, err := newBenchmarkNode(material.sourceIdentity, nodeUDPAddress, nodeTCPAddress, material.sourceTLS, tcpConfig, sourceRoutes, sourcePackets)
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	sinkService, err := newBenchmarkNode(material.sinkIdentity, nodeUDPAddress, nodeTCPAddress, material.sinkTLS, tcpConfig, sinkRoutes, sinkPackets)
	if err != nil {
		return quicBenchmarkResult{}, err
	}

	sessionContext, cancelSessions := context.WithCancel(parent)
	defer cancelSessions()
	componentErrors := make(chan error, 3)
	go func() {
		processErr := <-process.done
		if relayContext.Err() == nil {
			if processErr == nil {
				processErr = errors.New("stopped unexpectedly")
			}
			componentErrors <- fmt.Errorf("Rust relay: %w; output: %s", processErr, process.diagnostics())
		}
	}()
	go runBenchmarkComponent(sessionContext, "source node", componentErrors, func() error {
		return sourceService.RunSession(sessionContext)
	})
	go runBenchmarkComponent(sessionContext, "sink node", componentErrors, func() error {
		return sinkService.RunSession(sessionContext)
	})
	readyContext, cancelReady := context.WithTimeout(parent, 10*time.Second)
	err = waitForBenchmarkRoutes(readyContext, sourceService, material.sinkIdentity.NodeID, sinkService, material.sourceIdentity.NodeID, componentErrors)
	cancelReady()
	if err != nil {
		return quicBenchmarkResult{}, fmt.Errorf("external Rust relay readiness: %w; output: %s", err, process.diagnostics())
	}
	metricsContext, cancelMetrics := context.WithTimeout(parent, 2*time.Second)
	relayMetricsStart, err := readRustRelayMetrics(metricsContext, metricsAddress)
	cancelMetrics()
	if err != nil {
		return quicBenchmarkResult{}, fmt.Errorf("read initial Rust relay benchmark metrics: %w; output: %s", err, process.diagnostics())
	}
	if relayMetricsStart.queueDepth != 0 || relayMetricsStart.queueDepthPeak != 0 {
		return quicBenchmarkResult{}, errors.New("Rust relay queue metrics were nonzero before measurement")
	}

	measurement := beginBenchmarkMeasurement()
	relayCPUStart, err := processCPUTimeForPID(process.command.Process.Pid)
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	relayMeasurementStarted := time.Now()
	measurementContext, cancelMeasurement := context.WithTimeout(parent, options.duration)
	started := time.Now()
	sourcePackets.start(measurementContext)
	progressScenario := "rust-relay-quic"
	if tcp {
		progressScenario = "rust-relay-tcp"
	}
	progressDone := startBenchmarkProgress(measurementContext, options.output, receiverStats, progressScenario)
	select {
	case <-measurementContext.Done():
	case componentErr := <-componentErrors:
		cancelMeasurement()
		return quicBenchmarkResult{}, fmt.Errorf("%w; Rust relay output: %s", componentErr, process.diagnostics())
	}
	cancelMeasurement()
	elapsed := time.Since(started)
	<-progressDone
	sourcePackets.waitForHalt(100 * time.Millisecond)
	sent := sourceService.Metrics().PacketsSent
	waitForBenchmarkDrain(parent, receiverStats, sent, 250*time.Millisecond)
	metricsContext, cancelMetrics = context.WithTimeout(parent, 2*time.Second)
	relayMetricsEnd, err := readRustRelayMetrics(metricsContext, metricsAddress)
	cancelMetrics()
	if err != nil {
		return quicBenchmarkResult{}, fmt.Errorf("read final Rust relay benchmark metrics: %w; output: %s", err, process.diagnostics())
	}
	if relayMetricsEnd.queueDepth != 0 {
		return quicBenchmarkResult{}, fmt.Errorf("Rust relay retained %d queued packets after drain", relayMetricsEnd.queueDepth)
	}
	relayAllocations, err := monotonicCounterDelta("Rust relay allocator allocations", relayMetricsStart.allocations, relayMetricsEnd.allocations)
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	relayAllocatedBytes, err := monotonicCounterDelta("Rust relay allocator allocated bytes", relayMetricsStart.allocatedBytes, relayMetricsEnd.allocatedBytes)
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	received := receiverStats.packets.Load()
	generated := sourceStats.packets.Load()
	dropped := uint64(0)
	if generated > received {
		dropped = generated - received
	}
	receiverStats.drops.Store(dropped)
	relayElapsed := time.Since(relayMeasurementStarted)
	relayCPUEnd, err := processCPUTimeForPID(process.command.Process.Pid)
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	if relayCPUEnd < relayCPUStart {
		return quicBenchmarkResult{}, errors.New("Rust relay CPU counter regressed")
	}
	relayCPU := relayCPUEnd - relayCPUStart
	relayCPUPercent := 0.0
	if relayElapsed > 0 && relayCPU > 0 {
		relayCPUPercent = float64(relayCPU) / float64(relayElapsed) * 100
	}
	relayRSS, err := externalProcessRSSBytes(process.command.Process.Pid)
	if err != nil {
		return quicBenchmarkResult{}, err
	}
	result := quicBenchmarkResult{
		scenario: progressScenario,
		transport: func() string {
			if tcp {
				return "tls1.3-tcp"
			}
			return "quic-datagram"
		}(),
		scope: "authenticated-external-rust-relay", profile: options.profile,
		flows: options.flows, packetSize: options.packetSize, duration: elapsed,
		generated: generated, sent: sent, received: received, bytes: receiverStats.bytes.Load(),
		dropped: dropped, bad: receiverStats.bad.Load(), p50: receiverStats.percentile(50),
		p95: receiverStats.percentile(95), p99: receiverStats.percentile(99),
		queueCapacity:   options.queue,
		queueDepth:      relayMetricsEnd.queueDepth,
		queuePeak:       relayMetricsEnd.queueDepthPeak,
		queuePeakScope:  "relay-counter",
		relayCPU:        relayCPUPercent,
		relayRSS:        relayRSS,
		relayAllocs:     relayAllocations,
		relayAllocBytes: relayAllocatedBytes,
	}
	result.resources = measurement.finish()
	cancelSessions()
	cancelRelay()
	if result.generated == 0 && parent.Err() == nil {
		return quicBenchmarkResult{}, errors.New("external Rust relay benchmark generated no packets")
	}
	if result.received > 0 && result.queuePeak == 0 {
		return quicBenchmarkResult{}, errors.New("Rust relay queue peak remained zero after forwarding traffic")
	}
	return result, nil
}

func reserveBenchmarkAddress(network string) (string, error) {
	if network == "udp" {
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			return "", fmt.Errorf("reserve UDP benchmark address: %w", err)
		}
		address := listener.LocalAddr().String()
		if err := listener.Close(); err != nil {
			return "", fmt.Errorf("release UDP benchmark address: %w", err)
		}
		return address, nil
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("reserve TCP benchmark address: %w", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return "", fmt.Errorf("release TCP benchmark address: %w", err)
	}
	return address, nil
}

func writeRustRelayBenchmarkConfig(directory string, material benchmarkIdentityMaterial, options quicBenchmarkOptions, udpAddress, tcpAddress, metricsAddress string, tcp bool) (string, error) {
	certificatePath := filepath.Join(directory, "relay.crt")
	keyPath := filepath.Join(directory, "relay.key")
	caPath := filepath.Join(directory, "ca.crt")
	keyDER, err := x509.MarshalPKCS8PrivateKey(material.relayMaterial.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("marshal benchmark relay key: %w", err)
	}
	files := []struct {
		path  string
		block *pem.Block
		mode  os.FileMode
	}{
		{certificatePath, &pem.Block{Type: "CERTIFICATE", Bytes: material.relayMaterial.CertificateDER}, 0o644},
		{keyPath, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}, 0o600},
		{caPath, &pem.Block{Type: "CERTIFICATE", Bytes: material.caCertificate.Raw}, 0o644},
	}
	for _, file := range files {
		if err := os.WriteFile(file.path, pem.EncodeToMemory(file.block), file.mode); err != nil {
			return "", fmt.Errorf("write benchmark credential %s: %w", filepath.Base(file.path), err)
		}
	}
	config := fmt.Sprintf(`mode = "relay"
[tls]
certificate = %q
private_key = %q
ca = %q
[relay]
listen = %q
queue_depth = %d
max_sessions = 4
max_routes = 4
handshake_timeout = "5s"
idle_timeout = "5s"
metrics_interval = "0s"
metrics_listen = %q
candidate_republish_floor = "5s"
`, certificatePath, keyPath, caPath, udpAddress, options.queue, metricsAddress)
	if tcp {
		config += fmt.Sprintf(`[tcp_fallback]
listen = %q
handshake_timeout = "5s"
write_timeout = "5s"
idle_timeout = "5s"
keepalive_period = "1s"
queue_depth = %d
`, tcpAddress, options.queue)
	}
	for _, peer := range []struct {
		id      string
		address string
	}{
		{material.sourceIdentity.NodeID.String(), benchmarkSourceAddress},
		{material.sinkIdentity.NodeID.String(), benchmarkSinkAddress},
	} {
		config += fmt.Sprintf(`[[peers]]
network_id = %q
node_id = %q
prefixes = [%q]
`, material.networkID.String(), peer.id, peer.address+"/32")
	}
	path := filepath.Join(directory, "relay.toml")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		return "", fmt.Errorf("write Rust relay benchmark config: %w", err)
	}
	return path, nil
}

type rustRelayMetrics struct {
	allocations    uint64
	allocatedBytes uint64
	queueDepth     uint64
	queueDepthPeak uint64
}

func readRustRelayMetrics(ctx context.Context, address string) (rustRelayMetrics, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/metrics", nil)
	if err != nil {
		return rustRelayMetrics{}, err
	}
	response, err := (&http.Client{Timeout: 2 * time.Second}).Do(request)
	if err != nil {
		return rustRelayMetrics{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return rustRelayMetrics{}, fmt.Errorf("metrics status %s", response.Status)
	}
	const maximumMetricsBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumMetricsBody+1))
	if err != nil {
		return rustRelayMetrics{}, err
	}
	if len(body) > maximumMetricsBody {
		return rustRelayMetrics{}, errors.New("Rust relay metrics body exceeds 1 MiB")
	}
	return parseRustRelayMetrics(body)
}

func parseRustRelayMetrics(body []byte) (rustRelayMetrics, error) {
	wanted := map[string]*uint64{
		"laneway_relay_allocator_allocations_total":     nil,
		"laneway_relay_allocator_allocated_bytes_total": nil,
		"laneway_relay_queue_depth":                     nil,
		"laneway_relay_queue_depth_peak":                nil,
	}
	values := make(map[string]uint64, len(wanted))
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if _, ok := wanted[fields[0]]; !ok {
			continue
		}
		if _, duplicate := values[fields[0]]; duplicate {
			return rustRelayMetrics{}, fmt.Errorf("duplicate Rust relay metric %s", fields[0])
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			return rustRelayMetrics{}, fmt.Errorf("parse metric %s: %w", fields[0], parseErr)
		}
		values[fields[0]] = value
	}
	metrics := rustRelayMetrics{
		allocations:    values["laneway_relay_allocator_allocations_total"],
		allocatedBytes: values["laneway_relay_allocator_allocated_bytes_total"],
		queueDepth:     values["laneway_relay_queue_depth"],
		queueDepthPeak: values["laneway_relay_queue_depth_peak"],
	}
	if len(values) != len(wanted) {
		return rustRelayMetrics{}, errors.New("Rust relay benchmark metrics are missing")
	}
	return metrics, nil
}

func monotonicCounterDelta(name string, start, end uint64) (uint64, error) {
	if end < start {
		return 0, fmt.Errorf("%s regressed from %d to %d", name, start, end)
	}
	return end - start, nil
}

func startRustRelayBenchmarkProcess(ctx context.Context, binary, config string) (*rustRelayProcess, error) {
	process := &rustRelayProcess{done: make(chan error, 1)}
	process.command = exec.CommandContext(ctx, binary, "--config", config)
	process.command.Stdout = &process.output
	process.command.Stderr = &process.output
	if err := process.command.Start(); err != nil {
		return nil, fmt.Errorf("start external Rust relay: %w", err)
	}
	go func() { process.done <- process.command.Wait() }()
	return process, nil
}

func (p *rustRelayProcess) diagnostics() string {
	const maximum = 4096
	text := p.output.String()
	if len(text) > maximum {
		text = text[len(text)-maximum:]
	}
	return strings.TrimSpace(text)
}
