// netprobe is a deliberately small process used by the privileged namespace
// integration suite. It keeps application traffic generation independent of
// optional host utilities such as ping, socat, and curl.
package main

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"laneway.dev/laneway/internal/exitnode"
	"laneway.dev/laneway/internal/identity"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: netprobe <udp-server|udp-client|udp-echo-server|udp-bench-client|tcp-server|tcp-client|metric|certificate-info|exit-client|exit-gateway> [flags]")
	}
	var err error
	switch os.Args[1] {
	case "udp-server":
		err = udpServer(os.Args[2:])
	case "udp-client":
		err = udpClient(os.Args[2:])
	case "udp-echo-server":
		err = udpEchoServer(os.Args[2:])
	case "udp-bench-client":
		err = udpBenchClient(os.Args[2:])
	case "tcp-server":
		err = tcpServer(os.Args[2:])
	case "tcp-client":
		err = tcpClient(os.Args[2:])
	case "metric":
		err = metric(os.Args[2:])
	case "certificate-info":
		err = certificateInfo(os.Args[2:])
	case "exit-client":
		err = exitClient(os.Args[2:])
	case "exit-gateway":
		err = exitGateway(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fatal(err.Error())
	}
}

func certificateInfo(args []string) error {
	fs := flag.NewFlagSet("certificate-info", flag.ContinueOnError)
	path := fs.String("cert", "", "PEM certificate chain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *path == "" {
		return fmt.Errorf("usage: netprobe certificate-info -cert path")
	}
	contents, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("%s does not begin with a PEM certificate", *path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	authenticated, err := identity.IdentityFromCertificate(certificate)
	if err != nil {
		return err
	}
	serial := certificate.SerialNumber.Bytes()
	if len(serial) == 0 {
		return fmt.Errorf("certificate serial is not positive")
	}
	fmt.Printf("network=%s node=%s serial=%s\n", authenticated.NetworkID, authenticated.NodeID, hex.EncodeToString(serial))
	return nil
}

func udpServer(args []string) error {
	fs := flag.NewFlagSet("udp-server", flag.ContinueOnError)
	listen := fs.String("listen", "", "UDP listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	address, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Println("ready=udp-server")
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return err
	}
	buffer := make([]byte, 2048)
	n, remote, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return err
	}
	fmt.Printf("remote=%s payload=%s\n", remote, string(buffer[:n]))
	_, err = conn.WriteToUDP(buffer[:n], remote)
	return err
}

func udpClient(args []string) error {
	fs := flag.NewFlagSet("udp-client", flag.ContinueOnError)
	target := fs.String("target", "", "UDP target address")
	message := fs.String("message", "laneway-netprobe", "payload to exchange")
	timeout := fs.Duration("timeout", 12*time.Second, "overall retry timeout")
	once := fs.Bool("once", false, "send only once")
	if err := fs.Parse(args); err != nil {
		return err
	}
	remote, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline := time.Now().Add(*timeout)
	buffer := make([]byte, 2048)
	for {
		attemptDeadline := time.Now().Add(500 * time.Millisecond)
		if attemptDeadline.After(deadline) {
			attemptDeadline = deadline
		}
		if err := conn.SetDeadline(attemptDeadline); err != nil {
			return err
		}
		if _, err := conn.WriteToUDP([]byte(*message), remote); err == nil {
			n, source, readErr := conn.ReadFromUDP(buffer)
			if readErr == nil && source.IP.Equal(remote.IP) && source.Port == remote.Port && string(buffer[:n]) == *message {
				fmt.Printf("reply=%s payload=%s\n", source, string(buffer[:n]))
				return nil
			}
		}
		if *once || !time.Now().Before(deadline) {
			return fmt.Errorf("no valid UDP reply from %s", remote)
		}
	}
}

func udpEchoServer(args []string) error {
	fs := flag.NewFlagSet("udp-echo-server", flag.ContinueOnError)
	listen := fs.String("listen", "", "UDP listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	address, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetReadBuffer(4 << 20); err != nil {
		return err
	}
	if err := conn.SetWriteBuffer(4 << 20); err != nil {
		return err
	}
	fmt.Println("ready=udp-echo-server")
	buffer := make([]byte, 65535)
	for {
		n, remote, readErr := conn.ReadFromUDP(buffer)
		if readErr != nil {
			return readErr
		}
		if _, writeErr := conn.WriteToUDP(buffer[:n], remote); writeErr != nil {
			return writeErr
		}
	}
}

type udpBenchReport struct {
	Schema             string  `json:"schema"`
	Scenario           string  `json:"scenario"`
	Scope              string  `json:"scope"`
	Flows              int     `json:"flows"`
	PacketSize         int     `json:"packet_size"`
	DurationMS         int64   `json:"duration_ms"`
	ResourceDurationMS int64   `json:"resource_duration_ms"`
	ResourceScope      string  `json:"resource_scope"`
	Generated          uint64  `json:"generated"`
	Sent               uint64  `json:"sent"`
	SendErrors         uint64  `json:"send_errors"`
	Received           uint64  `json:"received"`
	Bytes              uint64  `json:"bytes"`
	Drops              uint64  `json:"drops"`
	LossPercent        float64 `json:"loss_percent"`
	Bad                uint64  `json:"bad"`
	PPS                float64 `json:"pps"`
	Gbps               float64 `json:"gbps"`
	P50US              int64   `json:"p50_us"`
	P95US              int64   `json:"p95_us"`
	P99US              int64   `json:"p99_us"`
	LatencySamples     uint64  `json:"latency_samples"`
	CPUPercent         float64 `json:"cpu_percent"`
	RSSBytes           uint64  `json:"rss_bytes"`
	Allocations        uint64  `json:"allocations"`
	GCCount            uint32  `json:"gc_count"`
	GCPauseNS          uint64  `json:"gc_pause_ns"`
}

const maxUDPBenchmarkLatencySamples = 1_000_000

func udpBenchClient(args []string) error {
	fs := flag.NewFlagSet("udp-bench-client", flag.ContinueOnError)
	target := fs.String("target", "", "UDP echo target")
	scenario := fs.String("scenario", "kernel-path", "machine-readable scenario name")
	scope := fs.String("scope", "udp-echo-unspecified-path", "machine-readable measured path scope")
	duration := fs.Duration("duration", time.Second, "measurement duration")
	packetSize := fs.Int("size", 1200, "UDP payload bytes")
	packetsPerSecond := fs.Uint64("pps", 1000, "aggregate packet rate")
	flows := fs.Int("flows", 1, "concurrent UDP flows")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *duration < 10*time.Millisecond || *duration > time.Minute || *packetSize < 16 || *packetSize > 60000 ||
		*packetsPerSecond == 0 || *packetsPerSecond > 1_000_000 || *flows < 1 || *flows > 100 {
		return errors.New("UDP benchmark dimensions are outside bounded limits")
	}
	if !validBenchmarkLabel(*scenario) || !validBenchmarkLabel(*scope) {
		return errors.New("UDP benchmark scenario and scope must be nonempty bounded labels")
	}
	interval := time.Second / time.Duration(*packetsPerSecond)
	if *duration <= interval {
		return errors.New("UDP benchmark duration must exceed one packet interval")
	}
	remote, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		return err
	}
	connections := make([]*net.UDPConn, *flows)
	payloads := make([][]byte, *flows)
	for i := range connections {
		connection, dialErr := net.DialUDP("udp", nil, remote)
		if dialErr != nil {
			return dialErr
		}
		connections[i] = connection
		payloads[i] = make([]byte, *packetSize)
	}
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()

	maximumGenerated := uint64((*duration + interval - 1) / interval)
	latencyStride := (maximumGenerated + maxUDPBenchmarkLatencySamples - 1) / maxUDPBenchmarkLatencySamples
	maximumSamples := (maximumGenerated + latencyStride - 1) / latencyStride
	latencies := make([]int64, 0, int(maximumSamples))
	maximumPerFlow := (maximumGenerated + uint64(*flows) - 1) / uint64(*flows)
	seen := make([][]uint64, *flows)
	for flow := range seen {
		seen[flow] = make([]uint64, (maximumPerFlow+63)/64)
	}
	var received, bytesReceived, bad atomic.Uint64
	var latencyMu sync.Mutex
	stop := make(chan struct{})
	var receivers sync.WaitGroup
	for flow, connection := range connections {
		receivers.Add(1)
		go func(flow int, connection *net.UDPConn) {
			defer receivers.Done()
			buffer := make([]byte, *packetSize+1)
			for {
				_ = connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, readErr := connection.Read(buffer)
				if readErr != nil {
					if networkErr, ok := readErr.(net.Error); ok && networkErr.Timeout() {
						select {
						case <-stop:
							return
						default:
							continue
						}
					}
					return
				}
				if n != *packetSize {
					bad.Add(1)
					continue
				}
				sequence := binary.BigEndian.Uint64(buffer[:8])
				if sequence == 0 || sequence > maximumGenerated ||
					int((sequence-1)%uint64(*flows)) != flow {
					bad.Add(1)
					continue
				}
				flowSequence := (sequence - 1) / uint64(*flows)
				word, mask := flowSequence/64, uint64(1)<<(flowSequence%64)
				if seen[flow][word]&mask != 0 {
					bad.Add(1)
					continue
				}
				seen[flow][word] |= mask
				sentAt := int64(binary.BigEndian.Uint64(buffer[8:16]))
				latency := time.Now().UnixNano() - sentAt
				if sentAt <= 0 || latency < 0 {
					bad.Add(1)
					continue
				}
				received.Add(1)
				bytesReceived.Add(uint64(n))
				if (sequence-1)%latencyStride == 0 {
					latencyMu.Lock()
					latencies = append(latencies, latency)
					latencyMu.Unlock()
				}
			}
		}(flow, connection)
	}

	var memoryStart runtime.MemStats
	runtime.ReadMemStats(&memoryStart)
	cpuStart := processCPUTime()
	started := time.Now()
	deadline := started.Add(*duration)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var generated, sent uint64
	for now := range ticker.C {
		if !now.Before(deadline) {
			break
		}
		flow := generated % uint64(len(connections))
		payload := payloads[flow]
		binary.BigEndian.PutUint64(payload[:8], generated+1)
		binary.BigEndian.PutUint64(payload[8:16], uint64(time.Now().UnixNano()))
		generated++
		if _, writeErr := connections[flow].Write(payload); writeErr == nil {
			sent++
		}
	}
	measurementElapsed := time.Since(started)
	time.Sleep(250 * time.Millisecond)
	close(stop)
	for _, connection := range connections {
		_ = connection.Close()
	}
	receivers.Wait()
	resourceElapsed := time.Since(started)
	cpuElapsed := processCPUTime() - cpuStart
	var memoryEnd runtime.MemStats
	runtime.ReadMemStats(&memoryEnd)
	latencyMu.Lock()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p50, p95, p99 := percentileNanoseconds(latencies, 50), percentileNanoseconds(latencies, 95), percentileNanoseconds(latencies, 99)
	latencyMu.Unlock()
	receivedCount := received.Load()
	if generated == 0 || sent == 0 || receivedCount == 0 {
		return errors.New("UDP benchmark did not complete a packet exchange")
	}
	if receivedCount > sent {
		return fmt.Errorf("UDP benchmark received %d packets after only %d successful sends", receivedCount, sent)
	}
	drops := uint64(0)
	if sent > receivedCount {
		drops = sent - receivedCount
	}
	lossPercent := float64(drops) / float64(sent) * 100
	cpuPercent := 0.0
	if resourceElapsed > 0 {
		cpuPercent = float64(cpuElapsed) / float64(resourceElapsed) * 100
	}
	report := udpBenchReport{
		Schema: "laneway-kernel-datapath-benchmark-v1", Scenario: *scenario,
		Scope: *scope, Flows: *flows,
		PacketSize: *packetSize, DurationMS: measurementElapsed.Milliseconds(), ResourceDurationMS: resourceElapsed.Milliseconds(), ResourceScope: processResourceScope(), Generated: generated,
		Sent: sent, SendErrors: generated - sent, Received: receivedCount, Bytes: bytesReceived.Load(), Drops: drops,
		LossPercent: lossPercent, Bad: bad.Load(), PPS: float64(receivedCount) / measurementElapsed.Seconds(),
		Gbps:  float64(bytesReceived.Load()) * 8 / measurementElapsed.Seconds() / 1_000_000_000,
		P50US: p50 / 1000, P95US: p95 / 1000, P99US: p99 / 1000, LatencySamples: uint64(len(latencies)),
		CPUPercent: cpuPercent, RSSBytes: processRSSBytes(),
		Allocations: memoryEnd.Mallocs - memoryStart.Mallocs, GCCount: memoryEnd.NumGC - memoryStart.NumGC,
		GCPauseNS: memoryEnd.PauseTotalNs - memoryStart.PauseTotalNs,
	}
	if err := report.validate(); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}

func validBenchmarkLabel(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func (report udpBenchReport) validate() error {
	if report.Schema != "laneway-kernel-datapath-benchmark-v1" || report.Generated == 0 ||
		report.Sent == 0 || report.Received == 0 || report.DurationMS <= 0 ||
		report.ResourceDurationMS < report.DurationMS || report.ResourceScope == "" {
		return errors.New("UDP benchmark report has invalid dimensions")
	}
	if report.Generated != report.Sent+report.SendErrors || report.Sent != report.Received+report.Drops ||
		report.Bytes != report.Received*uint64(report.PacketSize) {
		return errors.New("UDP benchmark report has inconsistent packet accounting")
	}
	if report.LossPercent < 0 || report.LossPercent > 100 || report.PPS <= 0 || report.Gbps <= 0 ||
		report.P50US < 0 || report.P95US < report.P50US || report.P99US < report.P95US ||
		report.LatencySamples == 0 || report.LatencySamples > report.Received {
		return errors.New("UDP benchmark report has invalid measurements")
	}
	return nil
}

func percentileNanoseconds(values []int64, percentile int) int64 {
	if len(values) == 0 {
		return 0
	}
	index := (len(values)*percentile + 99) / 100
	if index == 0 {
		index = 1
	}
	return values[index-1]
}

const maxTCPProbePayload = 2048

func tcpServer(args []string) error {
	fs := flag.NewFlagSet("tcp-server", flag.ContinueOnError)
	listen := fs.String("listen", "", "TCP listen address")
	timeout := fs.Duration("timeout", 20*time.Second, "accept and exchange deadline")
	if err := fs.Parse(args); err != nil {
		return err
	}
	address, err := net.ResolveTCPAddr("tcp", *listen)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(*timeout)); err != nil {
		return err
	}
	fmt.Println("ready=tcp-server")
	connection, err := listener.AcceptTCP()
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(*timeout)); err != nil {
		return err
	}
	payload, err := readTCPProbe(connection)
	if err != nil {
		return err
	}
	fmt.Printf("remote=%s payload=%s\n", connection.RemoteAddr(), string(payload))
	return writeTCPProbe(connection, payload)
}

func tcpClient(args []string) error {
	fs := flag.NewFlagSet("tcp-client", flag.ContinueOnError)
	target := fs.String("target", "", "TCP target address")
	message := fs.String("message", "laneway-netprobe", "payload to exchange")
	timeout := fs.Duration("timeout", 12*time.Second, "overall retry timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(*message) == 0 || len(*message) > maxTCPProbePayload {
		return fmt.Errorf("TCP message length must be in [1,%d]", maxTCPProbePayload)
	}
	remote, err := net.ResolveTCPAddr("tcp", *target)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(*timeout)
	for time.Now().Before(deadline) {
		attemptDeadline := time.Now().Add(500 * time.Millisecond)
		if attemptDeadline.After(deadline) {
			attemptDeadline = deadline
		}
		dialer := net.Dialer{Timeout: time.Until(attemptDeadline)}
		connection, dialErr := dialer.Dial("tcp", remote.String())
		if dialErr == nil {
			if err := connection.SetDeadline(attemptDeadline); err != nil {
				connection.Close()
				return err
			}
			writeErr := writeTCPProbe(connection, []byte(*message))
			response, readErr := readTCPProbe(connection)
			connection.Close()
			if writeErr == nil && readErr == nil && string(response) == *message {
				fmt.Printf("reply=%s payload=%s\n", remote, string(response))
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("no valid TCP reply from %s", remote)
}

func writeTCPProbe(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > maxTCPProbePayload {
		return fmt.Errorf("TCP probe payload length must be in [1,%d]", maxTCPProbePayload)
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) != 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func readTCPProbe(reader io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[:]))
	if length == 0 || length > maxTCPProbePayload {
		return nil, fmt.Errorf("TCP probe payload length must be in [1,%d]", maxTCPProbePayload)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func metric(args []string) error {
	fs := flag.NewFlagSet("metric", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:6060/metrics", "metrics URL")
	name := fs.String("name", "", "exact Prometheus metric name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get(*url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("metrics status %s", response.Status)
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == *name {
			if _, err := strconv.ParseUint(fields[1], 10, 64); err != nil {
				return fmt.Errorf("invalid value for %s: %w", *name, err)
			}
			fmt.Println(fields[1])
			return nil
		}
	}
	return fmt.Errorf("metric %q not found", *name)
}

func exitClient(args []string) error {
	fs := flag.NewFlagSet("exit-client", flag.ContinueOnError)
	interfaceName := fs.String("interface", "lane0", "tunnel interface")
	bypassText := fs.String("transport-bypass", "", "native relay address")
	ipv6 := fs.Bool("ipv6", false, "also install IPv6 split-default routes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bypass, err := netip.ParseAddr(*bypassText)
	if err != nil {
		return err
	}
	routes, err := exitnode.NewRouteManager(exitnode.RouteManagerConfig{InterfaceName: *interfaceName})
	if err != nil {
		return err
	}
	manager, err := exitnode.NewClientManager(routes, exitnode.NewMemoryDNSManager(), 5*time.Second)
	if err != nil {
		_ = routes.Close()
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	exitPrefixes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	dnsServers := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	if *ipv6 {
		exitPrefixes = append(exitPrefixes, netip.MustParsePrefix("::/0"))
		dnsServers = append(dnsServers, netip.MustParseAddr("2606:4700:4700::1111"))
	}
	if err := manager.Apply(ctx, exitnode.ClientPlan{
		Enabled: true, Authorized: true, FailureMode: exitnode.FailureModeClosed, PathAvailable: true,
		ExitPrefixes: exitPrefixes, TransportBypass: []netip.Addr{bypass}, DNSServers: dnsServers,
	}); err != nil {
		_ = manager.Close()
		return err
	}
	fmt.Println("ready=exit-client")
	<-ctx.Done()
	return manager.Close()
}

func exitGateway(args []string) error {
	fs := flag.NewFlagSet("exit-gateway", flag.ContinueOnError)
	input := fs.String("input", "lane0", "tunnel input interface")
	output := fs.String("output", "wan0", "native output interface")
	sourceText := fs.String("overlay-source", "", "authorized overlay source prefix")
	source6Text := fs.String("overlay-source6", "", "optional authorized IPv6 overlay source prefix")
	if err := fs.Parse(args); err != nil {
		return err
	}
	source, err := netip.ParsePrefix(*sourceText)
	if err != nil {
		return err
	}
	sources := []netip.Prefix{source}
	if *source6Text != "" {
		source6, parseErr := netip.ParsePrefix(*source6Text)
		if parseErr != nil {
			return parseErr
		}
		sources = append(sources, source6)
	}
	manager, err := exitnode.NewGatewayManager(exitnode.GatewayManagerConfig{InputInterface: *input, OutputInterface: *output})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := manager.Apply(ctx, exitnode.GatewayPlan{Enabled: true, Authorized: true, OverlaySources: sources}); err != nil {
		_ = manager.Close()
		return err
	}
	fmt.Println("ready=exit-gateway")
	<-ctx.Done()
	return manager.Close()
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "netprobe:", message)
	os.Exit(1)
}
