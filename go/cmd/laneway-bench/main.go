// laneway-bench is a TUN-less packet-path benchmark. Its default scenario
// exercises the authenticated production QUIC-datagram relay path. Explicit
// udp-* modes retain the original plain-UDP framing baseline for comparison.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"math/bits"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Doout/laneway/go/internal/protocol"
)

const (
	benchmarkMetaLen = 16
	ipv4HeaderLen    = 20
	maxPacketSize    = 65507 // Maximum portable IPv4 UDP payload.
)

type counters struct {
	packets atomic.Uint64
	bytes   atomic.Uint64
	drops   atomic.Uint64
	bad     atomic.Uint64
	latency [64]atomic.Uint64 // Log2 microsecond buckets; receiver only.
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mode := "quic-relay"
	args := os.Args[1:]
	if len(args) > 0 {
		mode, args = args[0], args[1:]
	}
	var err error
	switch mode {
	case "native-udp":
		err = runNativeUDP(ctx, args)
	case "quic-stream":
		err = runQUICStream(ctx, args)
	case "quic-relay", "quic":
		err = runQUICRelay(ctx, args)
	case "relay-tcp", "tcp-fallback":
		err = runTCPRelay(ctx, args)
	case "rust-relay-quic":
		err = runExternalRustRelay(ctx, args, false)
	case "rust-relay-tcp":
		err = runExternalRustRelay(ctx, args, true)
	case "direct-quic", "direct":
		err = runDirectQUIC(ctx, args)
	case "subnet-forward", "subnet":
		err = runForwarding(ctx, args, false)
	case "exit-forward", "exit":
		err = runForwarding(ctx, args, true)
	case "matrix":
		err = runBenchmarkMatrix(ctx, args)
	case "udp-sender", "sender":
		err = runSender(ctx, args)
	case "udp-receiver", "receiver":
		err = runReceiver(ctx, args)
	case "udp-relay", "relay":
		err = runRelay(ctx, args)
	case "help", "-h", "--help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "laneway-bench:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: laneway-bench <mode> [options]

modes:
  native-udp    run an unauthenticated native loopback UDP baseline
  quic-stream   run a TLS 1.3/mTLS QUIC stream baseline
  quic-relay    run an in-process TLS 1.3/mTLS QUIC relay benchmark (default)
  relay-tcp     run the authenticated TLS/TCP fallback relay path
  rust-relay-quic drive an external Rust relay over authenticated QUIC
  rust-relay-tcp drive an external Rust relay over authenticated TLS/TCP
  direct-quic   run authenticated direct node-to-node QUIC datagrams
  subnet-forward exercise TUN-less subnet routing/policy packet pumps
  exit-forward exercise TUN-less default-route/policy packet pumps (no NAT)
  matrix        run a bounded cross-scenario parameter matrix
  udp-sender    send plain-UDP baseline packets
  udp-receiver  receive and validate plain-UDP baseline packets
  udp-relay     forward plain-UDP baseline packets

Run "laneway-bench <mode> -h" for mode-specific options.`)
}

func runSender(parent context.Context, args []string) error {
	fs := flag.NewFlagSet("sender", flag.ContinueOnError)
	target := fs.String("target", "127.0.0.1:9443", "receiver or relay UDP address")
	duration := fs.Duration("duration", 10*time.Second, "test duration (zero runs until interrupted)")
	size := fs.Int("size", 1200, "total UDP payload size including Laneway header")
	rate := fs.Uint64("pps", 0, "packet rate limit; zero sends as fast as possible")
	route := fs.Uint("route", 1, "32-bit relay route handle")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *size < protocol.PacketHeaderSize+ipv4HeaderLen+benchmarkMetaLen || *size > maxPacketSize {
		return fmt.Errorf("size must be between %d and %d", protocol.PacketHeaderSize+ipv4HeaderLen+benchmarkMetaLen, maxPacketSize)
	}
	if uint64(*route) > uint64(^uint32(0)) {
		return fmt.Errorf("route handle exceeds 32 bits")
	}

	remote, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		return fmt.Errorf("resolve target: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return fmt.Errorf("dial target: %w", err)
	}
	defer conn.Close()

	ctx := parent
	var cancel context.CancelFunc
	if *duration > 0 {
		ctx, cancel = context.WithTimeout(parent, *duration)
		defer cancel()
	}

	buf := make([]byte, *size)
	if err := protocol.EncodePacketHeader(buf, protocol.PacketHeader{
		Version:     protocol.PacketVersion1,
		RouteHandle: uint32(*route),
	}); err != nil {
		return fmt.Errorf("encode packet header: %w", err)
	}
	initializeIPv4(buf[protocol.PacketHeaderSize:])
	metadata := buf[protocol.PacketHeaderSize+ipv4HeaderLen:]
	stats := &counters{}
	defer startReporter("udp-sender", stats)()

	var ticker *time.Ticker
	if *rate > 0 {
		interval := time.Second / time.Duration(*rate)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	var sequence uint64
	for ctx.Err() == nil {
		if ticker != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
		}
		binary.BigEndian.PutUint64(metadata, sequence)
		binary.BigEndian.PutUint64(metadata[8:], uint64(time.Now().UnixNano()))
		n, writeErr := conn.Write(buf)
		if writeErr != nil {
			if ctx.Err() != nil {
				break
			}
			return fmt.Errorf("send packet: %w", writeErr)
		}
		stats.packets.Add(1)
		stats.bytes.Add(uint64(n))
		sequence++
	}
	return nil
}

func runReceiver(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("receiver", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:9443", "UDP listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := listenUDP(*listen)
	if err != nil {
		return err
	}
	defer conn.Close()
	go closeOnDone(ctx, conn)

	stats := &counters{}
	defer startReporter("udp-receiver", stats)()
	buf := make([]byte, maxPacketSize)
	var next uint64
	var initialized bool
	for {
		n, _, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			if ctx.Err() != nil {
				break
			}
			return fmt.Errorf("receive packet: %w", readErr)
		}
		_, payload, decodeErr := protocol.DecodePacket(buf[:n])
		metadata, metadataErr := benchmarkMetadata(payload)
		if decodeErr != nil || metadataErr != nil {
			stats.bad.Add(1)
			continue
		}
		sequence := binary.BigEndian.Uint64(metadata)
		sentAt := int64(binary.BigEndian.Uint64(metadata[8:]))
		if latency := time.Since(time.Unix(0, sentAt)); latency >= 0 {
			stats.observeLatency(latency)
		}
		if initialized && sequence > next {
			stats.drops.Add(sequence - next)
		}
		if !initialized || sequence >= next {
			next = sequence + 1
			initialized = true
		}
		stats.packets.Add(1)
		stats.bytes.Add(uint64(n))
	}
	return nil
}

func runRelay(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:9443", "UDP listen address")
	target := fs.String("target", "127.0.0.1:9444", "receiver UDP address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	in, err := listenUDP(*listen)
	if err != nil {
		return err
	}
	defer in.Close()
	remote, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		return fmt.Errorf("resolve target: %w", err)
	}
	out, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return fmt.Errorf("dial target: %w", err)
	}
	defer out.Close()
	go closeOnDone(ctx, in)

	stats := &counters{}
	defer startReporter("udp-relay", stats)()
	buf := make([]byte, maxPacketSize)
	for {
		n, _, readErr := in.ReadFromUDP(buf)
		if readErr != nil {
			if ctx.Err() != nil {
				break
			}
			return fmt.Errorf("receive packet: %w", readErr)
		}
		if _, _, decodeErr := protocol.DecodePacket(buf[:n]); decodeErr != nil {
			stats.bad.Add(1)
			continue
		}
		written, writeErr := out.Write(buf[:n])
		if writeErr != nil {
			return fmt.Errorf("relay packet: %w", writeErr)
		}
		stats.packets.Add(1)
		stats.bytes.Add(uint64(written))
	}
	return nil
}

func listenUDP(address string) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve listen address: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", address, err)
	}
	fmt.Println("listening on", conn.LocalAddr())
	return conn, nil
}

func closeOnDone(ctx context.Context, conn *net.UDPConn) {
	<-ctx.Done()
	_ = conn.Close()
}

func report(ctx context.Context, verb string, stats *counters, done chan<- struct{}) {
	defer close(done)
	started := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var previousPackets, previousBytes uint64
	for {
		select {
		case <-ticker.C:
			packets := stats.packets.Load()
			bytes := stats.bytes.Load()
			fmt.Printf("%s pps=%s throughput_Gbps=%.4f throughput_MiBps=%s total=%s drops=%s bad=%s\n",
				verb,
				formatUint(packets-previousPackets),
				float64(bytes-previousBytes)*8/1_000_000_000,
				strconv.FormatFloat(float64(bytes-previousBytes)/(1024*1024), 'f', 2, 64),
				formatUint(packets),
				formatUint(stats.drops.Load()),
				formatUint(stats.bad.Load()),
			)
			previousPackets, previousBytes = packets, bytes
		case <-ctx.Done():
			elapsed := time.Since(started).Seconds()
			packets := stats.packets.Load()
			bytes := stats.bytes.Load()
			var memory runtime.MemStats
			runtime.ReadMemStats(&memory)
			fmt.Printf("summary mode=%s duration=%s packets=%s bytes=%s avg_pps=%.0f avg_Gbps=%.4f avg_MiBps=%.2f drops=%s loss_pct=%.4f bad=%s latency_p50=%s latency_p95=%s latency_p99=%s allocs=%s heap_bytes=%s\n",
				verb, time.Since(started).Round(time.Millisecond), formatUint(packets), formatUint(bytes),
				float64(packets)/elapsed, float64(bytes)*8/1_000_000_000/elapsed, float64(bytes)/(1024*1024)/elapsed,
				formatUint(stats.drops.Load()), lossPercent(packets, stats.drops.Load()), formatUint(stats.bad.Load()),
				stats.percentile(50), stats.percentile(95), stats.percentile(99),
				formatUint(memory.Mallocs), formatUint(memory.HeapAlloc))
			return
		}
	}
}

func lossPercent(received, dropped uint64) float64 {
	total := received + dropped
	if total == 0 {
		return 0
	}
	return 100 * float64(dropped) / float64(total)
}

func startReporter(verb string, stats *counters) func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go report(ctx, verb, stats, done)
	return func() {
		cancel()
		<-done
	}
}

func formatUint(value uint64) string {
	return strconv.FormatUint(value, 10)
}

func initializeIPv4(packet []byte) {
	packet[0] = 0x45 // IPv4, 20-byte header.
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64  // TTL
	packet[9] = 253 // RFC 3692 experimentation and testing.
	copy(packet[12:16], []byte{100, 96, 0, 1})
	copy(packet[16:20], []byte{100, 96, 0, 2})
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:ipv4HeaderLen]))
}

func benchmarkMetadata(packet []byte) ([]byte, error) {
	if len(packet) < ipv4HeaderLen || packet[0]>>4 != 4 {
		return nil, errors.New("benchmark payload is not IPv4")
	}
	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < ipv4HeaderLen || len(packet) < headerLen+benchmarkMetaLen {
		return nil, errors.New("benchmark payload has no metadata")
	}
	return packet[headerLen : headerLen+benchmarkMetaLen], nil
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (c *counters) observeLatency(latency time.Duration) {
	micros := uint64(latency.Microseconds())
	bucket := bits.Len64(micros)
	if bucket >= len(c.latency) {
		bucket = len(c.latency) - 1
	}
	c.latency[bucket].Add(1)
}

func (c *counters) percentile(percent uint64) time.Duration {
	var total uint64
	for i := range c.latency {
		total += c.latency[i].Load()
	}
	if total == 0 {
		return 0
	}
	want := (total*percent + 99) / 100
	var seen uint64
	for i := range c.latency {
		seen += c.latency[i].Load()
		if seen >= want {
			if i == 0 {
				return 0
			}
			return time.Duration(uint64(1)<<(i-1)) * time.Microsecond
		}
	}
	return 0
}
