package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLatencyPercentiles(t *testing.T) {
	var stats counters
	for _, latency := range []time.Duration{
		1 * time.Microsecond,
		2 * time.Microsecond,
		4 * time.Microsecond,
		8 * time.Microsecond,
		16 * time.Microsecond,
	} {
		stats.observeLatency(latency)
	}
	if got := stats.percentile(50); got != 4*time.Microsecond {
		t.Fatalf("p50 = %v, want 4us", got)
	}
	if got := stats.percentile(99); got != 16*time.Microsecond {
		t.Fatalf("p99 = %v, want 16us", got)
	}
}

func TestEmptyLatencyPercentile(t *testing.T) {
	var stats counters
	if got := stats.percentile(95); got != 0 {
		t.Fatalf("empty percentile = %v, want zero", got)
	}
}

func TestBenchmarkIPv4Payload(t *testing.T) {
	packet := make([]byte, ipv4HeaderLen+benchmarkMetaLen)
	initializeIPv4(packet)
	metadata, err := benchmarkMetadata(packet)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(metadata, 42)
	if got := binary.BigEndian.Uint64(packet[ipv4HeaderLen:]); got != 42 {
		t.Fatalf("sequence = %d, want 42", got)
	}
	if got := ipv4Checksum(packet[:ipv4HeaderLen]); got != 0 {
		t.Fatalf("checksum over initialized header = %#x, want 0", got)
	}
}

func TestLossPercent(t *testing.T) {
	if got := lossPercent(95, 5); got != 5 {
		t.Fatalf("lossPercent(95, 5) = %v, want 5", got)
	}
	if got := lossPercent(0, 0); got != 0 {
		t.Fatalf("lossPercent(0, 0) = %v, want 0", got)
	}
}

func TestBenchmarkSummaryReportsPPSAndGigabits(t *testing.T) {
	var output bytes.Buffer
	printBenchmarkSummary(&output, quicBenchmarkResult{
		scenario: "relay-quic", transport: "quic-datagram", scope: "authenticated-relay",
		profile: "lan", flows: 1, packetSize: 1200, duration: time.Second,
		received: 100, bytes: 125_000_000,
	})
	for _, field := range []string{"avg_pps=100", "avg_Gbps=1.0000", "avg_MiBps=", "queue_peak_scope=not-applicable"} {
		if !strings.Contains(output.String(), field) {
			t.Fatalf("summary %q omitted %q", output.String(), field)
		}
	}
}

func TestAuthenticatedQUICRelayBenchmark(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runAuthenticatedQUICBenchmark(ctx, quicBenchmarkOptions{
		duration:   150 * time.Millisecond,
		packetSize: 256,
		packetsPS:  1000,
		queue:      512,
		output:     io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.generated == 0 || result.sent == 0 || result.received == 0 {
		t.Fatalf("authenticated relay did not carry traffic: %#v", result)
	}
	if result.sent > result.generated {
		t.Fatalf("sent %d packets after generating only %d", result.sent, result.generated)
	}
	if result.received > result.sent {
		t.Fatalf("received %d packets after sending only %d", result.received, result.sent)
	}
	if result.dropped != result.sent-result.received {
		t.Fatalf("drops = %d, want %d", result.dropped, result.sent-result.received)
	}
	if result.bytes != result.received*256 {
		t.Fatalf("received bytes = %d, want %d", result.bytes, result.received*256)
	}
	if result.bad != 0 {
		t.Fatalf("bad packets = %d, want zero", result.bad)
	}
}

func TestAuthenticatedTCPRelayBenchmark(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runAuthenticatedRelayBenchmark(ctx, quicBenchmarkOptions{
		duration: 75 * time.Millisecond, packetSize: 64, packetsPS: 500,
		queue: 64, flows: 10, profile: "lan", output: io.Discard,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	assertBenchmarkCarriedTraffic(t, result, "relay-tcp", 64)
}

func TestAuthenticatedDirectQUICBenchmark(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runAuthenticatedDirectBenchmark(ctx, quicBenchmarkOptions{
		duration: 75 * time.Millisecond, packetSize: 64, packetsPS: 500,
		flows: 100, profile: "lan", output: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertBenchmarkCarriedTraffic(t, result, "direct-quic", 64)
}

func TestNativeUDPAndAuthenticatedQUICStreamBaselines(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(context.Context, quicBenchmarkOptions) (quicBenchmarkResult, error)
	}{
		{name: "native-udp", run: runNativeUDPBenchmark},
		{name: "quic-stream", run: runAuthenticatedQUICStreamBenchmark},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := test.run(ctx, quicBenchmarkOptions{
				duration: 50 * time.Millisecond, packetSize: 64, packetsPS: 500,
				flows: 10, profile: "lan", output: io.Discard,
			})
			if err != nil {
				t.Fatal(err)
			}
			assertBenchmarkCarriedTraffic(t, result, test.name, 64)
		})
	}
}

func TestDataplaneForwardingBenchmarks(t *testing.T) {
	for _, exit := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result, err := runDataplaneForwardingBenchmark(ctx, quicBenchmarkOptions{
			duration: 50 * time.Millisecond, packetSize: 64, packetsPS: 500,
			queue: 64, flows: 10, profile: "lan", output: io.Discard,
		}, exit)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		want := "subnet-forward"
		if exit {
			want = "exit-forward"
		}
		assertBenchmarkCarriedTraffic(t, result, want, 64)
	}
}

func TestMatrixDimensionsAndAliases(t *testing.T) {
	delay, err := validateMatrixDimensions(100, "wan", -1, 2.5, 3)
	if err != nil || delay != 25*time.Millisecond {
		t.Fatalf("WAN dimensions = %v, %v", delay, err)
	}
	if _, err := validateMatrixDimensions(2, "lan", -1, 0, 0); err == nil {
		t.Fatal("unsupported flow count was accepted")
	}
	sizes, err := parseMatrixIntegers("small,mtu", map[string]int{"small": 64, "mtu": 1200}, func(value int) bool { return value >= 64 }, "sizes")
	if err != nil || len(sizes) != 2 || sizes[0] != 64 || sizes[1] != 1200 {
		t.Fatalf("sizes = %v, %v", sizes, err)
	}
	scenarios, err := parseScenarios("rust-relay-quic,rust-relay-tcp")
	if err != nil || len(scenarios) != 2 {
		t.Fatalf("external relay scenarios = %v, %v", scenarios, err)
	}
}

func TestRustRelayBenchmarkConfigUsesEphemeralIdentityAndStrictKeyMode(t *testing.T) {
	material, err := newBenchmarkIdentityMaterial()
	if err != nil {
		t.Fatal(err)
	}
	path, err := writeRustRelayBenchmarkConfig(t.TempDir(), material, quicBenchmarkOptions{queue: 64}, "127.0.0.1:4433", "127.0.0.1:443", "127.0.0.1:9091", true)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{material.networkID.String(), material.sourceIdentity.NodeID.String(), material.sinkIdentity.NodeID.String(), "[tcp_fallback]"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("generated config omitted %q", expected)
		}
	}
	keyInfo, err := os.Stat(strings.Trim(strings.Split(strings.Split(text, "private_key = ")[1], "\n")[0], "\""))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("relay key mode = %o, want 600", keyInfo.Mode().Perm())
	}
}

func TestParseRustRelayAllocatorMetricsIsStrict(t *testing.T) {
	valid := []byte(`# HELP laneway_relay_allocator_allocations_total Successful allocations.
laneway_relay_allocator_allocations_total 123
laneway_relay_allocator_allocated_bytes_total 4567
laneway_relay_queue_depth 2
laneway_relay_queue_depth_peak 7
`)
	metrics, err := parseRustRelayMetrics(valid)
	if err != nil || metrics.allocations != 123 || metrics.allocatedBytes != 4567 ||
		metrics.queueDepth != 2 || metrics.queueDepthPeak != 7 {
		t.Fatalf("relay metrics = %#v, %v", metrics, err)
	}
	for name, body := range map[string][]byte{
		"missing":   []byte("laneway_relay_allocator_allocations_total 1\n"),
		"duplicate": append(append([]byte(nil), valid...), []byte("laneway_relay_allocator_allocations_total 124\n")...),
		"invalid":   []byte("laneway_relay_allocator_allocations_total nope\nlaneway_relay_allocator_allocated_bytes_total 1\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRustRelayMetrics(body); err == nil {
				t.Fatal("invalid allocator metrics were accepted")
			}
		})
	}
}

func TestMonotonicCounterDeltaRejectsRegression(t *testing.T) {
	if got, err := monotonicCounterDelta("test counter", 40, 42); err != nil || got != 2 {
		t.Fatalf("delta = %d, %v, want 2", got, err)
	}
	if _, err := monotonicCounterDelta("test counter", 42, 40); err == nil {
		t.Fatal("counter regression was accepted")
	}
}

func assertBenchmarkCarriedTraffic(t *testing.T, result quicBenchmarkResult, scenario string, size uint64) {
	t.Helper()
	if result.scenario != scenario || result.generated == 0 || result.sent == 0 || result.received == 0 {
		t.Fatalf("%s did not carry traffic: %#v", scenario, result)
	}
	if result.received > result.sent || result.sent > result.generated {
		t.Fatalf("invalid packet accounting: %#v", result)
	}
	if result.bytes != result.received*size || result.bad != 0 {
		t.Fatalf("invalid byte/bad accounting: %#v", result)
	}
}
