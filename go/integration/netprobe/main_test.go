package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestTCPProbeFrameRoundTripWithShortWrites(t *testing.T) {
	payload := []byte("ssh-class-stream")
	var storage bytes.Buffer
	writer := &shortWriter{writer: &storage, maximum: 3}
	if err := writeTCPProbe(writer, payload); err != nil {
		t.Fatalf("writeTCPProbe: %v", err)
	}
	got, err := readTCPProbe(&storage)
	if err != nil {
		t.Fatalf("readTCPProbe: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestTCPProbeFrameRejectsInvalidAndTruncatedLengths(t *testing.T) {
	for _, length := range []uint16{0, maxTCPProbePayload + 1} {
		var frame [2]byte
		binary.BigEndian.PutUint16(frame[:], length)
		if _, err := readTCPProbe(bytes.NewReader(frame[:])); err == nil {
			t.Fatalf("length %d was accepted", length)
		}
	}
	frame := []byte{0, 4, 1, 2}
	if _, err := readTCPProbe(bytes.NewReader(frame)); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

func TestPercentileNanosecondsUsesNearestRank(t *testing.T) {
	values := []int64{10, 20, 30, 40, 50}
	if got := percentileNanoseconds(values, 50); got != 30 {
		t.Fatalf("p50 = %d, want 30", got)
	}
	if got := percentileNanoseconds(values, 95); got != 50 {
		t.Fatalf("p95 = %d, want 50", got)
	}
	if got := percentileNanoseconds(nil, 99); got != 0 {
		t.Fatalf("empty percentile = %d, want zero", got)
	}
}

func TestUDPBenchmarkReportInvariants(t *testing.T) {
	valid := udpBenchReport{
		Schema: "laneway-kernel-datapath-benchmark-v1", Flows: 1, PacketSize: 64,
		DurationMS: 100, ResourceDurationMS: 350, ResourceScope: "process-rusage+procfs-rss+go-runtime",
		Generated: 100, Sent: 98, SendErrors: 2, Received: 95, Drops: 3,
		Bytes: 95 * 64, LossPercent: 100 * 3.0 / 98, PPS: 950, Gbps: 0.0004,
		P50US: 10, P95US: 20, P99US: 30, LatencySamples: 95,
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
	for name, mutate := range map[string]func(*udpBenchReport){
		"send accounting": func(report *udpBenchReport) { report.SendErrors++ },
		"drop accounting": func(report *udpBenchReport) { report.Drops++ },
		"byte accounting": func(report *udpBenchReport) { report.Bytes++ },
		"resource window": func(report *udpBenchReport) { report.ResourceDurationMS = 99 },
		"resource scope":  func(report *udpBenchReport) { report.ResourceScope = "" },
		"latency order":   func(report *udpBenchReport) { report.P95US = 9 },
		"sample bound":    func(report *udpBenchReport) { report.LatencySamples = 96 },
	} {
		t.Run(name, func(t *testing.T) {
			report := valid
			mutate(&report)
			if err := report.validate(); err == nil {
				t.Fatal("invalid report was accepted")
			}
		})
	}
}

func TestUDPBenchmarkLabelsAreBoundedMachineTokens(t *testing.T) {
	for _, valid := range []string{"kernel-path", "production_kernel.v1", "a"} {
		if !validBenchmarkLabel(valid) {
			t.Fatalf("valid label %q rejected", valid)
		}
	}
	for _, invalid := range []string{"", "has spaces", "UPPER", string(make([]byte, 129))} {
		if validBenchmarkLabel(invalid) {
			t.Fatalf("invalid label %q accepted", invalid)
		}
	}
}

func TestUDPBenchmarkRejectsWindowWithoutOneTickerEvent(t *testing.T) {
	err := udpBenchClient([]string{"-duration", "100ms", "-pps", "10"})
	if err == nil || err.Error() != "UDP benchmark duration must exceed one packet interval" {
		t.Fatalf("error = %v", err)
	}
}

type shortWriter struct {
	writer  io.Writer
	maximum int
}

func (w *shortWriter) Write(payload []byte) (int, error) {
	if len(payload) > w.maximum {
		payload = payload[:w.maximum]
	}
	return w.writer.Write(payload)
}
