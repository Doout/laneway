package main

import (
	"fmt"
	"io"
	"runtime"
	"time"
)

type benchmarkMeasurement struct {
	started time.Time
	cpu     time.Duration
	memory  runtime.MemStats
}

type benchmarkResources struct {
	cpuPercent float64
	rssBytes   uint64
	allocs     uint64
	gcCount    uint32
	gcPause    time.Duration
}

func beginBenchmarkMeasurement() benchmarkMeasurement {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return benchmarkMeasurement{started: time.Now(), cpu: processCPUTime(), memory: memory}
}

func (m benchmarkMeasurement) finish() benchmarkResources {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	elapsed := time.Since(m.started)
	cpu := processCPUTime() - m.cpu
	percent := 0.0
	if elapsed > 0 && cpu > 0 {
		percent = float64(cpu) / float64(elapsed) * 100
	}
	return benchmarkResources{
		cpuPercent: percent,
		rssBytes:   processRSSBytes(),
		allocs:     memory.Mallocs - m.memory.Mallocs,
		gcCount:    memory.NumGC - m.memory.NumGC,
		gcPause:    time.Duration(memory.PauseTotalNs - m.memory.PauseTotalNs),
	}
}

func printBenchmarkSummary(output io.Writer, result quicBenchmarkResult) {
	elapsed := result.duration.Seconds()
	if elapsed <= 0 {
		elapsed = time.Nanosecond.Seconds()
	}
	queuePeakScope := result.queuePeakScope
	if queuePeakScope == "" {
		queuePeakScope = "not-applicable"
	}
	fmt.Fprintf(output, "summary scenario=%s transport=%s scope=%s profile=%s flows=%d size=%d duration=%s generated=%s sent=%s packets=%s bytes=%s avg_pps=%.0f avg_Gbps=%.4f avg_MiBps=%.2f drops=%s loss_pct=%.4f bad=%s latency_p50=%s latency_p95=%s latency_p99=%s cpu_pct=%.2f rss_bytes=%s allocs=%s gc_count=%d gc_pause=%s relay_cpu_pct=%.2f relay_rss_bytes=%s relay_allocs=%s relay_allocated_bytes=%s queue_capacity=%d queue_depth=%d queue_peak=%d queue_peak_scope=%s\n",
		result.scenario, result.transport, result.scope, result.profile, result.flows, result.packetSize,
		result.duration.Round(time.Millisecond), formatUint(result.generated), formatUint(result.sent),
		formatUint(result.received), formatUint(result.bytes), float64(result.received)/elapsed,
		float64(result.bytes)*8/1_000_000_000/elapsed, float64(result.bytes)/(1024*1024)/elapsed, formatUint(result.dropped),
		lossPercent(result.received, result.dropped), formatUint(result.bad), result.p50,
		result.p95, result.p99, result.resources.cpuPercent, formatUint(result.resources.rssBytes),
		formatUint(result.resources.allocs), result.resources.gcCount, result.resources.gcPause,
		result.relayCPU, formatUint(result.relayRSS), formatUint(result.relayAllocs), formatUint(result.relayAllocBytes),
		result.queueCapacity, result.queueDepth, result.queuePeak, queuePeakScope)
}
