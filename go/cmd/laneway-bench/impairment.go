package main

import (
	"context"
	"errors"
	"math/rand"
	"time"
)

type benchmarkImpairment struct {
	delay     time.Duration
	loss      float64
	burstLoss int
	offered   uint64
	burstLeft int
	random    *rand.Rand
	stats     *counters
}

func newBenchmarkImpairment(delay time.Duration, loss float64, burst int, seed int64, stats *counters) *benchmarkImpairment {
	return &benchmarkImpairment{delay: delay, loss: loss / 100, burstLoss: burst, random: rand.New(rand.NewSource(seed)), stats: stats}
}

func (i *benchmarkImpairment) drop() bool {
	i.offered++
	drop := false
	if i.burstLeft > 0 {
		i.burstLeft--
		drop = true
	} else if i.burstLoss > 0 && i.offered%100 == 0 {
		i.burstLeft = i.burstLoss - 1
		drop = true
	} else if i.loss > 0 && i.random.Float64() < i.loss {
		drop = true
	}
	if drop && i.stats != nil {
		i.stats.drops.Add(1)
	}
	return drop
}

func (i *benchmarkImpairment) wait(ctx context.Context) error {
	if i == nil || i.delay <= 0 {
		return nil
	}
	timer := time.NewTimer(i.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func validFlowCount(flows int) bool { return flows == 1 || flows == 10 || flows == 100 }

func validateMatrixDimensions(flows int, profile string, delay time.Duration, loss float64, burst int) (time.Duration, error) {
	if !validFlowCount(flows) {
		return 0, errors.New("flows must be 1, 10, or 100")
	}
	if profile != "lan" && profile != "wan" {
		return 0, errors.New("profile must be lan or wan")
	}
	if delay < -1 || loss < 0 || loss > 100 || burst < 0 || burst > 100 {
		return 0, errors.New("delay must be non-negative, loss in [0,100], and burst-loss in [0,100]")
	}
	if delay >= 0 {
		return delay, nil
	}
	if profile == "wan" {
		return 25 * time.Millisecond, nil
	}
	return 0, nil
}
