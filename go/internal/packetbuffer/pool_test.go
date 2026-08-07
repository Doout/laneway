package packetbuffer

import "testing"

func TestPoolReusesAndClearsBoundedBuffer(t *testing.T) {
	pool := NewPool(1205)
	first := pool.Acquire(1205)
	first.Bytes()[0] = 99
	first.Release()
	first.Release()
	second := pool.Acquire(1205)
	if second.Bytes()[0] != 0 || cap(second.Bytes()) != 1205 {
		t.Fatalf("reused buffer was not cleared or bounded: first=%d cap=%d", second.Bytes()[0], cap(second.Bytes()))
	}
	second.Release()
}

func TestPoolWarmAcquireReleaseDoesNotAllocate(t *testing.T) {
	pool := NewPool(1205)
	pool.Acquire(1205).Release()
	if allocations := testing.AllocsPerRun(1000, func() {
		buffer := pool.Acquire(1205)
		buffer.Bytes()[0] = 1
		buffer.Release()
	}); allocations != 0 {
		t.Fatalf("warm acquire/release allocations = %v, want zero", allocations)
	}
}
