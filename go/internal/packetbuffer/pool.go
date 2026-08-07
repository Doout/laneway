// Package packetbuffer provides fixed-capacity, explicitly released packet
// buffers for hot paths whose ownership crosses function or goroutine bounds.
package packetbuffer

import (
	"sync"
	"sync/atomic"
)

// Pool reuses buffers of one bounded capacity. A garbage collection may drop
// cached buffers; the pool never retains a buffer larger than Capacity.
type Pool struct {
	capacity int
	pool     sync.Pool
	created  atomic.Uint64
}

func NewPool(capacity int) *Pool {
	if capacity <= 0 {
		panic("packetbuffer: capacity must be positive")
	}
	p := &Pool{capacity: capacity}
	p.pool.New = func() any {
		p.created.Add(1)
		return &Buffer{bytes: make([]byte, 0, capacity), owner: p}
	}
	return p
}

func (p *Pool) Capacity() int { return p.capacity }

// Created reports the number of backing buffers ever allocated. It is useful
// for proving that a warmed hot path is recycling bounded storage.
func (p *Pool) Created() uint64 {
	if p == nil {
		return 0
	}
	return p.created.Load()
}

// Acquire returns a buffer of length size. Call Release exactly once after the
// final synchronous consumer or queued owner is finished with Bytes.
func (p *Pool) Acquire(size int) *Buffer {
	if p == nil || size < 0 || size > p.capacity {
		panic("packetbuffer: requested size exceeds pool capacity")
	}
	buffer := p.pool.Get().(*Buffer)
	buffer.released.Store(false)
	buffer.bytes = buffer.bytes[:size]
	return buffer
}

type Buffer struct {
	bytes    []byte
	owner    *Pool
	released atomic.Bool
}

func (b *Buffer) Bytes() []byte {
	if b == nil || b.released.Load() {
		return nil
	}
	return b.bytes
}

// Release clears the used bytes before reuse. It is idempotent so error and
// shutdown paths can safely converge without returning one buffer twice.
func (b *Buffer) Release() {
	if b == nil || b.owner == nil || b.released.Swap(true) {
		return
	}
	clear(b.bytes)
	b.bytes = b.bytes[:0]
	b.owner.pool.Put(b)
}
