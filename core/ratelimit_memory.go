package core

import (
	"context"
	"math"
	"sync"
	"time"
)

// tokenBucket is one key's bucket. capacity and refill are recorded so the sweeper
// can evict buckets that have (or would have) refilled to full without re-deriving
// them from a Rule.
type tokenBucket struct {
	tokens   float64
	capacity float64
	refill   float64 // tokens per second
	last     time.Time
}

// memoryRateLimiter is an in-process token-bucket RateLimiter. It is the default
// backend: correct and dependency-free for a single instance, but its counters are
// per-process (so N replicas allow N times the limit) and reset on restart.
//
// Idle buckets are swept opportunistically (no background goroutine): a bucket that
// has refilled to full carries no state, so dropping it bounds memory without changing
// behaviour.
type memoryRateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*tokenBucket
	now        func() time.Time // injectable for tests
	sweepEvery time.Duration
	nextSweep  time.Time
}

func newMemoryRateLimiter() *memoryRateLimiter {
	return &memoryRateLimiter{
		buckets:    make(map[string]*tokenBucket),
		now:        time.Now,
		sweepEvery: 10 * time.Minute,
	}
}

func (m *memoryRateLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	if limit <= 0 || window <= 0 {
		return true, 0, nil
	}
	capacity := float64(limit)
	refill := capacity / window.Seconds()

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	m.sweepLocked(now)

	b, ok := m.buckets[key]
	if !ok {
		b = &tokenBucket{tokens: capacity, capacity: capacity, refill: refill, last: now}
		m.buckets[key] = b
	} else {
		if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
			b.tokens = math.Min(capacity, b.tokens+elapsed*refill)
		}
		b.capacity = capacity
		b.refill = refill
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0, nil
	}
	retryAfter := time.Duration((1 - b.tokens) / refill * float64(time.Second))
	return false, retryAfter, nil
}

func (m *memoryRateLimiter) Reset(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.buckets, key)
	return nil
}

// sweepLocked drops buckets that have refilled to full since they were last touched.
// Runs at most once per sweepEvery. Callers must hold m.mu.
func (m *memoryRateLimiter) sweepLocked(now time.Time) {
	if now.Before(m.nextSweep) {
		return
	}
	m.nextSweep = now.Add(m.sweepEvery)
	for k, b := range m.buckets {
		if b.refill <= 0 {
			delete(m.buckets, k)
			continue
		}
		if b.tokens+now.Sub(b.last).Seconds()*b.refill >= b.capacity {
			delete(m.buckets, k)
		}
	}
}
