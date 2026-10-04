package tunnel

import (
	"sync"
	"time"
)

// bucket is an unsynchronized token bucket. Callers must provide locking.
type bucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

func newBucket(rate float64, burst int, now time.Time) *bucket {
	return &bucket{
		tokens:     float64(burst),
		maxTokens:  float64(burst),
		refillRate: rate,
		lastRefill: now,
	}
}

func (b *bucket) allow(now time.Time) bool {
	b.tokens += now.Sub(b.lastRefill).Seconds() * b.refillRate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	b.lastRefill = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// full reports whether the bucket would be fully refilled at now. A full bucket
// behaves exactly like a new one, so it can be discarded without changing behavior.
func (b *bucket) full(now time.Time) bool {
	return b.tokens+now.Sub(b.lastRefill).Seconds()*b.refillRate >= b.maxTokens
}

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	mu sync.Mutex
	b  *bucket
}

// NewRateLimiter creates a new rate limiter with the given rate and burst size
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{b: newBucket(rate, burst, time.Now())}
}

// Allow returns true if a request is allowed, false if rate limited
func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.b.allow(time.Now())
}

// KeyedRateLimiter keeps an independent token bucket per key (e.g. visitor IP).
// Memory is bounded by maxKeys: when full, buckets that have completely refilled
// are pruned, and any new keys beyond the limit share a single overflow bucket.
type KeyedRateLimiter struct {
	mu        sync.Mutex
	rate      float64
	burst     int
	maxKeys   int
	buckets   map[string]*bucket
	overflow  *bucket
	lastPrune time.Time
}

// minPruneInterval bounds how often a full map is scanned, so a flood of new
// keys cannot turn every request into an O(maxKeys) scan.
const minPruneInterval = time.Second

// NewKeyedRateLimiter creates a per-key rate limiter tracking at most maxKeys keys.
func NewKeyedRateLimiter(rate float64, burst int, maxKeys int) *KeyedRateLimiter {
	return &KeyedRateLimiter{
		rate:     rate,
		burst:    burst,
		maxKeys:  maxKeys,
		buckets:  make(map[string]*bucket),
		overflow: newBucket(rate, burst, time.Now()),
	}
}

// Allow returns true if a request for key is allowed, false if rate limited
func (k *KeyedRateLimiter) Allow(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()

	now := time.Now()
	b, ok := k.buckets[key]
	if !ok {
		if len(k.buckets) >= k.maxKeys && now.Sub(k.lastPrune) >= minPruneInterval {
			k.prune(now)
		}
		if len(k.buckets) >= k.maxKeys {
			return k.overflow.allow(now)
		}
		b = newBucket(k.rate, k.burst, now)
		k.buckets[key] = b
	}
	return b.allow(now)
}

// Available reports whether Allow would allow key now, without using a token.
func (k *KeyedRateLimiter) Available(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()

	b, ok := k.buckets[key]
	if !ok {
		if len(k.buckets) < k.maxKeys {
			return true // a new key starts with a full bucket
		}
		b = k.overflow
	}
	return b.tokens+time.Since(b.lastRefill).Seconds()*b.refillRate >= 1
}

// prune removes buckets that have fully refilled. Must be called with k.mu held.
func (k *KeyedRateLimiter) prune(now time.Time) {
	k.lastPrune = now
	for key, b := range k.buckets {
		if b.full(now) {
			delete(k.buckets, key)
		}
	}
}
