package tunnel

import (
	"testing"
	"time"
)

func TestRateLimiter_LimitAfterBurst(t *testing.T) {
	rl := NewRateLimiter(10, 5) // 10 tokens/sec, burst of 5

	for i := 0; i < 5; i++ {
		if !rl.Allow() {
			t.Fatalf("Allow() returned false on burst request %d", i+1)
		}
	}

	// Next request should be denied
	if rl.Allow() {
		t.Error("Allow() should return false after burst exhausted")
	}
}

func TestRateLimiter_TokenRefill(t *testing.T) {
	rl := NewRateLimiter(10, 5) // 10 tokens/sec, burst of 5

	// Exhaust burst
	for i := 0; i < 5; i++ {
		rl.Allow()
	}

	// Wait for tokens to refill (at 10/sec, 150ms should give ~1.5 tokens)
	time.Sleep(150 * time.Millisecond)

	if !rl.Allow() {
		t.Error("Allow() should return true after token refill")
	}
}

func TestKeyedRateLimiter_IndependentKeys(t *testing.T) {
	k := NewKeyedRateLimiter(10, 2, 100)

	k.Allow("a")
	k.Allow("a")
	if k.Allow("a") {
		t.Error("Allow(a) should return false after burst exhausted")
	}
	if !k.Allow("b") {
		t.Error("exhausting key a should not affect key b")
	}
}

func TestKeyedRateLimiter_PrunesRefilledBuckets(t *testing.T) {
	k := NewKeyedRateLimiter(10, 2, 2)

	k.Allow("a")
	k.Allow("b")

	// Pretend "a" has been idle long enough to refill completely
	k.buckets["a"].lastRefill = time.Now().Add(-time.Minute)

	if !k.Allow("c") {
		t.Error("Allow(c) should be allowed after pruning")
	}
	if _, ok := k.buckets["a"]; ok {
		t.Error("fully refilled bucket a should have been pruned")
	}
	if _, ok := k.buckets["c"]; !ok {
		t.Error("key c should be tracked after pruning made room")
	}
}

func TestKeyedRateLimiter_OverflowWhenFull(t *testing.T) {
	k := NewKeyedRateLimiter(10, 2, 2)

	// Fill the map with buckets that are still being limited
	for _, key := range []string{"a", "b"} {
		k.Allow(key)
		k.Allow(key)
	}

	// New keys beyond the cap share the overflow bucket and are not tracked
	if !k.Allow("c") || !k.Allow("d") {
		t.Error("overflow bucket should allow requests up to its burst")
	}
	if k.Allow("e") {
		t.Error("overflow keys should share one bucket")
	}
	if len(k.buckets) != 2 {
		t.Errorf("tracked keys = %d, want 2 (cap)", len(k.buckets))
	}
}
