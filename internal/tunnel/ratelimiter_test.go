package tunnel

import (
	"testing"
	"time"
)

func TestRateLimiter_BurstCapacity(t *testing.T) {
	rl := NewRateLimiter(10, 5) // 10 tokens/sec, burst of 5

	for i := 0; i < 5; i++ {
		if !rl.Allow() {
			t.Fatalf("Allow() returned false on burst request %d", i+1)
		}
	}
}

func TestRateLimiter_LimitAfterBurst(t *testing.T) {
	rl := NewRateLimiter(10, 5) // 10 tokens/sec, burst of 5

	// Exhaust burst
	for i := 0; i < 5; i++ {
		rl.Allow()
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
