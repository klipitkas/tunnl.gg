package server

import "sync"

// connLimiter caps the number of concurrent connections per key. Keys are
// removed when their count drops to zero, so memory is bounded by the number
// of open connections.
type connLimiter struct {
	mu     sync.Mutex
	max    int
	counts map[string]int
}

func newConnLimiter(max int) *connLimiter {
	return &connLimiter{max: max, counts: make(map[string]int)}
}

// acquire reserves a connection slot for key, returning false if key is at the limit.
func (c *connLimiter) acquire(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts[key] >= c.max {
		return false
	}
	c.counts[key]++
	return true
}

// release frees a slot reserved by a successful acquire.
func (c *connLimiter) release(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts[key] <= 1 {
		delete(c.counts, key)
		return
	}
	c.counts[key]--
}

// total returns the number of connections currently held across all keys.
func (c *connLimiter) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, count := range c.counts {
		n += count
	}
	return n
}
