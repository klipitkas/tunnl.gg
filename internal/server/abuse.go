package server

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"tunnl.gg/internal/config"
)

// BlockCallback is called when an IP is blocked
type BlockCallback func(ip string)

// AbuseTracker tracks connection patterns and blocks abusive IPs
type AbuseTracker struct {
	mu sync.RWMutex

	// Connection timestamps per IP for rate limiting
	connectionTimes map[string][]time.Time

	// Blocked IPs with expiration time
	blockedIPs map[string]time.Time

	// Rate limit violation counts per IP
	violationCounts map[string]int

	// Callback when IP is blocked
	onBlock BlockCallback

	// Stats (use atomic operations for thread safety)
	totalBlocked     atomic.Uint64
	totalRateLimited atomic.Uint64

	// Lifecycle management for cleanup goroutine
	stopCleanup chan struct{}
	cleanupDone chan struct{}
}

// NewAbuseTracker creates a new abuse tracker
func NewAbuseTracker() *AbuseTracker {
	at := &AbuseTracker{
		connectionTimes: make(map[string][]time.Time),
		blockedIPs:      make(map[string]time.Time),
		violationCounts: make(map[string]int),
		stopCleanup:     make(chan struct{}),
		cleanupDone:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go at.cleanup()

	return at
}

// Stop gracefully stops the cleanup goroutine
func (at *AbuseTracker) Stop() {
	close(at.stopCleanup)
	<-at.cleanupDone
}

// SetOnBlockCallback sets the callback to be called when an IP is blocked
func (at *AbuseTracker) SetOnBlockCallback(cb BlockCallback) {
	at.mu.Lock()
	defer at.mu.Unlock()
	at.onBlock = cb
}

// callOnBlock calls the onBlock callback if set (must be called without lock held)
func (at *AbuseTracker) callOnBlock(ip string) {
	at.mu.RLock()
	cb := at.onBlock
	at.mu.RUnlock()

	if cb != nil {
		// Call callback without holding lock to avoid deadlock
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Panic in onBlock callback for IP %s: %v", ip, r)
				}
			}()
			cb(ip)
		}()
	}
}

// GetBlockExpiry returns the expiry time for a blocked IP, or zero time if not blocked
func (at *AbuseTracker) GetBlockExpiry(ip string) time.Time {
	at.mu.RLock()
	defer at.mu.RUnlock()

	expiry, blocked := at.blockedIPs[ip]
	if !blocked || time.Now().After(expiry) {
		return time.Time{}
	}
	return expiry
}

// BlockIP blocks an IP for the configured duration
func (at *AbuseTracker) BlockIP(ip string) {
	at.mu.Lock()
	at.blockedIPs[ip] = time.Now().Add(config.BlockDuration)
	at.mu.Unlock()

	at.totalBlocked.Add(1)
	at.callOnBlock(ip)
}

// CheckConnectionRate checks if a new connection from IP should be allowed
// Returns true if allowed, false if rate limited
// Auto-blocks IP after repeated violations
func (at *AbuseTracker) CheckConnectionRate(ip string) bool {
	at.mu.Lock()

	now := time.Now()
	windowStart := now.Add(-config.ConnectionRateWindow)

	// Get existing timestamps and filter to current window
	times := at.connectionTimes[ip]
	validTimes := make([]time.Time, 0, len(times))
	for _, t := range times {
		if t.After(windowStart) {
			validTimes = append(validTimes, t)
		}
	}

	// Check if over limit
	if len(validTimes) >= config.MaxConnectionsPerMinute {
		at.violationCounts[ip]++

		// Auto-block after too many violations
		blocked := false
		if at.violationCounts[ip] >= config.RateLimitViolationsMax {
			at.blockedIPs[ip] = now.Add(config.BlockDuration)
			delete(at.violationCounts, ip)
			blocked = true
		}

		at.mu.Unlock()

		at.totalRateLimited.Add(1)
		if blocked {
			at.totalBlocked.Add(1)
			at.callOnBlock(ip)
		}
		return false
	}

	// Record this connection
	validTimes = append(validTimes, now)
	at.connectionTimes[ip] = validTimes

	at.mu.Unlock()
	return true
}


// GetStats returns abuse tracking statistics
func (at *AbuseTracker) GetStats() (blockedIPs int, totalBlocked uint64, totalRateLimited uint64) {
	at.mu.RLock()
	defer at.mu.RUnlock()

	// Count currently active blocks
	now := time.Now()
	activeBlocks := 0
	for _, expiry := range at.blockedIPs {
		if expiry.After(now) {
			activeBlocks++
		}
	}

	return activeBlocks, at.totalBlocked.Load(), at.totalRateLimited.Load()
}

// cleanup periodically removes expired entries
func (at *AbuseTracker) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	defer close(at.cleanupDone)

	for {
		select {
		case <-at.stopCleanup:
			return
		case <-ticker.C:
			at.mu.Lock()

			now := time.Now()
			windowStart := now.Add(-config.ConnectionRateWindow)
			// Use 2x window for stale data cleanup
			staleThreshold := now.Add(-2 * config.ConnectionRateWindow)

			// Clean up connection times
			for ip, times := range at.connectionTimes {
				validTimes := make([]time.Time, 0, len(times))
				for _, t := range times {
					if t.After(windowStart) {
						validTimes = append(validTimes, t)
					}
				}
				if len(validTimes) == 0 {
					delete(at.connectionTimes, ip)
				} else {
					// Also clean up if most recent connection is too old
					mostRecent := validTimes[len(validTimes)-1]
					if mostRecent.Before(staleThreshold) {
						delete(at.connectionTimes, ip)
					} else {
						at.connectionTimes[ip] = validTimes
					}
				}
			}

			// Clean up expired blocks
			for ip, expiry := range at.blockedIPs {
				if expiry.Before(now) {
					delete(at.blockedIPs, ip)
				}
			}

			// Clean up stale violation counts (IPs that haven't had recent activity and aren't blocked)
			for ip := range at.violationCounts {
				_, hasActivity := at.connectionTimes[ip]
				_, isBlocked := at.blockedIPs[ip]
				if !hasActivity && !isBlocked {
					delete(at.violationCounts, ip)
				}
			}

			at.mu.Unlock()
		}
	}
}
