package server

import (
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/klipitkas/tunnl.gg/pkg/config"
)

func TestConnectionHistoryPruneMatchesOriginalFilter(t *testing.T) {
	cutoff := time.Unix(1000, 0)
	for trial := range 1000 {
		times := make([]time.Time, trial%(config.MaxConnectionsPerMinute+1))
		var want []time.Time
		for i := range times {
			// Unsorted and duplicate entries, including the exact cutoff and
			// nanoseconds on both sides. Preserve the original strict After rule.
			times[i] = cutoff.Add(time.Duration((trial*17+i*23)%7 - 3))
			if times[i].After(cutoff) {
				want = append(want, times[i])
			}
		}
		got := recentConnectionTimes(times, cutoff)
		if !slices.Equal(got, want) {
			t.Fatalf("trial %d: got %v, want %v", trial, got, want)
		}
		for _, expired := range times[len(got):] {
			if !expired.IsZero() {
				t.Fatal("unused history tail retains expired entries")
			}
		}
	}
}

func TestConnectionRateExpiredEntriesAndExactBlockThreshold(t *testing.T) {
	at := newTestTracker(t)
	const ip = "192.0.2.1"
	now := time.Now()
	history := make([]time.Time, config.MaxConnectionsPerMinute)
	for i := range history {
		history[i] = now
	}
	history[0], history[1] = now.Add(-2*config.ConnectionRateWindow), now.Add(-2*config.ConnectionRateWindow)
	at.mu.Lock()
	at.connectionTimes[ip] = history
	at.mu.Unlock()
	blocked := make(chan string, 2)
	at.SetOnBlockCallback(func(ip string) { blocked <- ip })
	for range 2 {
		if !at.CheckConnectionRate(ip) {
			t.Fatal("expired accepted connections still consumed the budget")
		}
	}
	at.mu.RLock()
	accepted := slices.Clone(at.connectionTimes[ip])
	at.mu.RUnlock()
	for i := range config.RateLimitViolationsMax {
		if at.CheckConnectionRate(ip) {
			t.Fatal("an excess connection was allowed")
		}
		if i+1 < config.RateLimitViolationsMax && !at.GetBlockExpiry(ip).IsZero() {
			t.Fatal("automatic block fired before its violation threshold")
		}
	}
	select {
	case got := <-blocked:
		if got != ip {
			t.Fatalf("blocked wrong IP: %s", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("automatic block did not invoke its callback")
	}
	if n, total, limited := at.GetStats(); n != 1 || total != 1 || limited != uint64(config.RateLimitViolationsMax) {
		t.Fatalf("block statistics: %d, %d, %d", n, total, limited)
	}
	at.mu.RLock()
	defer at.mu.RUnlock()
	if !slices.Equal(at.connectionTimes[ip], accepted) || at.violationCounts[ip] != 0 {
		t.Fatal("denied attempts changed accepted history or failed to reset violations")
	}
}

func TestConnectionRateConcurrentAdmission(t *testing.T) {
	at := newTestTracker(t)
	ips := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}
	accepted := make([]atomic.Int64, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		for range 64 {
			wg.Go(func() {
				if at.CheckConnectionRate(ip) {
					accepted[i].Add(1)
				}
			})
		}
	}
	wg.Wait()
	for i, ip := range ips {
		if got := accepted[i].Load(); got != config.MaxConnectionsPerMinute {
			t.Errorf("%s admitted %d connections", ip, got)
		}
	}
	_, _, limited := at.GetStats()
	if want := uint64(len(ips) * (64 - config.MaxConnectionsPerMinute)); limited != want {
		t.Fatalf("rate-limit counter = %d, want %d", limited, want)
	}
}

func TestConnectionRateAutomaticBlockDoesNotShortenBan(t *testing.T) {
	at := newTestTracker(t)
	const ip = "192.0.2.1"
	until := time.Now().Add(2 * config.BlockDuration)
	at.mu.Lock()
	at.blockedIPs[ip] = until
	at.mu.Unlock()
	// CheckConnectionRate is the rate gate; the admission layer checks bans
	// separately. Concurrent admissions may already have passed that check.
	for range config.MaxConnectionsPerMinute + config.RateLimitViolationsMax {
		at.CheckConnectionRate(ip)
	}
	if got := at.GetBlockExpiry(ip); got != until {
		t.Fatalf("automatic block shortened the existing ban: %s", got)
	}
}

func TestAbuseCleanupPreservesBoundariesAndViolations(t *testing.T) {
	at := newTestTracker(t)
	now := time.Unix(1000, 0)
	cutoff := now.Add(-config.ConnectionRateWindow)
	at.mu.Lock()
	defer at.mu.Unlock()
	at.connectionTimes["active"] = []time.Time{cutoff, cutoff.Add(time.Nanosecond)}
	at.connectionTimes["stale"] = []time.Time{cutoff.Add(-time.Nanosecond), cutoff}
	at.blockedIPs["expired"] = now.Add(-time.Nanosecond)
	at.blockedIPs["boundary"] = now
	at.blockedIPs["future"] = now.Add(time.Hour)
	for _, ip := range []string{"active", "stale", "expired", "boundary", "future", "no-history"} {
		at.violationCounts[ip] = 2
	}
	at.cleanupExpired(now)
	if len(at.connectionTimes) != 1 || !slices.Equal(at.connectionTimes["active"], []time.Time{cutoff.Add(time.Nanosecond)}) {
		t.Fatalf("incorrect cleanup of connection history: %v", at.connectionTimes)
	}
	if len(at.blockedIPs) != 2 || at.blockedIPs["boundary"] != now || at.blockedIPs["future"] != now.Add(time.Hour) {
		t.Fatalf("block expiry boundaries changed: %v", at.blockedIPs)
	}
	if len(at.violationCounts) != 3 || at.violationCounts["active"] != 2 || at.violationCounts["boundary"] != 2 || at.violationCounts["future"] != 2 {
		t.Fatalf("cleanup lost active violations or retained stale ones: %v", at.violationCounts)
	}
}
