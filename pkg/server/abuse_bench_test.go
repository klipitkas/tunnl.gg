package server

import (
	"testing"
	"time"

	"github.com/klipitkas/tunnl.gg/pkg/config"
)

func BenchmarkConnectionRate(b *testing.B) {
	for _, mode := range []string{"fresh", "rolling", "limited", "burst10"} {
		b.Run(mode, func(b *testing.B) {
			at := &AbuseTracker{
				connectionTimes: make(map[string][]time.Time),
				blockedIPs:      make(map[string]time.Time), violationCounts: make(map[string]int),
			}
			const ip = "192.0.2.1"
			if mode == "rolling" || mode == "limited" {
				for range config.MaxConnectionsPerMinute {
					at.CheckConnectionRate(ip)
				}
			}
			old := time.Now().Add(-2 * config.ConnectionRateWindow)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				switch mode {
				case "fresh", "burst10":
					delete(at.connectionTimes, ip)
				case "rolling":
					// Simulate the oldest accepted connection leaving the window.
					at.connectionTimes[ip][0] = old
				}
				attempts := 1
				if mode == "burst10" {
					attempts = config.MaxConnectionsPerMinute
				}
				for range attempts {
					if got := at.CheckConnectionRate(ip); got != (mode != "limited") {
						b.Fatalf("unexpected admission in %s: %v", mode, got)
					}
				}
			}
		})
	}
}

func BenchmarkConnectionHistoryPrune(b *testing.B) {
	cutoff := time.Now().Add(-config.ConnectionRateWindow)
	for _, mode := range []string{"live", "mixed", "expired"} {
		b.Run(mode, func(b *testing.B) {
			times := make([]time.Time, config.MaxConnectionsPerMinute)
			input := make([]time.Time, len(times))
			want := 0
			for i := range input {
				input[i] = cutoff.Add(-time.Second)
				if mode == "live" || (mode == "mixed" && i%2 != 0) {
					input[i] = cutoff.Add(time.Second)
					want++
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				copy(times, input)
				if got := recentConnectionTimes(times, cutoff); len(got) != want {
					b.Fatalf("kept %d timestamps, want %d", len(got), want)
				}
			}
		})
	}
}

// Exercise the actual admission path, including the block check, rate check,
// anonymous-client limit and reservation/release locks, without SSH setup.
func BenchmarkConnectionAdmission(b *testing.B) {
	const ip = "192.0.2.1"
	at := &AbuseTracker{
		connectionTimes: make(map[string][]time.Time),
		blockedIPs:      make(map[string]time.Time), violationCounts: make(map[string]int),
	}
	s := &Server{abuseTracker: at, slots: make(map[string]int),
		freeLimits: config.FreeLimits(), maxTotalTunnels: 100}
	for range config.MaxConnectionsPerMinute {
		at.CheckConnectionRate(ip)
	}
	old := time.Now().Add(-2 * config.ConnectionRateWindow)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		at.connectionTimes[ip][0] = old
		slot, err := s.CheckAndReserveConnection(ip, nil)
		if err != nil || slot != ip {
			b.Fatalf("admission = %q, %v", slot, err)
		}
		s.ReleaseConnection(slot)
	}
	if s.totalReserved != 0 || len(s.slots) != 0 {
		b.Fatal("admission leaked connection reservations")
	}
}
