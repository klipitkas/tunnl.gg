package server

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sync/atomic"
)

// Stats holds server statistics
type Stats struct {
	ActiveTunnels    int      `json:"active_tunnels"`
	UniqueIPs        int      `json:"unique_ips"`
	TotalConnections uint64   `json:"total_connections"`
	TotalRequests    uint64   `json:"total_requests"`
	Subdomains       []string `json:"subdomains,omitempty"`

	// Abuse protection stats
	BlockedIPs       int    `json:"blocked_ips"`
	TotalBlocked     uint64 `json:"total_blocked"`
	TotalRateLimited uint64 `json:"total_rate_limited"`
}

// IncrementConnections increments the total connection counter
func (s *Server) IncrementConnections() {
	atomic.AddUint64(&s.totalConnections, 1)
}

// IncrementRequests increments the total request counter
func (s *Server) IncrementRequests() {
	atomic.AddUint64(&s.totalRequests, 1)
}

// GetStats returns current server statistics
func (s *Server) GetStats(includeSubdomains bool) Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	blockedIPs, totalBlocked, totalRateLimited := s.abuseTracker.GetStats()

	stats := Stats{
		ActiveTunnels:    len(s.tunnels),
		UniqueIPs:        len(s.ipConnections),
		TotalConnections: atomic.LoadUint64(&s.totalConnections),
		TotalRequests:    atomic.LoadUint64(&s.totalRequests),
		BlockedIPs:       blockedIPs,
		TotalBlocked:     totalBlocked,
		TotalRateLimited: totalRateLimited,
	}

	if includeSubdomains {
		stats.Subdomains = make([]string, 0, len(s.tunnels))
		for sub := range s.tunnels {
			stats.Subdomains = append(stats.Subdomains, sub)
		}
	}

	return stats
}

// StatsHandler returns an http.Handler for the stats endpoint
func (s *Server) StatsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only allow from localhost
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		includeSubdomains := r.URL.Query().Get("subdomains") == "true"
		stats := s.GetStats(includeSubdomains)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(stats); err != nil {
			log.Printf("Failed to encode stats response: %v", err)
		}
	})
}
