package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
)

// Stats holds server statistics
type Stats struct {
	ActiveTunnels    int      `json:"active_tunnels"`
	UniqueIPs        int      `json:"unique_ips"`
	TotalConnections uint64   `json:"total_connections"`
	TotalRequests    uint64   `json:"total_requests"`
	Subdomains       []string `json:"subdomains,omitempty"`
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

	stats := Stats{
		ActiveTunnels:    len(s.tunnels),
		UniqueIPs:        len(s.ipConnections),
		TotalConnections: atomic.LoadUint64(&s.totalConnections),
		TotalRequests:    atomic.LoadUint64(&s.totalRequests),
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
		remoteIP := r.RemoteAddr
		if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
			remoteIP = remoteIP[:idx]
		}
		if remoteIP != "127.0.0.1" && remoteIP != "::1" && remoteIP != "localhost" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		includeSubdomains := r.URL.Query().Get("subdomains") == "true"
		stats := s.GetStats(includeSubdomains)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	})
}
