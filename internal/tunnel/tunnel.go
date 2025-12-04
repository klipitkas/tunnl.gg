package tunnel

import (
	"net"
	"sync"
	"time"

	"tunnl.gg/internal/config"
)

// Tunnel represents an active SSH tunnel
type Tunnel struct {
	Subdomain   string
	Listener    net.Listener
	LastActive  time.Time
	BindAddr    string
	BindPort    uint32
	mu          sync.Mutex
	rateLimiter *RateLimiter
}

// New creates a new tunnel with the given parameters
func New(subdomain string, listener net.Listener, bindAddr string, bindPort uint32) *Tunnel {
	return &Tunnel{
		Subdomain:   subdomain,
		Listener:    listener,
		LastActive:  time.Now(),
		BindAddr:    bindAddr,
		BindPort:    bindPort,
		rateLimiter: NewRateLimiter(config.RequestsPerSecond, config.BurstSize),
	}
}

// Touch updates the last active timestamp
func (t *Tunnel) Touch() {
	t.mu.Lock()
	t.LastActive = time.Now()
	t.mu.Unlock()
}

// IsExpired returns true if the tunnel has been inactive for too long
func (t *Tunnel) IsExpired() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return time.Since(t.LastActive) > config.InactivityTimeout
}

// AllowRequest checks if a request is allowed by the rate limiter
func (t *Tunnel) AllowRequest() bool {
	return t.rateLimiter.Allow()
}

// Close closes the tunnel's listener
func (t *Tunnel) Close() {
	t.Listener.Close()
}
