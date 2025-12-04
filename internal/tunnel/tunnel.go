package tunnel

import (
	"net"
	"sync"
	"time"

	"tunnl.gg/internal/config"
)

// SSHCloser is an interface for closing SSH connections
type SSHCloser interface {
	Close() error
}

// Tunnel represents an active SSH tunnel
type Tunnel struct {
	Subdomain       string
	Listener        net.Listener
	CreatedAt       time.Time
	LastActive      time.Time
	BindAddr        string
	BindPort        uint32
	ClientIP        string    // SSH client IP that created this tunnel
	mu              sync.Mutex
	rateLimiter     *RateLimiter
	sshConn         SSHCloser // Reference to SSH connection for forced closure
	rateLimitHits   int       // Count of rate limit violations
}

// New creates a new tunnel with the given parameters
func New(subdomain string, listener net.Listener, bindAddr string, bindPort uint32, clientIP string) *Tunnel {
	now := time.Now()
	return &Tunnel{
		Subdomain:   subdomain,
		Listener:    listener,
		CreatedAt:   now,
		LastActive:  now,
		BindAddr:    bindAddr,
		BindPort:    bindPort,
		ClientIP:    clientIP,
		rateLimiter: NewRateLimiter(config.RequestsPerSecond, config.BurstSize),
	}
}

// Touch updates the last active timestamp
func (t *Tunnel) Touch() {
	t.mu.Lock()
	t.LastActive = time.Now()
	t.mu.Unlock()
}

// IsExpired returns true if the tunnel has been inactive for too long or exceeded max lifetime
func (t *Tunnel) IsExpired() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return time.Since(t.LastActive) > config.InactivityTimeout ||
		time.Since(t.CreatedAt) > config.MaxTunnelLifetime
}

// IsMaxLifetimeExceeded returns true if the tunnel has exceeded max lifetime
func (t *Tunnel) IsMaxLifetimeExceeded() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return time.Since(t.CreatedAt) > config.MaxTunnelLifetime
}

// TimeRemaining returns the time remaining before the tunnel expires (either by inactivity or max lifetime)
func (t *Tunnel) TimeRemaining() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	inactivityRemaining := config.InactivityTimeout - time.Since(t.LastActive)
	lifetimeRemaining := config.MaxTunnelLifetime - time.Since(t.CreatedAt)

	if inactivityRemaining < lifetimeRemaining {
		return inactivityRemaining
	}
	return lifetimeRemaining
}

// AllowRequest checks if a request is allowed by the rate limiter
func (t *Tunnel) AllowRequest() bool {
	return t.rateLimiter.Allow()
}

// SetSSHConn sets the SSH connection reference for forced closure
func (t *Tunnel) SetSSHConn(conn SSHCloser) {
	t.mu.Lock()
	t.sshConn = conn
	t.mu.Unlock()
}

// RecordRateLimitHit records a rate limit violation and returns true if the tunnel should be killed
func (t *Tunnel) RecordRateLimitHit() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rateLimitHits++
	return t.rateLimitHits >= config.RateLimitViolationsMax
}

// CloseSSH closes the SSH connection associated with this tunnel
func (t *Tunnel) CloseSSH() {
	t.mu.Lock()
	conn := t.sshConn
	t.mu.Unlock()

	if conn != nil {
		conn.Close()
	}
}

// Close closes the tunnel's listener
func (t *Tunnel) Close() {
	t.Listener.Close()
}
