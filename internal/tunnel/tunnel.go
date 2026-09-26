package tunnel

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"tunnl.gg/internal/config"
)

// Tunnel represents an active SSH tunnel
type Tunnel struct {
	Subdomain      string
	Listener       net.Listener
	CreatedAt      time.Time
	LastActive     time.Time
	inFlight       int // requests and WebSockets currently open
	BindAddr       string
	BindPort       uint32
	ClientIP       string // SSH client IP that created this tunnel
	mu             sync.Mutex
	rateLimiter    *RateLimiter      // Tunnel-wide rate limit across all visitors
	visitorLimiter *KeyedRateLimiter // Per-visitor rate limit
	transport      *http.Transport   // Reusable HTTP transport for proxying
	logger         *RequestLogger    // Async request logger for SSH terminal output
}

// New creates a new tunnel with the given parameters
func New(subdomain string, listener net.Listener, bindAddr string, bindPort uint32, clientIP string) *Tunnel {
	now := time.Now()
	listenerAddr := listener.Addr().String()
	return &Tunnel{
		Subdomain:   subdomain,
		Listener:    listener,
		CreatedAt:   now,
		LastActive:  now,
		BindAddr:    bindAddr,
		BindPort:    bindPort,
		ClientIP:    clientIP,
		rateLimiter: NewRateLimiter(config.RequestsPerSecond, config.BurstSize),
		visitorLimiter: NewKeyedRateLimiter(
			config.VisitorRequestsPerSecond,
			config.VisitorBurstSize,
			config.MaxTrackedVisitors,
		),
		transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("tcp", listenerAddr, 10*time.Second)
			},
			MaxIdleConns:    10,
			IdleConnTimeout: 90 * time.Second,
		},
	}
}

// Touch updates the last active timestamp
func (t *Tunnel) Touch() {
	t.mu.Lock()
	t.LastActive = time.Now()
	t.mu.Unlock()
}

// BeginRequest marks a request or WebSocket as in flight. The tunnel does not
// become idle until the returned function is called, so long-lived streams and
// WebSockets keep it alive. The returned function is safe to call more than once.
func (t *Tunnel) BeginRequest() (end func()) {
	t.mu.Lock()
	t.inFlight++
	t.LastActive = time.Now()
	t.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			t.inFlight--
			t.LastActive = time.Now()
			t.mu.Unlock()
		})
	}
}

// IsExpired returns true if the tunnel has been inactive for too long or exceeded max lifetime.
// A tunnel with requests or WebSockets in flight is never inactive.
func (t *Tunnel) IsExpired() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return (t.inFlight == 0 && time.Since(t.LastActive) > config.InactivityTimeout) ||
		time.Since(t.CreatedAt) > config.MaxTunnelLifetime
}

// AllowRequest checks if a request from visitor is allowed by the rate limiters.
// The visitor's own limit is checked first so a visitor who is already throttled
// does not drain the tunnel-wide budget shared with everyone else.
func (t *Tunnel) AllowRequest(visitor string) bool {
	if !t.visitorLimiter.Allow(visitor) {
		return false
	}
	return t.rateLimiter.Allow()
}

// SetLogger sets the request logger for SSH terminal output
func (t *Tunnel) SetLogger(l *RequestLogger) {
	t.mu.Lock()
	t.logger = l
	t.mu.Unlock()
}

// Logger returns the request logger, or nil if none is set
func (t *Tunnel) Logger() *RequestLogger {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.logger
}

// Transport returns the reusable HTTP transport for this tunnel
func (t *Tunnel) Transport() *http.Transport {
	return t.transport
}

// Close closes the tunnel's listener and cleans up the transport and logger
func (t *Tunnel) Close() {
	t.Listener.Close()
	if t.transport != nil {
		t.transport.CloseIdleConnections()
	}
	t.mu.Lock()
	l := t.logger
	t.logger = nil
	t.mu.Unlock()
	if l != nil {
		l.Close()
	}
}
