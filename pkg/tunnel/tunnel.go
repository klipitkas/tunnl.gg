package tunnel

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/klipitkas/tunnl.gg/pkg/config"
)

// Tunnel represents an active SSH tunnel
type Tunnel struct {
	Subdomain      string
	opener         ChannelOpener // SSH connection to the tunnel client
	CreatedAt      time.Time
	LastActive     time.Time
	inFlight       int // requests and WebSockets currently open
	BindAddr       string
	BindPort       uint32
	ClientIP       string        // SSH client IP that created this tunnel
	AccountID      string        // the account whose key opened it, or "" for anonymous clients
	Limits         config.Limits // set before the tunnel is shared, then read-only
	mu             sync.Mutex
	rateLimiter    *RateLimiter      // Tunnel-wide rate limit across all visitors
	visitorLimiter *KeyedRateLimiter // Per-visitor rate limit
	transport      *http.Transport   // Reusable HTTP transport for proxying
	pendingOpens   chan struct{}     // slots for channel opens awaiting the client's answer
	logger         *RequestLogger    // Async request logger for SSH terminal output
}

// New creates a new tunnel that forwards traffic to the client over opener
func New(subdomain string, opener ChannelOpener, bindAddr string, bindPort uint32, clientIP string) *Tunnel {
	now := time.Now()
	t := &Tunnel{
		Subdomain:    subdomain,
		opener:       opener,
		CreatedAt:    now,
		LastActive:   now,
		BindAddr:     bindAddr,
		BindPort:     bindPort,
		ClientIP:     clientIP,
		Limits:       config.FreeLimits(),
		rateLimiter:  NewRateLimiter(config.RequestsPerSecond, config.BurstSize),
		pendingOpens: make(chan struct{}, config.MaxPendingChannelOpens),
		visitorLimiter: NewKeyedRateLimiter(
			config.VisitorRequestsPerSecond,
			config.VisitorBurstSize,
			config.MaxTrackedVisitors,
		),
	}
	t.transport = &http.Transport{
		// Every request goes to the client over an SSH channel, whatever the URL
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return t.Dial(ctx)
		},
		// All requests share one host, so keep as many idle connections for
		// it as in total; the default of 2 opens a channel for most requests
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	return t
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
// A tunnel with requests or WebSockets in flight is never inactive. Limits
// that are zero don't apply.
func (t *Tunnel) IsExpired() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	idle, lifetime := t.Limits.InactivityTimeout, t.Limits.MaxLifetime
	return (idle > 0 && t.inFlight == 0 && time.Since(t.LastActive) > idle) ||
		(lifetime > 0 && time.Since(t.CreatedAt) > lifetime)
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

// Close cleans up the tunnel's transport and logger. Open channels close with
// the SSH connection.
func (t *Tunnel) Close() {
	if t.transport != nil {
		t.transport.CloseIdleConnections()
	}
	t.mu.Lock()
	l := t.logger
	t.logger = nil
	t.mu.Unlock()
	if l != nil {
		// Don't wait for the log to flush: callers may hold locks, and a client
		// that stopped reading would block the write until its connection
		// closes. The SSH session flushes its own log before this.
		l.CloseWithin(0)
	}
}
