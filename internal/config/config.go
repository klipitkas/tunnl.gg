package config

import (
	"fmt"
	"time"
)

const (
	DefaultDomain     = "tunnl.gg"
	InactivityTimeout = 2 * time.Hour
	MaxTunnelsPerIP   = 3 // Reduced from 5
	MaxTotalTunnels   = 1000

	// SSH handshake limits
	SSHHandshakeTimeout     = 30 * time.Second
	MaxHandshakesPerIP      = 3   // concurrent in-progress SSH handshakes per IP
	MaxConcurrentHandshakes = 100 // concurrent in-progress SSH handshakes server-wide

	// HTTP rate limiting. Exceeding a limit only returns 429 to the visitor; it
	// never penalizes the tunnel owner, since visitors control the request rate.
	// Bursts are sized for dev servers that load a page as hundreds of modules.
	VisitorRequestsPerSecond = 25   // per visitor IP (IPv6 grouped by /64) per tunnel
	VisitorBurstSize         = 200  // max burst per visitor
	RequestsPerSecond        = 50   // per tunnel, across all visitors
	BurstSize                = 400  // max burst per tunnel
	MaxTrackedVisitors       = 1024 // visitors tracked per tunnel; extras share one bucket

	// Request size limits
	MaxRequestBodySize = 128 * 1024 * 1024 // 128MB

	// Connection rate limiting (new connections per IP)
	MaxConnectionsPerMinute = 10              // max new connections per IP per minute
	ConnectionRateWindow    = 1 * time.Minute // sliding window for connection rate

	// IP blocking
	BlockDuration          = 1 * time.Hour // how long to block abusive IPs
	RateLimitViolationsMax = 10            // SSH connection rate violations before auto-block

	// Tunnel lifetime
	MaxTunnelLifetime = 24 * time.Hour // max tunnel duration regardless of activity

	// Response size limits
	MaxResponseBodySize = 128 * 1024 * 1024 // 128MB

	// HTTP server timeouts
	HTTPReadHeaderTimeout  = 5 * time.Second
	HTTPReadTimeout        = 10 * time.Second
	HTTPWriteTimeout       = 10 * time.Second
	HTTPIdleTimeout        = 30 * time.Second
	HTTPSReadHeaderTimeout = 5 * time.Second
	HTTPSReadTimeout       = 30 * time.Second
	HTTPSWriteTimeout      = 30 * time.Second
	HTTPSIdleTimeout       = 120 * time.Second
	StatsReadHeaderTimeout = 2 * time.Second
	StatsReadTimeout       = 5 * time.Second
	StatsWriteTimeout      = 5 * time.Second
	ShutdownTimeout        = 10 * time.Second

	// Proxied requests replace the HTTPS read/write timeouts with an idle
	// timeout, so long polls, streams and slow uploads work while they make
	// progress. A request is canceled after this long without progress.
	ProxyIdleTimeout = 2 * time.Minute

	// WebSocket limits
	WebSocketIdleTimeout    = 2 * time.Hour
	MaxWebSocketTransfer    = 1024 * 1024 * 1024 // 1GB
	MaxWebSocketsPerTunnel  = 100                // concurrent WebSockets per tunnel
	MaxWebSocketsPerVisitor = 20                 // concurrent WebSockets per visitor IP across all tunnels

	// Channel opens to a tunnel client that it hasn't answered yet. Past this,
	// requests to the tunnel fail until the client answers or disconnects.
	MaxPendingChannelOpens = 32

	// Request logging
	LogBufferSize = 128 // buffered channel size for SSH terminal request logs

	// Interstitial warning cookie
	WarningCookieName   = "tunnl_warned"
	WarningCookieMaxAge = 86400 // 1 day
)

// Config holds runtime configuration loaded from environment
type Config struct {
	SSHAddr     string
	HTTPAddr    string
	HTTPSAddr   string
	StatsAddr   string
	HostKeyPath string
	TLSCert     string
	TLSKey      string
	Domain      string
	// TrustedProxies lists proxies whose forwarding headers identify visitors:
	// CIDRs or IPs setting X-Forwarded-For, and "cloudflare" for Cloudflare's
	// CF-Connecting-IP. Empty trusts nothing, for direct deployments.
	TrustedProxies string
}

// Default returns configuration with default values
func Default() *Config {
	return &Config{
		SSHAddr:     ":22",
		HTTPAddr:    ":80",
		HTTPSAddr:   ":443",
		StatsAddr:   "127.0.0.1:9090",
		HostKeyPath: "host_key",
		TLSCert:     fmt.Sprintf("/etc/letsencrypt/live/%s/fullchain.pem", DefaultDomain),
		TLSKey:      fmt.Sprintf("/etc/letsencrypt/live/%s/privkey.pem", DefaultDomain),
		Domain:      DefaultDomain,
	}
}
