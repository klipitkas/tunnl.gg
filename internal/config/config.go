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

	// SSH handshake timeout
	SSHHandshakeTimeout = 30 * time.Second

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

	// WebSocket limits
	WebSocketIdleTimeout    = 2 * time.Hour
	MaxWebSocketTransfer    = 1024 * 1024 * 1024 // 1GB
	MaxWebSocketsPerTunnel  = 100                // concurrent WebSockets per tunnel
	MaxWebSocketsPerVisitor = 20                 // concurrent WebSockets per visitor IP across all tunnels

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
