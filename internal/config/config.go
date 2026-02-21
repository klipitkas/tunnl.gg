package config

import (
	"fmt"
	"time"
)

const (
	DefaultDomain         = "tunnl.gg"
	InactivityTimeout     = 2 * time.Hour
	MaxTunnelsPerIP       = 3
	MaxTotalTunnels       = 1000
	MaxPortsPerConnection = 10 // max -R port forwards per SSH connection

	// SSH handshake timeout
	SSHHandshakeTimeout = 30 * time.Second

	// HTTP rate limiting per tunnel
	RequestsPerSecond = 10
	BurstSize         = 20

	// Request size limits
	MaxRequestBodySize = 128 * 1024 * 1024 // 128MB

	// Connection rate limiting (new connections per IP)
	MaxConnectionsPerMinute = 10             // max new connections per IP per minute
	ConnectionRateWindow    = 1 * time.Minute

	// IP blocking
	BlockDuration          = 1 * time.Hour
	RateLimitViolationsMax = 10 // violations before auto-block

	// Tunnel lifetime
	MaxTunnelLifetime = 24 * time.Hour // max tunnel duration regardless of activity

	// Response size limits
	MaxResponseBodySize = 128 * 1024 * 1024 // 128MB

	// HTTP server timeouts
	HTTPReadTimeout    = 10 * time.Second
	HTTPWriteTimeout   = 10 * time.Second
	HTTPIdleTimeout    = 30 * time.Second
	HTTPSReadTimeout   = 30 * time.Second
	HTTPSWriteTimeout  = 30 * time.Second
	HTTPSIdleTimeout   = 120 * time.Second
	StatsReadTimeout   = 5 * time.Second
	StatsWriteTimeout  = 5 * time.Second
	ShutdownTimeout    = 10 * time.Second

	// WebSocket limits
	WebSocketIdleTimeout = 2 * time.Hour
	MaxWebSocketTransfer = 1024 * 1024 * 1024 // 1GB

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
