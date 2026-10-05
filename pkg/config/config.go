package config

import (
	"fmt"
	"time"
)

const (
	DefaultDomain     = "tunnl.gg"
	StableSSHUser     = "stable" // SSH user that gets a stable subdomain from its key
	AccountSSHUser    = "pro"    // SSH user that accounts connect as, when the server has an AccountStore
	InactivityTimeout = 2 * time.Hour
	MaxTunnelsPerIP   = 3
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

	// Wrong passwords for a tunnel with auth=, per visitor per tunnel: a
	// burst for typos, then one every 10 seconds
	PasswordFailureBurst      = 10
	PasswordFailuresPerSecond = 0.1

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

	// Concurrent proxied requests (WebSockets are limited separately). Set
	// above the visitor burst so dev servers loading many modules at once work.
	MaxInFlightPerVisitor = 256 // per visitor IP across all tunnels
	MaxInFlightPerTunnel  = 512 // per tunnel across all visitors

	// WebSocket limits
	WebSocketIdleTimeout    = 2 * time.Hour
	MaxWebSocketTransfer    = 1024 * 1024 * 1024 // 1GB
	MaxWebSocketsPerTunnel  = 100                // concurrent WebSockets per tunnel
	MaxWebSocketsPerVisitor = 20                 // concurrent WebSockets per visitor IP across all tunnels

	// Channel opens to a tunnel client that it hasn't answered yet. Past this,
	// requests wait for the client to answer (up to the 10s dial timeout).
	MaxPendingChannelOpens = 32

	// Request logging
	LogBufferSize = 128 // buffered channel size for SSH terminal request logs

	// Interstitial warning cookie
	WarningCookieName   = "tunnl_warned"
	WarningCookieMaxAge = 86400 // 1 day
)

// Limits are the limits and features that apply to a client's tunnels.
// Anonymous clients get FreeLimits; a hosted deployment can give accounts
// others.
type Limits struct {
	MaxTunnels        int           // tunnels open at once per client IP, or per account
	InactivityTimeout time.Duration // closes a tunnel after this long without traffic; 0 means never
	MaxLifetime       time.Duration // closes a tunnel after this long regardless of activity; 0 means never
	BrowserWarning    bool          // browsers see the warning page before reaching the tunnel
	Options           []string      // ssh command options the client may set (see AllOptions); nil allows none
	OptionsNote       string        // added to the error when a client sets an option it may not, e.g. how to get it
	UpgradeNote       string        // shown with the time limits (in the banner, the warning before they close a tunnel, and when they do), e.g. how to lift them; empty shows nothing
	Inspect           bool          // keep the latest requests for the request inspector (tunnel.Inspector)
}

// Options clients can set in the ssh command; see tunnel.ParseOptions.
const (
	OptionHost  = "host"  // rewrite the Host header sent to the app
	OptionAuth  = "auth"  // HTTP basic authentication for visitors
	OptionAllow = "allow" // visitor IP allowlist
	OptionCORS  = "cors"  // CORS headers for browsers on other sites
)

// AllOptions lists every option.
var AllOptions = []string{OptionHost, OptionAuth, OptionAllow, OptionCORS}

// AllowsOption reports whether a client with these limits may set the option.
func (l Limits) AllowsOption(name string) bool {
	for _, o := range l.Options {
		if o == name {
			return true
		}
	}
	return false
}

// FreeLimits returns the limits for anonymous clients.
func FreeLimits() Limits {
	return Limits{
		MaxTunnels:        MaxTunnelsPerIP,
		InactivityTimeout: InactivityTimeout,
		MaxLifetime:       MaxTunnelLifetime,
		BrowserWarning:    true,
		Options:           AllOptions,
	}
}

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
