package config

import "time"

const (
	Domain            = "tunnl.gg"
	InactivityTimeout = 1 * time.Hour
	MaxTunnelsPerIP   = 5
	MaxTotalTunnels   = 1000

	// HTTP rate limiting per tunnel
	RequestsPerSecond = 10 // requests per second per tunnel
	BurstSize         = 20 // max burst size

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
}

// Default returns configuration with default values
func Default() *Config {
	return &Config{
		SSHAddr:     ":22",
		HTTPAddr:    ":80",
		HTTPSAddr:   ":443",
		StatsAddr:   "127.0.0.1:9090",
		HostKeyPath: "host_key",
		TLSCert:     "/etc/letsencrypt/live/tunnl.gg/fullchain.pem",
		TLSKey:      "/etc/letsencrypt/live/tunnl.gg/privkey.pem",
	}
}
