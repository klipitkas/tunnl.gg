package server

import (
	"strings"
	"testing"
	"time"

	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

func TestExpiryText(t *testing.T) {
	tests := []struct {
		name   string
		limits config.Limits
		want   string
	}{
		{"free", config.FreeLimits(), "in 24h, or after 2h without traffic"},
		{"lifetime only", config.Limits{MaxLifetime: 12 * time.Hour}, "in 12h"},
		{"inactivity only", config.Limits{InactivityTimeout: 30 * time.Minute}, "after 30m without traffic"},
		{"no limits", config.Limits{}, "never"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := expiryText(tt.limits); got != tt.want {
				t.Errorf("expiryText() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSessionBannerUpgradeNote(t *testing.T) {
	limits := config.FreeLimits()
	plain := sessionBanner("https://x.example.com", "example.com", "note", limits, 0, tunnel.Options{})

	limits.UpgradeNote = "Pro: no time limits at https://example.com/pricing"
	withNote := sessionBanner("https://x.example.com", "example.com", "note", limits, 0, tunnel.Options{})
	if !strings.Contains(withNote, limits.UpgradeNote) {
		t.Errorf("banner is missing the upgrade note:\n%s", withNote)
	}
	// Without a note (the default, as on-prem), the banner has no extra line
	if strings.Count(withNote, "\r\n") != strings.Count(plain, "\r\n")+1 {
		t.Errorf("the note should add exactly one line")
	}
	if strings.Contains(plain, "Pro") {
		t.Errorf("banner without a note mentions Pro:\n%s", plain)
	}
}

func TestSessionBannerTransfer(t *testing.T) {
	limits := config.FreeLimits()
	banner := sessionBanner("https://x.example.com", "example.com", "note", limits, 1536, tunnel.Options{})
	if !strings.Contains(banner, "Transfer") || !strings.Contains(banner, "5 GB a day") || !strings.Contains(banner, "1.5 KB used today") {
		t.Errorf("banner is missing the daily transfer:\n%s", banner)
	}
	limits.DailyTransfer = 0
	if banner := sessionBanner("https://x.example.com", "example.com", "note", limits, 0, tunnel.Options{}); strings.Contains(banner, "Transfer") {
		t.Errorf("banner shows a transfer limit without one:\n%s", banner)
	}
}
