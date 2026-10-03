package server

import (
	"testing"
	"time"

	"github.com/klipitkas/tunnl.gg/pkg/config"
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
