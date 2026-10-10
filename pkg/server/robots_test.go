package server

import (
	"fmt"
	"net/http"
	"testing"
)

// Search engines mustn't index tunnels: the app's pages, whatever the app
// says, and tunnl's own answers
func TestE2E_TunnelsAreNotIndexed(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Robots-Tag", "index, follow")
		fmt.Fprint(w, "my app")
	}))

	resp := tt.get(t, "/")
	resp.Body.Close()
	if got := resp.Header.Values("X-Robots-Tag"); len(got) != 1 || got[0] != "noindex, nofollow" {
		t.Errorf("app response X-Robots-Tag = %q, want only noindex, nofollow", got)
	}

	tt.local.Close() // tunnl answers with an error page now
	resp = tt.get(t, "/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get("X-Robots-Tag") != "noindex, nofollow" {
		t.Errorf("tunnl's error page: %d with X-Robots-Tag %q", resp.StatusCode, resp.Header.Get("X-Robots-Tag"))
	}
}
