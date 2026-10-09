package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// jsonEvents parses the session's output=json lines.
func (tt *testTunnel) jsonEvents(t *testing.T) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(tt.output.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("output=json printed a line that isn't JSON: %q", line)
		}
		events = append(events, e)
	}
	return events
}

// A free tunnel can ask for JSON output: it's what scripts and AI agents read
func TestE2E_JSONOutput(t *testing.T) {
	srv, addr := startSSHServer(t)
	tt := openTunnelCommand(t, srv, addr, anonymousClient(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	}), "output=json")

	events := tt.jsonEvents(t)
	if len(events) == 0 || events[0]["event"] != "tunnel" {
		t.Fatalf("first event = %v, want the tunnel", events)
	}
	first := events[0]
	if first["url"] != "https://"+tt.host() || first["subdomain"] != tt.sub || first["stable"] != false {
		t.Errorf("tunnel event = %v", first)
	}
	if first["idle_timeout_seconds"] != float64(7200) || first["max_lifetime_seconds"] != float64(86400) {
		t.Errorf("limits = %v / %v, want the free plan's", first["idle_timeout_seconds"], first["max_lifetime_seconds"])
	}

	tt.get(t, "/hooks/stripe?id=1")
	var req map[string]any
	waitFor(t, "request event", func() bool {
		for _, e := range tt.jsonEvents(t) {
			if e["event"] == "request" && e["path"] == "/hooks/stripe?id=1" {
				req = e
				return true
			}
		}
		return false
	})
	if req["method"] != "GET" || req["status"] != float64(200) || req["bytes"] != float64(5) {
		t.Errorf("request event = %v", req)
	}

	if _, err := tt.stdin.Write([]byte{0x03}); err != nil { // Ctrl+C
		t.Fatalf("writing Ctrl+C: %v", err)
	}
	waitFor(t, "summary notice", func() bool {
		events := tt.jsonEvents(t)
		last := events[len(events)-1]
		return last["event"] == "notice" && strings.Contains(last["message"].(string), "Stopped. 1 request")
	})
}
