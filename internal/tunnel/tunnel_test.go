package tunnel

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"tunnl.gg/internal/config"
)

func newTestTunnel(t *testing.T) *Tunnel {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create test listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return New("test-sub-00000000", ln, "127.0.0.1", 8080, "127.0.0.1")
}

func TestTouch_ResetsInactivity(t *testing.T) {
	tun := newTestTunnel(t)

	tun.mu.Lock()
	tun.LastActive = time.Now().Add(-3 * time.Hour)
	tun.mu.Unlock()

	tun.Touch()

	if tun.IsExpired() {
		t.Error("Touch() should reset the inactivity timer")
	}
}

func TestIsExpired_NotWhileRequestInFlight(t *testing.T) {
	tun := newTestTunnel(t)

	end := tun.BeginRequest()
	// A long-lived stream or WebSocket has been open for longer than the timeout
	tun.mu.Lock()
	tun.LastActive = time.Now().Add(-3 * time.Hour)
	tun.mu.Unlock()

	if tun.IsExpired() {
		t.Error("tunnel with a request in flight should not expire from inactivity")
	}

	end()
	end() // safe to call twice
	if tun.IsExpired() {
		t.Error("finishing a request should reset the inactivity timer")
	}

	tun.mu.Lock()
	tun.LastActive = time.Now().Add(-3 * time.Hour)
	tun.mu.Unlock()
	if !tun.IsExpired() {
		t.Error("tunnel should expire from inactivity once no requests are in flight")
	}
}

func TestIsExpired_MaxLifetimeWhileRequestInFlight(t *testing.T) {
	tun := newTestTunnel(t)
	defer tun.BeginRequest()()

	tun.mu.Lock()
	tun.CreatedAt = time.Now().Add(-25 * time.Hour)
	tun.mu.Unlock()

	if !tun.IsExpired() {
		t.Error("max lifetime should apply even with requests in flight")
	}
}

func TestIsExpired_NotExpiredInitially(t *testing.T) {
	tun := newTestTunnel(t)
	if tun.IsExpired() {
		t.Error("new tunnel should not be expired")
	}
}

func TestIsExpired_Inactivity(t *testing.T) {
	tun := newTestTunnel(t)
	tun.mu.Lock()
	tun.LastActive = time.Now().Add(-3 * time.Hour)
	tun.mu.Unlock()

	if !tun.IsExpired() {
		t.Error("tunnel with old LastActive should be expired")
	}
}

func TestIsExpired_MaxLifetime(t *testing.T) {
	tun := newTestTunnel(t)
	tun.mu.Lock()
	tun.CreatedAt = time.Now().Add(-25 * time.Hour)
	tun.mu.Unlock()

	if !tun.IsExpired() {
		t.Error("tunnel past max lifetime should be expired")
	}
}

func TestAllowRequest_PerVisitorLimit(t *testing.T) {
	tun := newTestTunnel(t)

	for i := 0; i < config.VisitorBurstSize; i++ {
		if !tun.AllowRequest("198.51.100.1") {
			t.Fatalf("AllowRequest() returned false on request %d (within visitor burst)", i+1)
		}
	}
	if tun.AllowRequest("198.51.100.1") {
		t.Error("AllowRequest() should return false after visitor burst exhausted")
	}

	// Another visitor has their own budget
	if !tun.AllowRequest("198.51.100.2") {
		t.Error("throttling one visitor should not affect another")
	}
}

func TestAllowRequest_TunnelWideLimit(t *testing.T) {
	tun := newTestTunnel(t)

	allowed := 0
	for v := 0; allowed < config.BurstSize; v++ {
		visitor := fmt.Sprintf("198.51.100.%d", v)
		for i := 0; i < config.VisitorBurstSize && allowed < config.BurstSize; i++ {
			if !tun.AllowRequest(visitor) {
				t.Fatalf("AllowRequest() returned false after %d requests (within tunnel burst)", allowed)
			}
			allowed++
		}
	}

	if tun.AllowRequest("203.0.113.1") {
		t.Error("AllowRequest() should return false for a new visitor after tunnel burst exhausted")
	}
}

func TestAllowRequest_ThrottledVisitorDoesNotDrainTunnelBudget(t *testing.T) {
	tun := newTestTunnel(t)

	// One visitor hammers the tunnel far beyond its own limit
	for i := 0; i < config.BurstSize*10; i++ {
		tun.AllowRequest("198.51.100.1")
	}

	// Only the requests allowed by the visitor limit consumed tunnel budget
	remaining := config.BurstSize - config.VisitorBurstSize
	for i := 0; i < remaining; i++ {
		visitor := fmt.Sprintf("203.0.113.%d", i/config.VisitorBurstSize)
		if !tun.AllowRequest(visitor) {
			t.Fatalf("AllowRequest() returned false on request %d; throttled visitor drained tunnel budget", i+1)
		}
	}
}

func TestClose_FlushesAndDetachesLogger(t *testing.T) {
	tun := newTestTunnel(t)

	var buf bytes.Buffer
	tun.SetLogger(NewRequestLogger(&buf, 16))
	tun.Logger().LogRequest("GET", "/pending", 200, time.Millisecond)

	tun.Close()

	if !strings.Contains(buf.String(), "/pending") {
		t.Errorf("Close() should flush pending log lines, got %q", buf.String())
	}
	if tun.Logger() != nil {
		t.Error("Close() should detach the logger so requests stop logging to a closed session")
	}
}

func TestClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	tun := New("test-sub-00000000", ln, "127.0.0.1", 8080, "127.0.0.1")
	tun.Close()

	// Listener should be closed — Accept should fail
	_, err = ln.Accept()
	if err == nil {
		t.Error("Close() should close the listener")
	}
}
