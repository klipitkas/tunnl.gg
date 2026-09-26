package tunnel

import (
	"bytes"
	"fmt"
	"net"
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

func TestTouch(t *testing.T) {
	tun := newTestTunnel(t)
	before := tun.LastActive
	time.Sleep(10 * time.Millisecond)
	tun.Touch()
	if !tun.LastActive.After(before) {
		t.Error("Touch() did not update LastActive")
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

func TestTimeRemaining(t *testing.T) {
	tun := newTestTunnel(t)
	remaining := tun.TimeRemaining()

	// For a new tunnel, remaining should be close to InactivityTimeout (2h)
	// since it's less than MaxTunnelLifetime (24h)
	if remaining <= 0 {
		t.Error("TimeRemaining() should be positive for a new tunnel")
	}
	if remaining > 2*time.Hour+time.Second {
		t.Errorf("TimeRemaining() = %v, want <= 2h", remaining)
	}
}

func TestTransport(t *testing.T) {
	tun := newTestTunnel(t)
	tr := tun.Transport()
	if tr == nil {
		t.Error("Transport() returned nil")
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

func TestIsMaxLifetimeExceeded(t *testing.T) {
	tun := newTestTunnel(t)

	if tun.IsMaxLifetimeExceeded() {
		t.Error("new tunnel should not have exceeded max lifetime")
	}

	tun.mu.Lock()
	tun.CreatedAt = time.Now().Add(-25 * time.Hour)
	tun.mu.Unlock()

	if !tun.IsMaxLifetimeExceeded() {
		t.Error("tunnel past max lifetime should report exceeded")
	}
}

func TestSetLogger(t *testing.T) {
	tun := newTestTunnel(t)
	var buf bytes.Buffer
	logger := NewRequestLogger(&buf, 16)
	defer logger.Close()

	tun.SetLogger(logger)

	got := tun.Logger()
	if got != logger {
		t.Error("SetLogger()/Logger() round-trip failed")
	}
}

func TestLogger_NilByDefault(t *testing.T) {
	tun := newTestTunnel(t)
	if tun.Logger() != nil {
		t.Error("Logger() should be nil by default")
	}
}

func TestClose_ClosesLogger(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	tun := New("test-sub-00000000", ln, "127.0.0.1", 8080, "127.0.0.1")

	var buf bytes.Buffer
	logger := NewRequestLogger(&buf, 16)
	tun.SetLogger(logger)

	tun.Close()

	// After Close, logger should be nil
	if tun.Logger() != nil {
		t.Error("Close() should nil out logger")
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

func TestTimeRemaining_LifetimeShorter(t *testing.T) {
	tun := newTestTunnel(t)

	// Set CreatedAt so lifetime remaining is shorter than inactivity remaining
	tun.mu.Lock()
	tun.CreatedAt = time.Now().Add(-23*time.Hour - 50*time.Minute)
	tun.LastActive = time.Now() // just touched, so inactivity remaining ~2h
	tun.mu.Unlock()

	remaining := tun.TimeRemaining()
	// Lifetime remaining should be ~10 minutes, which is less than inactivity timeout of 2h
	if remaining > 15*time.Minute {
		t.Errorf("TimeRemaining() = %v, want <= 15m (lifetime should be limiting)", remaining)
	}
}
