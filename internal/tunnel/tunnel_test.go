package tunnel

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
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

func TestRecordRateLimitHit(t *testing.T) {
	tun := newTestTunnel(t)

	// Should not trigger kill until threshold
	for i := 0; i < 9; i++ {
		if tun.RecordRateLimitHit() {
			t.Fatalf("RecordRateLimitHit() returned true on hit %d, want false", i+1)
		}
	}

	// 10th hit should trigger kill
	if !tun.RecordRateLimitHit() {
		t.Error("RecordRateLimitHit() should return true on 10th violation")
	}
}

func TestTransport(t *testing.T) {
	tun := newTestTunnel(t)
	tr := tun.Transport()
	if tr == nil {
		t.Error("Transport() returned nil")
	}
}

func TestAllowRequest(t *testing.T) {
	tun := newTestTunnel(t)

	// Should allow requests up to burst size
	for i := 0; i < 20; i++ {
		if !tun.AllowRequest() {
			t.Fatalf("AllowRequest() returned false on request %d (within burst)", i+1)
		}
	}

	// Should deny after burst exhausted
	if tun.AllowRequest() {
		t.Error("AllowRequest() should return false after burst exhausted")
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

type mockSSHConn struct {
	mu     sync.Mutex
	closed bool
}

func (m *mockSSHConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("already closed")
	}
	m.closed = true
	return nil
}

func (m *mockSSHConn) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func TestSetSSHConn(t *testing.T) {
	tun := newTestTunnel(t)
	mock := &mockSSHConn{}
	tun.SetSSHConn(mock)

	tun.mu.Lock()
	got := tun.sshConn
	tun.mu.Unlock()

	if got != mock {
		t.Error("SetSSHConn() did not set sshConn")
	}
}

func TestCloseSSH(t *testing.T) {
	tun := newTestTunnel(t)
	mock := &mockSSHConn{}
	tun.SetSSHConn(mock)

	tun.CloseSSH()

	if !mock.isClosed() {
		t.Error("CloseSSH() did not close the SSH connection")
	}

	// sshConn should be nil after close (prevents double-close)
	tun.mu.Lock()
	got := tun.sshConn
	tun.mu.Unlock()
	if got != nil {
		t.Error("CloseSSH() should nil out sshConn")
	}
}

func TestCloseSSH_Nil(t *testing.T) {
	tun := newTestTunnel(t)
	// Should not panic when no SSH connection is set
	tun.CloseSSH()
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
