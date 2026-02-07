package tunnel

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLogRequest(t *testing.T) {
	var buf bytes.Buffer
	l := NewRequestLogger(&buf, 16)

	l.LogRequest("GET", "/api/users", 200, 12*time.Millisecond)
	l.Close()

	out := buf.String()
	if !strings.Contains(out, "GET") {
		t.Errorf("output missing method: %q", out)
	}
	if !strings.Contains(out, "/api/users") {
		t.Errorf("output missing path: %q", out)
	}
	if !strings.Contains(out, "200") {
		t.Errorf("output missing status: %q", out)
	}
	if !strings.Contains(out, "12ms") {
		t.Errorf("output missing latency: %q", out)
	}
	if !strings.HasSuffix(out, "\r\n") {
		t.Errorf("output should end with \\r\\n: %q", out)
	}
}

func TestLogWebSocketOpen(t *testing.T) {
	var buf bytes.Buffer
	l := NewRequestLogger(&buf, 16)

	l.LogWebSocketOpen("/ws/chat")
	l.Close()

	out := buf.String()
	if !strings.Contains(out, "WS") {
		t.Errorf("output missing WS: %q", out)
	}
	if !strings.Contains(out, "/ws/chat") {
		t.Errorf("output missing path: %q", out)
	}
	if !strings.Contains(out, "OPEN") {
		t.Errorf("output missing OPEN: %q", out)
	}
	if !strings.HasSuffix(out, "\r\n") {
		t.Errorf("output should end with \\r\\n: %q", out)
	}
}

func TestLogWebSocketClose(t *testing.T) {
	var buf bytes.Buffer
	l := NewRequestLogger(&buf, 16)

	l.LogWebSocketClose("/ws/chat", 2*time.Minute+31*time.Second, 1258291)
	l.Close()

	out := buf.String()
	if !strings.Contains(out, "WS") {
		t.Errorf("output missing WS: %q", out)
	}
	if !strings.Contains(out, "/ws/chat") {
		t.Errorf("output missing path: %q", out)
	}
	if !strings.Contains(out, "CLOSED") {
		t.Errorf("output missing CLOSED: %q", out)
	}
	if !strings.Contains(out, "2m31s") {
		t.Errorf("output missing duration: %q", out)
	}
	if !strings.Contains(out, "1.2MB") {
		t.Errorf("output missing bytes: %q", out)
	}
}

func TestNonBlocking(t *testing.T) {
	var buf bytes.Buffer
	l := NewRequestLogger(&buf, 1)

	// Send 100 lines with buffer size 1 — should not block
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			l.LogRequest("GET", "/test", 200, time.Millisecond)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("LogRequest blocked with full buffer")
	}

	l.Close()
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write error")
}

func TestClosedWriter(t *testing.T) {
	l := NewRequestLogger(errorWriter{}, 16)
	// Should not panic even though writer returns errors
	l.LogRequest("GET", "/test", 200, time.Millisecond)
	l.Close()
}

func TestCloseIdempotent(t *testing.T) {
	var buf bytes.Buffer
	l := NewRequestLogger(&buf, 16)
	l.Close()
	l.Close() // second call should not panic
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name  string
		bytes int64
		want  string
	}{
		{"zero", 0, "0B"},
		{"small", 512, "512B"},
		{"1KB", 1024, "1.0KB"},
		{"1.5MB", 1572864, "1.5MB"},
		{"2.3GB", 2469606195, "2.3GB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatBytes(tt.bytes); got != tt.want {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestFormatDurationHuman(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"5 seconds", 5 * time.Second, "5s"},
		{"2m30s", 2*time.Minute + 30*time.Second, "2m30s"},
		{"1h5m", 1*time.Hour + 5*time.Minute, "1h5m"},
		{"exact minutes", 3 * time.Minute, "3m"},
		{"exact hours", 2 * time.Hour, "2h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatDurationHuman(tt.d); got != tt.want {
				t.Errorf("formatDurationHuman(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestFormatRequestLog_LongPath(t *testing.T) {
	longPath := "/api/v1/very/long/path/that/exceeds/the/fifty/character/limit/by/a/lot"
	out := formatRequestLog("GET", longPath, 200, 5*time.Millisecond)

	if !strings.Contains(out, "...") {
		t.Errorf("long path should be truncated with ...: %q", out)
	}
	// Original path should NOT appear in full
	if strings.Contains(out, longPath) {
		t.Errorf("full long path should not appear in output: %q", out)
	}
}
