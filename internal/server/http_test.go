package server

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"tunnl.gg/internal/config"
)

func TestStripPort(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"with port", "example.com:443", "example.com"},
		{"without port", "example.com", "example.com"},
		{"ipv4 with port", "127.0.0.1:8080", "127.0.0.1"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripPort(tt.input); got != tt.want {
				t.Errorf("stripPort(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsBrowserRequest(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      bool
	}{
		{"chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0", true},
		{"firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0", true},
		{"curl", "curl/7.68.0", false},
		{"go http", "Go-http-client/1.1", false},
		{"empty", "", false},
		{"safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{}}
			r.Header.Set("User-Agent", tt.userAgent)
			if got := isBrowserRequest(r); got != tt.want {
				t.Errorf("isBrowserRequest(%q) = %v, want %v", tt.userAgent, got, tt.want)
			}
		})
	}
}

func TestIsWebSocketRequest(t *testing.T) {
	tests := []struct {
		name       string
		upgrade    string
		connection string
		want       bool
	}{
		{"valid websocket", "websocket", "Upgrade", true},
		{"case insensitive", "WebSocket", "upgrade", true},
		{"missing upgrade header", "", "Upgrade", false},
		{"missing connection header", "websocket", "", false},
		{"wrong upgrade value", "http/2", "Upgrade", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{}}
			if tt.upgrade != "" {
				r.Header.Set("Upgrade", tt.upgrade)
			}
			if tt.connection != "" {
				r.Header.Set("Connection", tt.connection)
			}
			if got := isWebSocketRequest(r); got != tt.want {
				t.Errorf("isWebSocketRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasWarningCookie(t *testing.T) {
	sub := "test-sub-12345678"
	cookieName := config.WarningCookieName + "_" + sub

	tests := []struct {
		name   string
		cookie *http.Cookie
		want   bool
	}{
		{"no cookie", nil, false},
		{"valid cookie", &http.Cookie{Name: cookieName, Value: "1"}, true},
		{"wrong value", &http.Cookie{Name: cookieName, Value: "0"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{}}
			if tt.cookie != nil {
				r.AddCookie(tt.cookie)
			}
			if got := hasWarningCookie(r, sub); got != tt.want {
				t.Errorf("hasWarningCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetSecurityHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	setSecurityHeaders(w)

	expected := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":       "DENY",
		"X-Xss-Protection":      "1; mode=block",
		"Referrer-Policy":       "strict-origin-when-cross-origin",
	}

	for header, want := range expected {
		if got := w.Header().Get(header); got != want {
			t.Errorf("header %q = %q, want %q", header, got, want)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"2 hours", 2 * time.Hour, "2h"},
		{"1 hour", 1 * time.Hour, "1h"},
		{"90 minutes", 90 * time.Minute, "1h"},
		{"45 minutes", 45 * time.Minute, "45m"},
		{"10 minutes", 10 * time.Minute, "10m"},
		{"3 hours", 3 * time.Hour, "3h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatDuration(tt.d); got != tt.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestLimitedReadCloser(t *testing.T) {
	t.Run("within limit", func(t *testing.T) {
		data := "hello world"
		rc := io.NopCloser(strings.NewReader(data))
		lrc := &limitedReadCloser{rc: rc, limit: 100}

		buf, err := io.ReadAll(lrc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(buf) != data {
			t.Errorf("got %q, want %q", string(buf), data)
		}
	})

	t.Run("exceeds limit", func(t *testing.T) {
		data := "hello world" // 11 bytes
		rc := io.NopCloser(strings.NewReader(data))
		lrc := &limitedReadCloser{rc: rc, limit: 5}

		buf := make([]byte, 20)
		// First read should return up to limit
		n, err := lrc.Read(buf)
		if err != nil {
			t.Fatalf("first read error: %v", err)
		}
		if n != 5 {
			t.Errorf("first read got %d bytes, want 5", n)
		}

		// Second read should error
		_, err = lrc.Read(buf)
		if err == nil {
			t.Error("expected error after exceeding limit")
		}
	})

	t.Run("close", func(t *testing.T) {
		rc := io.NopCloser(strings.NewReader("test"))
		lrc := &limitedReadCloser{rc: rc, limit: 100}
		if err := lrc.Close(); err != nil {
			t.Errorf("Close() error: %v", err)
		}
	})
}

func TestCopyWithLimits(t *testing.T) {
	t.Run("normal copy", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		data := []byte("hello world")
		go func() {
			server.Write(data)
			server.Close()
		}()

		dst, dstWriter := net.Pipe()
		defer dst.Close()
		defer dstWriter.Close()

		received := make(chan []byte, 1)
		go func() {
			buf, _ := io.ReadAll(dst)
			received <- buf
		}()

		err := copyWithLimits(dstWriter, client, 1024, 5*time.Second)
		dstWriter.Close()

		if err != nil {
			t.Fatalf("copyWithLimits error: %v", err)
		}

		got := <-received
		if string(got) != string(data) {
			t.Errorf("got %q, want %q", string(got), string(data))
		}
	})

	t.Run("transfer limit exceeded", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		// Write more than limit
		go func() {
			buf := make([]byte, 100)
			for i := 0; i < 100; i++ {
				server.Write(buf)
			}
			server.Close()
		}()

		dst, dstWriter := net.Pipe()
		defer dst.Close()
		defer dstWriter.Close()

		// Drain dst to avoid blocking
		go io.Copy(io.Discard, dst)

		err := copyWithLimits(dstWriter, client, 500, 5*time.Second)
		if err == nil || !strings.Contains(err.Error(), "transfer limit exceeded") {
			t.Errorf("expected transfer limit exceeded error, got: %v", err)
		}
	})

	t.Run("idle timeout", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		dst, dstWriter := net.Pipe()
		defer dst.Close()
		defer dstWriter.Close()

		go io.Copy(io.Discard, dst)

		// Don't write anything — should timeout
		err := copyWithLimits(dstWriter, client, 1024, 50*time.Millisecond)
		if err == nil {
			t.Error("expected timeout error, got nil")
		}
	})
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(t.TempDir()+"/host_key", config.DefaultDomain)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	t.Cleanup(func() { s.Stop() })
	return s
}

func TestHTTPRedirectHandler(t *testing.T) {
	s := newTestServer(t)
	handler := s.HTTPRedirectHandler()

	tests := []struct {
		name       string
		host       string
		path       string
		wantCode   int
		wantTarget string
	}{
		{
			"subdomain redirect",
			"test-sub-12345678.tunnl.gg",
			"/foo",
			http.StatusMovedPermanently,
			"https://test-sub-12345678.tunnl.gg/foo",
		},
		{
			"bare domain redirect",
			"tunnl.gg",
			"/",
			http.StatusMovedPermanently,
			"https://tunnl.gg/",
		},
		{
			"bad domain rejected",
			"evil.com",
			"/",
			http.StatusBadRequest,
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://"+tt.host+tt.path, nil)
			r.Host = tt.host
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if w.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tt.wantCode)
			}
			if tt.wantTarget != "" {
				loc := w.Header().Get("Location")
				if loc != tt.wantTarget {
					t.Errorf("Location = %q, want %q", loc, tt.wantTarget)
				}
			}
		})
	}
}

func TestRedirectToWarningPage(t *testing.T) {
	s := newTestServer(t)
	sub := "happy-tiger-abcdef01"
	r := httptest.NewRequest("GET", "https://happy-tiger-abcdef01.tunnl.gg/path?q=1", nil)
	r.Host = "happy-tiger-abcdef01.tunnl.gg"
	w := httptest.NewRecorder()

	s.redirectToWarningPage(w, r, sub)

	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}

	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://tunnl.gg/#/warning?") {
		t.Errorf("Location = %q, want prefix https://tunnl.gg/#/warning?", loc)
	}
	if !strings.Contains(loc, "redirect="+url.QueryEscape("https://happy-tiger-abcdef01.tunnl.gg/path?q=1")) {
		t.Errorf("Location missing redirect param: %q", loc)
	}
	if !strings.Contains(loc, "subdomain="+url.QueryEscape("happy-tiger-abcdef01.tunnl.gg")) {
		t.Errorf("Location missing subdomain param: %q", loc)
	}
}
