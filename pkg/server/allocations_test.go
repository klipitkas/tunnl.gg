package server

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

func TestResolvedVisitorKeysPreserveGrouping(t *testing.T) {
	for _, input := range []string{"192.0.2.1", "::ffff:192.0.2.1", "2001:db8:1:2:3:4:5:6", "2001:db8:1:2:ffff:ffff:ffff:ffff", "fe80::1%eth0"} {
		addr := netip.MustParseAddr(input)
		if got, want := visitorKeyAddr(addr), visitorKey(addr.String()); got != want {
			t.Errorf("%s: got %s want %s", input, got, want)
		}
	}
}

type readDeadlineRecorder struct {
	*httptest.ResponseRecorder
	reads []time.Time
}

func (w *readDeadlineRecorder) SetReadDeadline(deadline time.Time) error {
	w.reads = append(w.reads, deadline)
	return nil
}

func TestBodylessRequestClearsReadDeadline(t *testing.T) {
	s := newTestServer(t)
	tun := tunnel.New("empty", nil, "", 80, "")
	defer tun.Close()
	tun.Transport().RegisterProtocol("http", responseTransport{[]byte("ok")})
	s.tunnels[tun.Subdomain] = tun
	r := httptest.NewRequest(http.MethodGet, "https://empty.tunnl.gg/", nil)
	w := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.String() != "ok" {
		t.Fatalf("response: %d %s", w.Code, w.Body)
	}
	if r.Body != http.NoBody {
		t.Fatal("empty request acquired a body wrapper")
	}
	if len(w.reads) == 0 {
		t.Fatal("read deadline was not cleared")
	}
	for _, deadline := range w.reads {
		if !deadline.IsZero() {
			t.Fatal("bodyless request armed a read deadline")
		}
	}
}

func TestLocalResponseSecurityHeaders(t *testing.T) {
	for _, tc := range []struct {
		name, host, options, method string
		status                      int
	}{
		{"bad host", "example.com", "", http.MethodGet, http.StatusBadRequest},
		{"missing", "missing.tunnl.gg", "", http.MethodGet, http.StatusNotFound},
		{"password", "local.tunnl.gg", "auth=me:secret", http.MethodGet, http.StatusUnauthorized},
		{"allowlist", "local.tunnl.gg", "allow=203.0.113.1", http.MethodGet, http.StatusForbidden},
		{"preflight", "local.tunnl.gg", "cors=*", http.MethodOptions, http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			tun := tunnel.New("local", nil, "", 80, "")
			defer tun.Close()
			opts, err := tunnel.ParseOptions(tc.options)
			if err != nil {
				t.Fatal(err)
			}
			tun.SetOptions(opts)
			s.tunnels[tun.Subdomain] = tun
			r := httptest.NewRequest(tc.method, "https://"+tc.host+"/", nil)
			r.Header.Set("Origin", "https://example.com")
			r.Header.Set("Access-Control-Request-Method", http.MethodGet)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d", w.Code, tc.status)
			}
			for name, value := range securityHeaders {
				if got := w.Header().Get(name); got != value {
					t.Errorf("%s=%q want=%q", name, got, value)
				}
			}
		})
	}
	// Oversized bodies must still be rejected before looking up the tunnel.
	s := newTestServer(t)
	r := httptest.NewRequest(http.MethodPost, "https://missing.tunnl.gg/", nil)
	r.ContentLength = config.MaxRequestBodySize + 1
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("oversized request: %d %v", w.Code, w.Header())
	}
}

type bodyLimitTransport struct {
	read int64
	err  error
}

func (t *bodyLimitTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.read, t.err = io.Copy(io.Discard, r.Body)
	r.Body.Close()
	return nil, t.err
}

type zeroBody struct{}

func (zeroBody) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestUnknownLengthUploadStillLimited(t *testing.T) {
	s := newTestServer(t)
	tun := tunnel.New("upload", nil, "", 80, "")
	defer tun.Close()
	backend := &bodyLimitTransport{}
	tun.Transport().RegisterProtocol("http", backend)
	s.tunnels[tun.Subdomain] = tun
	r := httptest.NewRequest(http.MethodPost, "https://upload.tunnl.gg/", io.LimitReader(zeroBody{}, config.MaxRequestBodySize+1))
	r.ContentLength = -1
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var limitErr *http.MaxBytesError
	if backend.read != config.MaxRequestBodySize || !errors.As(backend.err, &limitErr) {
		t.Fatalf("upload limit lost: read=%d err=%v", backend.read, backend.err)
	}
	if w.Code != http.StatusBadGateway {
		t.Fatalf("proxy read failure status: %d", w.Code)
	}
}
