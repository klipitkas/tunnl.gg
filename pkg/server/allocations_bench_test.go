package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

// Exercise the real request handler with an in-process backend. This isolates
// relay allocations from TLS, SSH, sockets and generator timing. Request/writer
// construction is included identically in both measurements. Recreate the
// tunnel outside the timer every 100 requests to stay below its abuse budgets.
func BenchmarkRequestAllocations(b *testing.B) {
	for _, tc := range []struct {
		name             string
		upload, response int
		inspect, missing bool
		ipv4             bool
	}{
		{name: "GET1KiB", response: 1024},
		{name: "GET1KiBIPv4", response: 1024, ipv4: true},
		{name: "GET64KiB", response: 65536},
		{name: "Upload16KiB", upload: 16384, response: 1024},
		{name: "Inspected16KiB", response: 16384, inspect: true},
		{name: "Inspected15000B", response: 15000, inspect: true},
		{name: "MissingTunnel", missing: true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			s := &Server{domain: config.DefaultDomain, tunnels: make(map[string]*tunnel.Tunnel),
				reqPerVisitor: newConnLimiter(config.MaxInFlightPerVisitor),
				reqPerTunnel:  newConnLimiter(config.MaxInFlightPerTunnel)}
			payload := make([]byte, tc.response)
			upload := make([]byte, tc.upload)
			var tun *tunnel.Tunnel
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if i%100 == 0 {
					b.StopTimer()
					if tun != nil {
						tun.Close()
					}
					tun = tunnel.New("allocation-bench", nil, "", 80, "")
					tun.Limits.BrowserWarning = false
					tun.AwaitOptions()
					tun.SetOptions(tunnel.Options{})
					tun.Transport().RegisterProtocol("http", allocationBackend{payload: payload, upload: int64(tc.upload)})
					if tc.inspect {
						tun.EnableInspector()
					}
					if !tc.missing {
						s.tunnels[tun.Subdomain] = tun
					}
					b.StartTimer()
				}
				method := http.MethodGet
				var body io.Reader
				if tc.upload > 0 {
					method = http.MethodPost
					body = bytes.NewReader(upload)
				}
				r := httptest.NewRequest(method, "https://allocation-bench.tunnl.gg/path?q=value", body)
				r.RemoteAddr = "[2001:db8:1234:5678::1]:1234"
				if tc.ipv4 {
					r.RemoteAddr = "198.51.100.1:1234"
				}
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				want := http.StatusOK
				if tc.missing {
					want = http.StatusNotFound
				}
				if w.Code != want {
					b.Fatalf("status %d, want %d", w.Code, want)
				}
				if !tc.missing && w.Body.Len() != tc.response {
					b.Fatalf("body length %d", w.Body.Len())
				}
			}
			b.StopTimer()
			if tun != nil {
				tun.Close()
			}
		})
	}
}

type allocationBackend struct {
	payload []byte
	upload  int64
}

func (t allocationBackend) RoundTrip(r *http.Request) (*http.Response, error) {
	var n int64
	if r.Body != nil {
		n, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	status := http.StatusOK
	if n != t.upload {
		status = http.StatusBadRequest
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(t.payload)), ContentLength: int64(len(t.payload)), Request: r}, nil
}
