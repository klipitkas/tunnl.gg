package server

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"runtime/metrics"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

// scrape returns the server's metrics as a local collector would get them.
func scrape(t *testing.T, s *Server) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	s.StatsHandler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /metrics: status %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Errorf("Content-Type = %q, want the Prometheus text format", ct)
	}
	return w.Body.String()
}

func histogramCount(h *histogram) uint64 {
	var n uint64
	for i := range h.counts {
		n += h.counts[i].Load()
	}
	return n
}

var sampleLine = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^{}]*\})? (\S+)$`)

func TestMetricsEndpoint(t *testing.T) {
	s := newTestServer(t)

	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	s.StatsHandler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("remote GET /metrics: status %d, want %d", w.Code, http.StatusForbidden)
	}

	body := scrape(t, s)
	for _, want := range []string{
		"# TYPE tunnl_tunnels gauge\ntunnl_tunnels 0\n",
		"tunnl_tunnels_limit 1000\n",
		"# TYPE tunnl_proxied_request_duration_seconds histogram\n",
		`tunnl_proxied_request_duration_seconds_bucket{le="0.001"} 0`,
		`tunnl_proxied_request_duration_seconds_bucket{le="120"} 0`,
		`tunnl_proxied_response_body_bytes_bucket{le="1024"} 0`,
		`tunnl_answered_requests_total{reason="visitor_requests"} 0`,
		`tunnl_proxied_requests_total{result="app_refused"} 0`,
		`tunnl_https_connections_first_request_total{protocol="h2",resumed="true"} 0`,
		`tunnl_ssh_handshake_failures_total{reason="no_common_algorithm"} 0`,
		"# TYPE go_sched_latencies_seconds histogram\n",
		`go_sched_latencies_seconds_bucket{le="+Inf"} `,
		"# TYPE go_cpu_gc_seconds_total counter\n",
		"\ngo_goroutines ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q", want)
		}
	}

	// Every sample has a valid name and a number, and each family is
	// declared once, before its samples
	declared := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		if name, ok := strings.CutPrefix(line, "# TYPE "); ok {
			name, _, _ = strings.Cut(name, " ")
			if declared[name] {
				t.Errorf("%s declared twice", name)
			}
			declared[name] = true
			continue
		}
		if strings.HasPrefix(line, "# HELP ") {
			continue
		}
		m := sampleLine.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("malformed sample %q", line)
			continue
		}
		if _, err := strconv.ParseFloat(m[3], 64); err != nil {
			t.Errorf("sample %q: value isn't a number", line)
		}
		family := m[1]
		for _, suffix := range []string{"_bucket", "_sum", "_count"} {
			if base, ok := strings.CutSuffix(family, suffix); ok && declared[base] {
				family = base
			}
		}
		if !declared[family] {
			t.Errorf("sample %q before its family's TYPE", line)
		}
	}

	// The JSON stats are unchanged
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	w = httptest.NewRecorder()
	s.StatsHandler().ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), `"active_tunnels":0`) {
		t.Errorf("GET / = %s, want the JSON stats", w.Body)
	}
}

func TestHistogramExposition(t *testing.T) {
	var h histogram
	bounds := []int64{10, 100}
	for _, v := range []int64{0, 10, 11, 100, 101, 5000} {
		h.observe(bounds, v)
	}
	var b strings.Builder
	promWriter{&b}.histogram("test_seconds", "Test.", &h, bounds, 10)
	want := "# HELP test_seconds Test.\n# TYPE test_seconds histogram\n" +
		"test_seconds_bucket{le=\"1\"} 2\n" +
		"test_seconds_bucket{le=\"10\"} 4\n" +
		"test_seconds_bucket{le=\"+Inf\"} 6\n" +
		"test_seconds_sum 522.2\n" +
		"test_seconds_count 6\n"
	if b.String() != want {
		t.Errorf("histogram:\n%s\nwant:\n%s", b.String(), want)
	}
}

func TestRuntimeHistogramRegrouping(t *testing.T) {
	h := &metrics.Float64Histogram{
		Counts:  []uint64{1, 2, 3, 4},
		Buckets: []float64{math.Inf(-1), 1e-6, 5e-6, 1e-3, math.Inf(1)},
	}
	var b strings.Builder
	writeRuntimeHistogram(promWriter{&b}, "test_seconds", "Test.", h)
	for _, want := range []string{
		`test_seconds_bucket{le="1e-06"} 1`,
		`test_seconds_bucket{le="1e-05"} 3`,
		`test_seconds_bucket{le="0.0001"} 3`,
		`test_seconds_bucket{le="0.001"} 6`,
		`test_seconds_bucket{le="1"} 6`,
		`test_seconds_bucket{le="+Inf"} 10`,
		"test_seconds_count 10",
	} {
		if !strings.Contains(b.String(), want+"\n") {
			t.Errorf("regrouped histogram lacks %q:\n%s", want, b.String())
		}
	}
	// Midpoints, or the finite edge of an open-ended bucket
	sum := 1*1e-6 + 2*3e-6 + 3*(5e-6+1e-3)/2 + 4*1e-3
	m := regexp.MustCompile(`test_seconds_sum (\S+)`).FindStringSubmatch(b.String())
	if got, _ := strconv.ParseFloat(m[1], 64); math.Abs(got-sum) > 1e-12 {
		t.Errorf("sum = %v, want %v", got, sum)
	}
}

func TestRequestResult(t *testing.T) {
	for _, tc := range []struct {
		status int
		err    error
		cutOff bool
		want   int
	}{
		{http.StatusOK, nil, false, result2xx},
		{http.StatusSwitchingProtocols, nil, false, result1xx},
		{http.StatusFound, nil, false, result3xx},
		{http.StatusNotFound, nil, false, result4xx},
		{http.StatusServiceUnavailable, nil, false, result5xx},
		{0, nil, false, resultError},
		{http.StatusOK, nil, true, resultCutOff},
		{http.StatusBadGateway, &ssh.OpenChannelError{Reason: ssh.ConnectionFailed, Message: "Connection refused"}, false, resultAppRefused},
		{http.StatusBadGateway, fmt.Errorf("dial: %w", context.DeadlineExceeded), false, resultDialTimeout},
		{http.StatusBadGateway, fmt.Errorf("dial: %w", tunnel.ErrUnresponsive), false, resultUnresponsive},
		{http.StatusBadGateway, context.Canceled, false, resultCanceled},
		{http.StatusBadGateway, fmt.Errorf("%w: 200000000 bytes", errResponseTooLarge), false, resultTooLarge},
		{http.StatusBadGateway, io.ErrUnexpectedEOF, false, resultError},
	} {
		if got := requestResult(tc.status, tc.err, tc.cutOff); got != tc.want {
			t.Errorf("requestResult(%d, %v, %v) = %s, want %s", tc.status, tc.err, tc.cutOff, resultNames[got], resultNames[tc.want])
		}
	}
}

func TestClientSoftware(t *testing.T) {
	for version, want := range map[string]string{
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5": "OpenSSH_9.6",
		"SSH-2.0-OpenSSH_10.3":                     "OpenSSH_10.3",
		"SSH-2.0-OpenSSH_for_Windows_9.5":          "OpenSSH_for_Windows_9.5",
		"SSH-2.0-OpenSSH_9.9p":                     "OpenSSH_9.9p",
		"SSH-1.99-OpenSSH_3.9p1":                   "OpenSSH_3.9",
		"SSH-2.0-Go":                               "Go",
		"SSH-2.0-PuTTY_Release_0.81":               "PuTTY_Release_0.81",
		"SSH-2.0-dropbear_2022.83":                 "dropbear_2022.83",
		"SSH-2.0-\"evil\"{}\\\n":                   "evil",
		"SSH-2.0-" + strings.Repeat("a", 100):      strings.Repeat("a", 32),
		"SSH-2.0-":                                 "unknown",
		"":                                         "unknown",
	} {
		if got := clientSoftware([]byte(version)); got != want {
			t.Errorf("clientSoftware(%q) = %q, want %q", version, got, want)
		}
	}
}

func TestE2E_MetricsDescribeTunnelTraffic(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 2048))
	}))
	for i := 0; i < 2; i++ {
		resp := tt.get(t, "/")
		io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
	}
	req, err := http.NewRequest(http.MethodGet, tt.public.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "nothing-here-12345678." + config.DefaultDomain
	resp, err := tt.public.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	m := &tt.srv.metrics
	waitFor(t, "both proxied requests to be recorded", func() bool { return m.results[result2xx].Load() == 2 })
	body := scrape(t, tt.srv)
	for _, want := range []string{
		`tunnl_proxied_requests_total{result="2xx"} 2`,
		`tunnl_proxied_response_headers_seconds_count 2`,
		`tunnl_proxied_request_duration_seconds_count 2`,
		`tunnl_proxied_response_body_bytes_bucket{le="1024"} 0`,
		`tunnl_proxied_response_body_bytes_bucket{le="4096"} 2`,
		`tunnl_proxied_request_body_bytes_bucket{le="0"} 2`,
		`tunnl_answered_requests_total{reason="no_tunnel"} 1`,
		`tunnl_https_requests_total{protocol="http/1.1"} 3`,
		`tunnl_tunnels 1`,
		`tunnl_ssh_handshake_seconds_count 1`,
	} {
		if !strings.Contains(body, want+"\n") {
			t.Errorf("metrics lack %q", want)
		}
	}
	// The Go client is the SSH client here; it prefers AES-GCM
	if !regexp.MustCompile(`(?m)^tunnl_ssh_handshakes_total\{client="Go",kex="[^"]+",cipher="aes128-gcm@openssh.com",mac=""\} 1$`).MatchString(body) {
		t.Errorf("metrics lack the Go client's handshake:\n%s", body)
	}
	// The tunnel's transport keeps the backend connection for the next request
	if opens := histogramCount(&m.channelOpenTime); opens < 1 || opens > 2 {
		t.Errorf("%d channel opens recorded, want 1 or 2", opens)
	}
}

func TestHTTPSConnectionMetrics(t *testing.T) {
	s := newTestServer(t)
	ts := httptest.NewUnstartedServer(s)
	ts.EnableHTTP2 = true
	ts.Config.ConnContext = s.HTTPSConnContext
	ts.Config.ConnState = s.HTTPSConnState
	ts.StartTLS()
	defer ts.Close()

	for i := 0; i < 3; i++ {
		req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "nothing-here-12345678." + config.DefaultDomain
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("protocol %s, want HTTP/2", resp.Proto)
		}
	}

	m := &s.metrics
	if got := m.httpsOpened.Load(); got != 1 {
		t.Errorf("%d connections opened, want 1", got)
	}
	if got := m.httpsFirst[1][0].Load(); got != 1 {
		t.Errorf("%d new HTTP/2 connections counted at their first request, want 1", got)
	}
	if got := m.httpsRequests[1].Load(); got != 3 {
		t.Errorf("%d HTTP/2 requests, want 3", got)
	}
	if got := m.answered[answerNoTunnel].Load(); got != 3 {
		t.Errorf("%d requests answered for want of a tunnel, want 3", got)
	}
}

func TestSampleTunnels(t *testing.T) {
	s := newTestServer(t)
	quiet := tunnel.New("quiet-tunnel-00000001", nil, "", 80, "")
	busy := tunnel.New("busy-tunnel-00000002", nil, "", 80, "")
	s.mu.Lock()
	s.tunnels[quiet.Subdomain], s.tunnels[busy.Subdomain] = quiet, busy
	s.mu.Unlock()

	last := s.sampleTunnels(nil)
	if n := histogramCount(&s.metrics.tunnelRequests); n != 0 {
		t.Fatalf("the first sample recorded %d values, want none: it has no previous totals", n)
	}

	for i := 0; i < 7; i++ {
		busy.CountRequest(http.StatusOK, 0, 1000, time.Millisecond)
	}
	// Opened since the last sample, so its first, partial minute is skipped
	late := tunnel.New("late-tunnel-00000003", nil, "", 80, "")
	late.CountRequest(http.StatusOK, 0, 1000, 0)
	s.mu.Lock()
	s.tunnels[late.Subdomain] = late
	s.mu.Unlock()
	s.sampleTunnels(last)

	requests, bytes := &s.metrics.tunnelRequests, &s.metrics.tunnelBytes
	if got := histogramCount(requests); got != 2 {
		t.Errorf("%d tunnels sampled, want 2", got)
	}
	// Buckets: requests up to 0, 1, 2, 5, 10; bytes up to 0, 256, 1 KiB, 4 KiB, 16 KiB
	if requests.counts[0].Load() != 1 || requests.counts[4].Load() != 1 || requests.sum.Load() != 7 {
		t.Errorf("requests per minute: want the quiet tunnel's 0 and the busy one's 7")
	}
	if bytes.counts[0].Load() != 1 || bytes.counts[4].Load() != 1 || bytes.sum.Load() != 7000 {
		t.Errorf("bytes per minute: want the quiet tunnel's 0 and the busy one's 7000")
	}
}

func TestE2E_WebSocketMetrics(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(echoWebSocketBackend))
	conn, br := tt.dialWebSocket(t, "/ws")
	conn.Write([]byte("ping"))
	echo := make([]byte, 4)
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("echo %q, %v", echo, err)
	}
	conn.Close()

	m := &tt.srv.metrics
	waitFor(t, "the WebSocket to be recorded when it closes", func() bool { return histogramCount(&m.wsTime) == 1 })
	if got := m.wsRelayed.Load(); got != 1 {
		t.Errorf("%d WebSockets relayed, want 1", got)
	}
	// The pings both ways, and the app's upgrade response
	if got := m.wsBytes.sum.Load(); got <= 8 {
		t.Errorf("%d WebSocket bytes, want the upgrade response and both pings", got)
	}
}

func TestSSHHandshakeFailureReasons(t *testing.T) {
	srv, addr := startSSHServer(t)
	cfg := anonymousClient()
	cfg.Ciphers = []string{ssh.InsecureCipherAES128CBC} // which the server doesn't offer
	if client, err := ssh.Dial("tcp", addr, cfg); err == nil {
		client.Close()
		t.Fatal("handshake succeeded without a common cipher")
	}
	waitFor(t, "the failed handshake to be counted", func() bool {
		return srv.metrics.sshFailures[sshFailedAlgorithms].Load() == 1
	})
}
