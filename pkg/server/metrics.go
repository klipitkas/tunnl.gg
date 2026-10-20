package server

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"runtime/metrics"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

// relayMetrics measure the relay for capacity planning: where proxied
// requests spend their time, what visitors' connections and SSH clients look
// like, and how traffic is spread across tunnels. They are served in the
// Prometheus text format on the private stats listener (GET /metrics).
//
// The zero value is ready to use, and recording takes a few atomic adds
// without allocating, so the request path pays almost nothing for them.
type relayMetrics struct {
	// HTTPS connections, from Cloudflare's edge in production
	httpsOpened, httpsClosed atomic.Uint64
	httpsFirst               [2][2]atomic.Uint64 // connections by [HTTP/2][resumed TLS], at their first tunnel request
	httpsRequests            [2]atomic.Uint64    // tunnel requests over HTTP/1.x and HTTP/2

	// Requests tunnl answered itself, and proxied requests
	answered      [numAnswers]atomic.Uint64
	results       [numResults]atomic.Uint64
	requestTime   histogram // until the response was sent, or failed
	headersTime   histogram // until the app's response headers arrived
	requestBytes  histogram
	responseBytes histogram

	// Backend connections: channels opened to tunnel clients
	channelOpenTime histogram
	channelRefused  atomic.Uint64 // the client refused, e.g. nothing listens on its local port
	channelFailed   atomic.Uint64 // other failures, e.g. the connection closed

	// WebSockets
	wsRelayed, wsDialFailed atomic.Uint64
	wsTime                  histogram
	wsBytes                 histogram

	// SSH clients
	sshHandshakeTime histogram
	sshFailures      [numSSHFailures]atomic.Uint64
	keepAliveCloses  atomic.Uint64 // connections closed for silence; see keepAlive
	sshMu            sync.Mutex
	sshClients       map[sshClientKey]uint64

	// Every open tunnel's traffic, sampled each tunnelSampleInterval
	tunnelRequests histogram
	tunnelBytes    histogram
}

// Bucket upper bounds. Latencies are in nanoseconds, up to the 2-minute proxy
// idle timeout; sizes are in bytes, up to the 128 MB body limits.
var (
	latencyBuckets = []int64{1e6, 2.5e6, 5e6, 10e6, 25e6, 50e6, 100e6, 250e6, 500e6, 1e9, 2.5e9, 5e9, 10e9, 30e9, 60e9, 120e9}
	sizeBuckets    = []int64{0, 256, 1 << 10, 4 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 4 << 20, 16 << 20, 64 << 20, 128 << 20}
	// WebSockets last up to their 2-hour idle timeout
	sessionBuckets = []int64{1e9, 10e9, 60e9, 300e9, 900e9, 1800e9, 3600e9, 7200e9}
	// Requests per tunnel per minute; 3,000 is a tunnel's sustained rate limit
	rateBuckets = []int64{0, 1, 2, 5, 10, 30, 60, 300, 600, 1500, 3000, 6000}
)

// maxBuckets is the most bounds any histogram has.
const maxBuckets = 16

// histogram counts values into buckets. The bounds are the caller's, the
// same on every call: latencyBuckets, sizeBuckets and so on.
type histogram struct {
	counts [maxBuckets + 1]atomic.Uint64 // counts[len(bounds)] holds values above every bound
	sum    atomic.Int64
}

func (h *histogram) observe(bounds []int64, v int64) {
	i := 0
	for i < len(bounds) && v > bounds[i] {
		i++
	}
	h.counts[i].Add(1)
	h.sum.Add(v)
}

// Why tunnl answered a request itself instead of the app.
const (
	answerTooLarge          = iota // the request body is over the size limit
	answerBadHost                  // not a tunnel's host
	answerNoTunnel                 // no tunnel open on the subdomain
	answerNoOptions                // the client never sent its options
	answerAllowlist                // the visitor isn't on the tunnel's allowlist
	answerRateLimited              // the visitor's or the tunnel's request rate
	answerPreflight                // a CORS preflight
	answerPasswordTries            // too many wrong passwords
	answerPassword                 // no or a wrong password
	answerWarningPage              // a browser sent to the warning page
	answerVisitorWebSockets        // the visitor's open WebSockets
	answerTunnelWebSockets         // the tunnel's open WebSockets
	answerVisitorRequests          // the visitor's open requests
	answerTunnelRequests           // the tunnel's open requests
	numAnswers
)

var answerNames = [numAnswers]string{"too_large", "bad_host", "no_tunnel", "no_options", "allowlist", "rate_limited",
	"cors_preflight", "password_tries", "password", "warning_page", "visitor_websockets", "tunnel_websockets",
	"visitor_requests", "tunnel_requests"}

func (m *relayMetrics) answer(why int) {
	m.answered[why].Add(1)
}

// Results of proxied requests: the app's status class, or why its response
// didn't reach the visitor.
const (
	result1xx = iota // the app's status classes, in order
	result2xx
	result3xx
	result4xx
	result5xx          // the app's own 5xx; tunnl's are the results below
	resultAppRefused   // the tunnel client couldn't connect to its local app
	resultDialTimeout  // the tunnel client didn't answer the channel open in time
	resultUnresponsive // the tunnel client had stopped answering channel opens
	resultCanceled     // the visitor left, or the request went idle, before a response
	resultTooLarge     // the response was over the size limit
	resultCutOff       // the response stopped partway
	resultError        // anything else, e.g. the app closed the connection
	numResults
)

var resultNames = [numResults]string{"1xx", "2xx", "3xx", "4xx", "5xx",
	"app_refused", "dial_timeout", "unresponsive", "canceled", "too_large", "cut_off", "error"}

// requestResult classifies a proxied request by the status the app answered
// with, or by the error that kept its response from the visitor. It matches
// describeProxyError.
func requestResult(status int, err error, cutOff bool) int {
	switch {
	case cutOff:
		return resultCutOff
	case err == nil && status >= 100 && status < 600:
		return result1xx + status/100 - 1
	case err == nil:
		return resultError
	}
	// Declared after the success path returns, since it escapes
	var openErr *ssh.OpenChannelError
	switch {
	case errors.As(err, &openErr):
		return resultAppRefused
	case errors.Is(err, errResponseTooLarge):
		return resultTooLarge
	case errors.Is(err, tunnel.ErrUnresponsive):
		return resultUnresponsive
	case errors.Is(err, context.DeadlineExceeded):
		return resultDialTimeout
	case errors.Is(err, context.Canceled):
		return resultCanceled
	default:
		return resultError
	}
}

// requestDone records a proxied request once its response was sent or failed.
func (m *relayMetrics) requestDone(result int, took time.Duration, bytesIn, bytesOut int64) {
	m.results[result].Add(1)
	m.requestTime.observe(latencyBuckets, int64(took))
	m.requestBytes.observe(sizeBuckets, bytesIn)
	m.responseBytes.observe(sizeBuckets, bytesOut)
}

func (m *relayMetrics) websocketDone(took time.Duration, bytes int64) {
	m.wsTime.observe(sessionBuckets, int64(took))
	m.wsBytes.observe(sizeBuckets, bytes)
}

// httpsConn is what's known about a visitor's HTTPS connection.
type httpsConn struct {
	counted atomic.Bool // a tunnel request on it was counted
}

type httpsConnKey struct{}

// HTTPSConnContext and HTTPSConnState are for the HTTPS server's ConnContext
// and ConnState. They count visitors' connections and, at the first tunnel
// request on each, its protocol and whether TLS resumed a session.
func (s *Server) HTTPSConnContext(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, httpsConnKey{}, &httpsConn{})
}

func (s *Server) HTTPSConnState(_ net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		s.metrics.httpsOpened.Add(1)
	case http.StateClosed, http.StateHijacked:
		s.metrics.httpsClosed.Add(1)
	}
}

// countRequest counts a tunnel request by protocol, and its connection if
// it's the first tunnel request on it.
func (m *relayMetrics) countRequest(r *http.Request) {
	h2 := 0
	if r.ProtoMajor == 2 {
		h2 = 1
	}
	m.httpsRequests[h2].Add(1)
	if c, _ := r.Context().Value(httpsConnKey{}).(*httpsConn); c != nil && c.counted.CompareAndSwap(false, true) {
		resumed := 0
		if r.TLS != nil && r.TLS.DidResume {
			resumed = 1
		}
		m.httpsFirst[h2][resumed].Add(1)
	}
}

// timedOpener opens a tunnel's channels, recording how long the client takes
// to answer: a round trip to the client plus its connection to the local app.
type timedOpener struct {
	tunnel.ChannelOpener
	m *relayMetrics
}

func (o timedOpener) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	start := time.Now()
	ch, reqs, err := o.ChannelOpener.OpenChannel(name, data)
	o.m.channelOpened(time.Since(start), err)
	return ch, reqs, err
}

func (m *relayMetrics) channelOpened(took time.Duration, err error) {
	if err == nil {
		m.channelOpenTime.observe(latencyBuckets, int64(took))
		return
	}
	var openErr *ssh.OpenChannelError
	if errors.As(err, &openErr) {
		m.channelRefused.Add(1)
	} else {
		m.channelFailed.Add(1)
	}
}

// sshClientKey groups SSH connections by client software and negotiated
// algorithms. Responses travel from the client, so the read direction's
// cipher and MAC are what the server spends on decrypting them.
type sshClientKey struct {
	client, kex, cipher, mac string
}

// maxSSHClientKeys bounds the keys kept: clients choose their version
// strings, so further keys are counted together as "other".
const maxSSHClientKeys = 200

// sshConnected counts a completed SSH handshake. conn is the connection's
// ssh.Conn, which can report the negotiated algorithms.
func (m *relayMetrics) sshConnected(conn ssh.ConnMetadata, took time.Duration) {
	m.sshHandshakeTime.observe(latencyBuckets, int64(took))
	key := sshClientKey{client: clientSoftware(conn.ClientVersion())}
	if a, ok := conn.(ssh.AlgorithmsConnMetadata); ok {
		algs := a.Algorithms()
		key.kex, key.cipher, key.mac = algs.KeyExchange, algs.Read.Cipher, algs.Read.MAC
	}
	m.sshMu.Lock()
	defer m.sshMu.Unlock()
	if m.sshClients == nil {
		m.sshClients = make(map[sshClientKey]uint64)
	}
	if _, ok := m.sshClients[key]; !ok && len(m.sshClients) >= maxSSHClientKeys {
		key = sshClientKey{"other", "other", "other", "other"}
	}
	m.sshClients[key]++
}

// Why SSH handshakes failed.
const (
	sshFailedAlgorithms = iota // no algorithm in common, e.g. a very old client
	sshFailedTimeout
	sshFailedOther // mostly scanners, and clients that hang up
	numSSHFailures
)

var sshFailureNames = [numSSHFailures]string{"no_common_algorithm", "timeout", "other"}

func (m *relayMetrics) sshFailed(err error) {
	var algErr *ssh.AlgorithmNegotiationError
	var netErr net.Error
	switch {
	case errors.As(err, &algErr):
		m.sshFailures[sshFailedAlgorithms].Add(1)
	case errors.As(err, &netErr) && netErr.Timeout():
		m.sshFailures[sshFailedTimeout].Add(1)
	default:
		m.sshFailures[sshFailedOther].Add(1)
	}
}

// clientSoftware returns the software part of an SSH client's version
// string, without OpenSSH's portable release suffix: "SSH-2.0-OpenSSH_9.6p1
// Ubuntu-3" gives "OpenSSH_9.6". Clients choose the string, so it's cut short
// and limited to letters, digits and ._-
func clientSoftware(version []byte) string {
	v := string(version)
	if rest, ok := strings.CutPrefix(v, "SSH-"); ok {
		if _, software, ok := strings.Cut(rest, "-"); ok {
			v = software
		}
	}
	v, _, _ = strings.Cut(v, " ")
	if i := strings.LastIndexByte(v, 'p'); strings.HasPrefix(v, "OpenSSH_") && i > 0 && isDigits(v[i+1:]) {
		v = v[:i]
	}
	v = strings.Map(func(r rune) rune {
		if r == '.' || r == '_' || r == '-' || 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' {
			return r
		}
		return -1
	}, v)
	if len(v) > 32 {
		v = v[:32]
	}
	if v == "" {
		return "unknown"
	}
	return v
}

func isDigits(s string) bool {
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// tunnelSampleInterval is how often every open tunnel's traffic is sampled.
const tunnelSampleInterval = time.Minute

// sampleTunnels records each open tunnel's requests and response bytes since
// the previous sample, given the totals seen then, and returns the totals
// seen now. Tunnels opened since then are left for the next sample, so every
// sample covers a whole interval.
func (s *Server) sampleTunnels(last map[*tunnel.Tunnel]tunnel.Totals) map[*tunnel.Tunnel]tunnel.Totals {
	s.mu.RLock()
	open := make([]*tunnel.Tunnel, 0, len(s.tunnels))
	for _, t := range s.tunnels {
		open = append(open, t)
	}
	s.mu.RUnlock()

	seen := make(map[*tunnel.Tunnel]tunnel.Totals, len(open))
	for _, t := range open {
		now := t.Totals()
		seen[t] = now
		if before, ok := last[t]; ok {
			s.metrics.tunnelRequests.observe(rateBuckets, now.Requests-before.Requests)
			s.metrics.tunnelBytes.observe(sizeBuckets, now.BytesOut-before.BytesOut)
		}
	}
	return seen
}

// sampleTunnelsEvery samples the open tunnels' traffic until stop is closed.
func (s *Server) sampleTunnelsEvery(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var last map[*tunnel.Tunnel]tunnel.Totals
	for {
		select {
		case <-ticker.C:
			last = s.sampleTunnels(last)
		case <-stop:
			return
		}
	}
}

// promWriter writes metrics in the Prometheus text format.
type promWriter struct{ w io.Writer }

func (p promWriter) header(name, kind, help string) {
	fmt.Fprintf(p.w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
}

// value writes one sample; labels are "" or like `a="x",b="y"`.
func (p promWriter) value(name, labels string, v uint64) {
	if labels != "" {
		labels = "{" + labels + "}"
	}
	fmt.Fprintf(p.w, "%s%s %d\n", name, labels, v)
}

func (p promWriter) float(name, labels string, v float64) {
	if labels != "" {
		labels = "{" + labels + "}"
	}
	fmt.Fprintf(p.w, "%s%s %s\n", name, labels, formatFloat(v))
}

// single writes a metric with one unlabeled sample.
func (p promWriter) single(name, kind, help string, v uint64) {
	p.header(name, kind, help)
	p.value(name, "", v)
}

// histogram writes h, whose values are divided by unit: 1e9 turns
// nanoseconds into seconds.
func (p promWriter) histogram(name, help string, h *histogram, bounds []int64, unit float64) {
	p.header(name, "histogram", help)
	var count uint64
	for i, b := range bounds {
		count += h.counts[i].Load()
		p.value(name+"_bucket", `le="`+formatFloat(float64(b)/unit)+`"`, count)
	}
	count += h.counts[len(bounds)].Load()
	p.value(name+"_bucket", `le="+Inf"`, count)
	p.float(name+"_sum", "", float64(h.sum.Load())/unit)
	p.value(name+"_count", "", count)
}

func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// label quotes a label value: backslashes, quotes and newlines are escaped.
func label(v string) string {
	return `"` + labelEscaper.Replace(v) + `"`
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// writeMetrics writes the server's metrics in the Prometheus text format.
func (s *Server) writeMetrics(w io.Writer) {
	p := promWriter{w}
	m := &s.metrics
	st := s.GetStats(false)

	p.single("tunnl_tunnels", "gauge", "Open tunnels.", uint64(st.ActiveTunnels))
	p.single("tunnl_tunnels_limit", "gauge", "Tunnel admission cap (MAX_TOTAL_TUNNELS).", uint64(st.MaxTotalTunnels))
	p.single("tunnl_ssh_client_ips", "gauge", "Client IPs (IPv6 by /64) with an admitted SSH connection.", uint64(st.UniqueIPs))
	p.single("tunnl_ssh_connections_total", "counter", "SSH connections admitted after the handshake.", st.TotalConnections)
	p.single("tunnl_ssh_rate_limited_total", "counter", "SSH connections over the per-IP connection rate.", st.TotalRateLimited)
	p.single("tunnl_blocked_ips", "gauge", "IPs blocked from connecting over SSH.", uint64(st.BlockedIPs))
	p.single("tunnl_blocked_total", "counter", "IP blocks.", st.TotalBlocked)
	p.single("tunnl_admitted_requests_total", "counter", "Tunnel requests within the tunnels' rate limits.", st.TotalRequests)
	p.single("tunnl_proxied_requests_in_flight", "gauge", "Proxied requests in flight.", uint64(st.ActiveRequests))
	p.single("tunnl_websockets_open", "gauge", "Open WebSockets.", uint64(st.ActiveWebSockets))
	pending, busiestPending := s.pendingOpens()
	p.single("tunnl_busiest_tunnel_requests_in_flight", "gauge", "Proxied requests in flight on the busiest tunnel.", uint64(s.reqPerTunnel.busiest()))
	p.single("tunnl_busiest_visitor_requests_in_flight", "gauge", "Proxied requests in flight from the busiest visitor.", uint64(s.reqPerVisitor.busiest()))
	p.single("tunnl_channel_opens_pending", "gauge", "Channel opens awaiting the tunnel clients' answers.", uint64(pending))
	p.single("tunnl_busiest_tunnel_channel_opens_pending", "gauge", "Channel opens awaiting the answer of the busiest tunnel's client.", uint64(busiestPending))

	// Closed first: every connection counted closed was counted opened before
	closed := m.httpsClosed.Load()
	opened := m.httpsOpened.Load()
	p.single("tunnl_https_connections_total", "counter", "HTTPS connections accepted, for every host.", opened)
	p.single("tunnl_https_connections_open", "gauge", "HTTPS connections open, for every host.", opened-closed)
	protocols := [2]string{"http/1.1", "h2"}
	p.header("tunnl_https_connections_first_request_total", "counter", "HTTPS connections, at their first tunnel request, by protocol and TLS session resumption.")
	for h2, protocol := range protocols {
		for resumed, r := range [2]string{"false", "true"} {
			p.value("tunnl_https_connections_first_request_total", "protocol="+label(protocol)+",resumed="+label(r), m.httpsFirst[h2][resumed].Load())
		}
	}
	p.header("tunnl_https_requests_total", "counter", "Tunnel requests by protocol.")
	for h2, protocol := range protocols {
		p.value("tunnl_https_requests_total", "protocol="+label(protocol), m.httpsRequests[h2].Load())
	}

	p.header("tunnl_answered_requests_total", "counter", "Tunnel requests tunnl answered itself, without the app, by reason.")
	for i, name := range answerNames {
		p.value("tunnl_answered_requests_total", "reason="+label(name), m.answered[i].Load())
	}
	p.header("tunnl_proxied_requests_total", "counter", "Proxied requests by the app's status class, or why its response didn't reach the visitor.")
	for i, name := range resultNames {
		p.value("tunnl_proxied_requests_total", "result="+label(name), m.results[i].Load())
	}
	p.histogram("tunnl_proxied_request_duration_seconds", "Proxied requests from arrival until the response was sent or failed.", &m.requestTime, latencyBuckets, 1e9)
	p.histogram("tunnl_proxied_response_headers_seconds", "Proxied requests from arrival until the app's response headers arrived.", &m.headersTime, latencyBuckets, 1e9)
	p.histogram("tunnl_proxied_request_body_bytes", "Request body bytes sent to the app.", &m.requestBytes, sizeBuckets, 1)
	p.histogram("tunnl_proxied_response_body_bytes", "Response body bytes sent to the visitor.", &m.responseBytes, sizeBuckets, 1)

	p.histogram("tunnl_channel_open_seconds", "Time tunnel clients took to accept a channel: a round trip plus their connection to the local app.", &m.channelOpenTime, latencyBuckets, 1e9)
	p.header("tunnl_channel_open_failures_total", "counter", "Channel opens that failed, by reason.")
	p.value("tunnl_channel_open_failures_total", `reason="refused"`, m.channelRefused.Load())
	p.value("tunnl_channel_open_failures_total", `reason="failed"`, m.channelFailed.Load())

	p.header("tunnl_websockets_total", "counter", "WebSocket upgrades relayed to the app, and those whose channel failed.")
	p.value("tunnl_websockets_total", `result="relayed"`, m.wsRelayed.Load())
	p.value("tunnl_websockets_total", `result="dial_failed"`, m.wsDialFailed.Load())
	p.histogram("tunnl_websocket_duration_seconds", "Relayed WebSockets' durations.", &m.wsTime, sessionBuckets, 1e9)
	p.histogram("tunnl_websocket_bytes", "Bytes relayed per WebSocket, both directions.", &m.wsBytes, sizeBuckets, 1)

	p.histogram("tunnl_ssh_handshake_seconds", "Completed SSH handshakes' durations.", &m.sshHandshakeTime, latencyBuckets, 1e9)
	p.header("tunnl_ssh_handshakes_total", "counter", "Completed SSH handshakes by client software and negotiated key exchange, cipher and MAC (client to server).")
	m.sshMu.Lock()
	keys := make([]sshClientKey, 0, len(m.sshClients))
	for k := range m.sshClients {
		keys = append(keys, k)
	}
	counts := make([]uint64, len(keys))
	slices.SortFunc(keys, func(a, b sshClientKey) int {
		return cmp.Or(strings.Compare(a.client, b.client), strings.Compare(a.kex, b.kex),
			strings.Compare(a.cipher, b.cipher), strings.Compare(a.mac, b.mac))
	})
	for i, k := range keys {
		counts[i] = m.sshClients[k]
	}
	m.sshMu.Unlock()
	for i, k := range keys {
		p.value("tunnl_ssh_handshakes_total", "client="+label(k.client)+",kex="+label(k.kex)+",cipher="+label(k.cipher)+",mac="+label(k.mac), counts[i])
	}
	p.header("tunnl_ssh_handshake_failures_total", "counter", "Failed SSH handshakes by reason.")
	for i, name := range sshFailureNames {
		p.value("tunnl_ssh_handshake_failures_total", "reason="+label(name), m.sshFailures[i].Load())
	}
	p.single("tunnl_ssh_keepalive_closes_total", "counter", "SSH connections closed because nothing came from the client for the keepalive timeout.", m.keepAliveCloses.Load())

	p.histogram("tunnl_tunnel_requests_per_minute", "Every open tunnel's requests in each whole minute.", &m.tunnelRequests, rateBuckets, 1)
	p.histogram("tunnl_tunnel_response_bytes_per_minute", "Every open tunnel's response body bytes in each whole minute.", &m.tunnelBytes, sizeBuckets, 1)

	writeRuntimeMetrics(p)
}

// pendingOpens returns the channel opens awaiting tunnel clients' answers, in
// all and on the tunnel with the most.
func (s *Server) pendingOpens() (total, busiest int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tunnels {
		n := t.PendingOpens()
		total += n
		busiest = max(busiest, n)
	}
	return total, busiest
}

// runtimeMetrics are the Go runtime's own measurements, served with the
// relay's. Scheduling latency shows CPU saturation before CPU use does.
// Names a Go version doesn't have are skipped.
var runtimeMetrics = []struct{ name, runtime, kind, help string }{
	{"go_sched_latencies_seconds", "/sched/latencies:seconds", "histogram", "Time goroutines waited to run once runnable (sum approximate)."},
	{"go_gc_pauses_seconds", "/sched/pauses/total/gc:seconds", "histogram", "Stop-the-world pauses for garbage collection (sum approximate)."},
	{"go_cpu_gc_seconds_total", "/cpu/classes/gc/total:cpu-seconds", "counter", "Estimated CPU time spent on garbage collection."},
	{"go_cpu_user_seconds_total", "/cpu/classes/user:cpu-seconds", "counter", "Estimated CPU time spent running Go code."},
	{"go_cpu_scavenge_seconds_total", "/cpu/classes/scavenge/total:cpu-seconds", "counter", "Estimated CPU time spent returning memory to the OS."},
	{"go_cpu_idle_seconds_total", "/cpu/classes/idle:cpu-seconds", "counter", "Estimated CPU time available to Go but unused."},
	{"go_mutex_wait_seconds_total", "/sync/mutex/wait/total:seconds", "counter", "Time goroutines spent blocked on sync.Mutex and sync.RWMutex."},
	{"go_heap_allocs_bytes_total", "/gc/heap/allocs:bytes", "counter", "Bytes allocated on the heap."},
	{"go_heap_live_bytes", "/gc/heap/live:bytes", "gauge", "Heap bytes live after the last garbage collection."},
	{"go_heap_goal_bytes", "/gc/heap/goal:bytes", "gauge", "Heap size the next garbage collection aims for."},
	{"go_memory_bytes", "/memory/classes/total:bytes", "gauge", "Memory mapped by the Go runtime."},
	{"go_gc_cycles_total", "/gc/cycles/total:gc-cycles", "counter", "Completed garbage collection cycles."},
	{"go_goroutines", "/sched/goroutines:goroutines", "gauge", "Live goroutines."},
	{"go_threads", "/sched/threads/total:threads", "gauge", "OS threads the runtime owns."},
	{"go_gomaxprocs", "/sched/gomaxprocs:threads", "gauge", "GOMAXPROCS."},
	{"go_gogc_percent", "/gc/gogc:percent", "gauge", "GOGC."},
	{"go_gomemlimit_bytes", "/gc/gomemlimit:bytes", "gauge", "GOMEMLIMIT."},
}

// runtimeBuckets regroup the runtime's fine-grained time histograms, in seconds.
var runtimeBuckets = []float64{1e-6, 10e-6, 100e-6, 1e-3, 10e-3, 100e-3, 1}

func writeRuntimeMetrics(p promWriter) {
	samples := make([]metrics.Sample, len(runtimeMetrics))
	for i, m := range runtimeMetrics {
		samples[i].Name = m.runtime
	}
	metrics.Read(samples)
	for i, m := range runtimeMetrics {
		v := samples[i].Value
		switch v.Kind() {
		case metrics.KindUint64:
			p.single(m.name, m.kind, m.help, v.Uint64())
		case metrics.KindFloat64:
			p.header(m.name, m.kind, m.help)
			p.float(m.name, "", v.Float64())
		case metrics.KindFloat64Histogram:
			writeRuntimeHistogram(p, m.name, m.help, v.Float64Histogram())
		}
	}
}

// writeRuntimeHistogram writes a runtime histogram regrouped into
// runtimeBuckets. A runtime bucket counts toward the first bound at or above
// its upper edge. The runtime keeps no sum, so it's estimated from bucket
// midpoints.
func writeRuntimeHistogram(p promWriter, name, help string, h *metrics.Float64Histogram) {
	p.header(name, "histogram", help)
	var count uint64
	var sum float64
	b := 0
	add := func() {
		lo, hi := h.Buckets[b], h.Buckets[b+1]
		mid := (lo + hi) / 2
		if math.IsInf(lo, 0) {
			mid = hi
		} else if math.IsInf(hi, 0) {
			mid = lo
		}
		count += h.Counts[b]
		sum += float64(h.Counts[b]) * mid
		b++
	}
	for _, bound := range runtimeBuckets {
		for b < len(h.Counts) && h.Buckets[b+1] <= bound {
			add()
		}
		p.value(name+"_bucket", `le="`+formatFloat(bound)+`"`, count)
	}
	for b < len(h.Counts) {
		add()
	}
	p.value(name+"_bucket", `le="+Inf"`, count)
	p.float(name+"_sum", "", sum)
	p.value(name+"_count", "", count)
}
