package server

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/clientip"
	"github.com/klipitkas/tunnl.gg/pkg/config"
)

// testTunnel is a tunnel created by a real SSH client through HandleSSHConnection.
// Public traffic is sent to public, which serves the Server's HTTPS handler.
type testTunnel struct {
	srv    *Server
	sub    string
	client *ssh.Client
	public *httptest.Server
	local  *httptest.Server // the tunneled app
	output *syncBuffer      // SSH session output (banner and request logs)
	stdin  io.WriteCloser   // SSH session input, as typed by the user
}

// syncBuffer is a bytes.Buffer safe for concurrent use.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var publicURLPattern = regexp.MustCompile(`https://([a-z]+-[a-z]+-[0-9a-f]{8})\.`)

// startSSHServer starts a server accepting SSH connections and returns its address.
func startSSHServer(t *testing.T) (*Server, string) {
	t.Helper()
	srv := newTestServer(t)

	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error: %v", err)
	}
	t.Cleanup(func() { sshLn.Close() })
	go func() {
		for {
			conn, err := sshLn.Accept()
			if err != nil {
				return
			}
			go srv.HandleSSHConnection(conn)
		}
	}()
	return srv, sshLn.Addr().String()
}

// anonymousClient is how most clients connect: no key, any username.
func anonymousClient() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
}

// stableClient connects as the stable user with key.
func stableClient(key ssh.Signer) *ssh.ClientConfig {
	cfg := anonymousClient()
	cfg.User = config.StableSSHUser
	cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(key)}
	return cfg
}

func dialSSH(addr string) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, anonymousClient())
}

// startTestTunnel starts a server, connects an SSH client that forwards
// tunnel traffic to backend, and waits for the tunnel to go live.
func startTestTunnel(t *testing.T, backend http.Handler) *testTunnel {
	t.Helper()
	srv, addr := startSSHServer(t)
	return openTunnel(t, srv, addr, anonymousClient(), backend)
}

// openTunnel connects an SSH client to the server at addr with clientConfig,
// forwards tunnel traffic to backend, and waits for the tunnel to go live.
func openTunnel(t *testing.T, srv *Server, addr string, clientConfig *ssh.ClientConfig, backend http.Handler) *testTunnel {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		t.Fatalf("ssh.Dial() error: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	// Equivalent of: ssh -R 80:localhost:<backend port>. Like the ssh client,
	// relay each forwarded channel to a real local TCP server.
	local := httptest.NewServer(backend)
	t.Cleanup(local.Close)
	forwarded, err := client.Listen("tcp", "0.0.0.0:80")
	if err != nil {
		t.Fatalf("client.Listen() error: %v", err)
	}
	go func() {
		for {
			ch, err := forwarded.Accept()
			if err != nil {
				return
			}
			go relayToLocal(ch, local.Listener.Addr().String())
		}
	}()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe() error: %v", err)
	}
	// Keep stdin open like an interactive `ssh -t`; the server treats EOF on
	// stdin as the user disconnecting.
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe() error: %v", err)
	}
	t.Cleanup(func() { stdin.Close() })
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty() error: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Shell() error: %v", err)
	}

	output := &syncBuffer{}
	go io.Copy(output, stdout)

	var sub string
	waitFor(t, "tunnel banner with public URL", func() bool {
		m := publicURLPattern.FindStringSubmatch(output.String())
		if m != nil {
			sub = m[1]
		}
		return m != nil
	})

	public := httptest.NewServer(srv)
	t.Cleanup(public.Close)

	return &testTunnel{srv: srv, sub: sub, client: client, public: public, output: output, stdin: stdin, local: local}
}

// relayToLocal copies a forwarded SSH channel to and from a local TCP server.
func relayToLocal(ch net.Conn, addr string) {
	defer ch.Close()
	local, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer local.Close()
	go func() {
		io.Copy(local, ch)
		local.(*net.TCPConn).CloseWrite()
	}()
	io.Copy(ch, local)
}

func (tt *testTunnel) host() string {
	return tt.sub + "." + config.DefaultDomain
}

// get sends a GET request for path through the tunnel's public URL.
func (tt *testTunnel) get(t *testing.T, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, tt.public.URL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	req.Host = tt.host()
	resp, err := tt.public.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s error: %v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// dialWebSocket opens a raw connection to the public server and completes
// a WebSocket upgrade handshake for path.
func (tt *testTunnel) dialWebSocket(t *testing.T, path string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, br, status := tt.tryWebSocket(t, path)
	if status != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d, want %d", status, http.StatusSwitchingProtocols)
	}
	return conn, br
}

// tryWebSocket attempts a WebSocket upgrade for path and returns the response status.
func (tt *testTunnel) tryWebSocket(t *testing.T, path string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	conn, err := net.Dial("tcp", tt.public.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", path, tt.host())

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse() error: %v", err)
	}
	return conn, br, resp.StatusCode
}

// echoWebSocketBackend completes the upgrade and echoes every byte back.
func echoWebSocketBackend(w http.ResponseWriter, r *http.Request) {
	conn, brw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	brw.Flush()
	io.Copy(conn, brw)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestE2E_HTTPRequestThroughTunnel(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s host=%s", r.Method, r.URL.Path, r.Host)
	}))

	resp := tt.get(t, "/hello")
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if want := "GET /hello host=" + tt.host(); string(body) != want {
		t.Errorf("body = %q, want %q", body, want)
	}
	if !strings.Contains(tt.output.String(), qrColors) {
		t.Error("SSH session banner should include a QR code of the URL")
	}
	waitFor(t, "request log line in SSH session", func() bool {
		return bytes.Contains([]byte(tt.output.String()), []byte("/hello"))
	})
}

func TestE2E_WebSocketThroughTunnel(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(echoWebSocketBackend))

	conn, br := tt.dialWebSocket(t, "/ws")
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("ReadFull() error: %v", err)
	}
	if string(got) != "ping" {
		t.Errorf("echo = %q, want %q", got, "ping")
	}
}

func TestE2E_DisconnectRemovesTunnel(t *testing.T) {
	tt := startTestTunnel(t, http.NotFoundHandler())

	if tt.srv.GetTunnel(tt.sub) == nil {
		t.Fatal("tunnel should be registered while the SSH client is connected")
	}

	tt.client.Close()

	waitFor(t, "tunnel cleanup after disconnect", func() bool {
		stats := tt.srv.GetStats(false)
		return tt.srv.GetTunnel(tt.sub) == nil && stats.ActiveTunnels == 0 && stats.UniqueIPs == 0
	})
	if resp := tt.get(t, "/"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("status after disconnect = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestE2E_WebSocketDataSentWithUpgradeRequest(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(echoWebSocketBackend))

	conn, err := net.Dial("tcp", tt.public.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Clients may send their first frame without waiting for the 101
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nping", tt.host())

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse() error: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d, want %d", resp.StatusCode, http.StatusSwitchingProtocols)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("ReadFull() error: %v (data sent with the upgrade request was lost)", err)
	}
	if string(got) != "ping" {
		t.Errorf("echo = %q, want %q", got, "ping")
	}
}

func TestE2E_WebSocketLimitPerVisitor(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(echoWebSocketBackend))

	conns := make([]net.Conn, 0, config.MaxWebSocketsPerVisitor)
	for i := 0; i < config.MaxWebSocketsPerVisitor; i++ {
		conn, _ := tt.dialWebSocket(t, "/ws")
		conns = append(conns, conn)
	}
	if got := tt.srv.GetStats(false).ActiveWebSockets; got != config.MaxWebSocketsPerVisitor {
		t.Errorf("active_websockets = %d, want %d", got, config.MaxWebSocketsPerVisitor)
	}

	if _, _, status := tt.tryWebSocket(t, "/ws"); status != http.StatusTooManyRequests {
		t.Fatalf("upgrade over the limit: status = %d, want %d", status, http.StatusTooManyRequests)
	}

	// Closing a WebSocket frees its slot
	conns[0].Close()
	waitFor(t, "WebSocket slot to be released", func() bool {
		return tt.srv.GetStats(false).ActiveWebSockets == config.MaxWebSocketsPerVisitor-1
	})
	tt.dialWebSocket(t, "/ws")
}

// withTimeouts returns a public server for tt with short server-wide
// read and write timeouts, standing in for the production HTTPS timeouts.
func (tt *testTunnel) withTimeouts(t *testing.T, timeout time.Duration) *httptest.Server {
	t.Helper()
	public := httptest.NewUnstartedServer(tt.srv)
	public.Config.ReadTimeout = timeout
	public.Config.WriteTimeout = timeout
	public.Start()
	t.Cleanup(public.Close)
	return public
}

func TestE2E_StreamingResponseOutlivesServerWriteTimeout(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Long poll: wait before responding, then stream chunks
		time.Sleep(400 * time.Millisecond)
		for i := 0; i < 5; i++ {
			fmt.Fprintf(w, "chunk%d\n", i)
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}))
	public := tt.withTimeouts(t, 300*time.Millisecond)

	req, _ := http.NewRequest(http.MethodGet, public.URL+"/stream", nil)
	req.Host = tt.host()
	resp, err := public.Client().Do(req)
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading streamed body: %v (got %q)", err, body)
	}
	if want := "chunk0\nchunk1\nchunk2\nchunk3\nchunk4\n"; string(body) != want {
		t.Errorf("body = %q, want %q", body, want)
	}
}

func TestE2E_SlowUploadOutlivesServerReadTimeout(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprintf(w, "%d", n)
	}))
	public := tt.withTimeouts(t, 300*time.Millisecond)

	pr, pw := io.Pipe()
	go func() {
		for i := 0; i < 5; i++ {
			pw.Write(bytes.Repeat([]byte("x"), 1000))
			time.Sleep(100 * time.Millisecond)
		}
		pw.Close()
	}()

	req, _ := http.NewRequest(http.MethodPost, public.URL+"/upload", pr)
	req.Host = tt.host()
	resp, err := public.Client().Do(req)
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "5000" {
		t.Errorf("backend received %q bytes, want 5000 (status %d)", body, resp.StatusCode)
	}
}

func TestE2E_BlockedIPDroppedBeforeHandshake(t *testing.T) {
	srv, addr := startSSHServer(t)
	srv.abuseTracker.BlockIP("127.0.0.1")

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// The server closes the connection without sending its SSH version banner
	n, err := conn.Read(make([]byte, 64))
	if n != 0 || err != io.EOF {
		t.Errorf("Read() = %d, %v; want connection closed before the handshake", n, err)
	}
}

func TestE2E_ConcurrentHandshakesPerIPLimited(t *testing.T) {
	_, addr := startSSHServer(t)

	// Hold handshakes open by connecting and never sending anything
	stalled := make([]net.Conn, 0, config.MaxHandshakesPerIP)
	for i := 0; i < config.MaxHandshakesPerIP; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("Dial() error: %v", err)
		}
		defer conn.Close()
		stalled = append(stalled, conn)
	}
	// Wait until the server has started every stalled handshake
	for _, conn := range stalled {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
			t.Fatalf("reading server version: %v", err)
		}
	}

	if client, err := dialSSH(addr); err == nil {
		client.Close()
		t.Fatal("SSH connection over the handshake limit should be rejected")
	}

	stalled[0].Close()
	waitFor(t, "handshake slot to be released", func() bool {
		client, err := dialSSH(addr)
		if err == nil {
			client.Close()
		}
		return err == nil
	})
}

func TestE2E_ProxiedResponseKeepsAppHeaders(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/embeddable" {
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Header().Set("X-Content-Type-Options", "nosniff")
		}
	}))

	resp := tt.get(t, "/embeddable")
	if got := resp.Header.Values("X-Frame-Options"); len(got) != 1 || got[0] != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options = %q, want only the app's SAMEORIGIN", got)
	}
	if got := resp.Header.Values("X-Content-Type-Options"); len(got) != 1 {
		t.Errorf("X-Content-Type-Options = %q, want a single value", got)
	}

	resp = tt.get(t, "/plain")
	if got := resp.Header.Get("X-Frame-Options"); got != "" {
		t.Errorf("X-Frame-Options = %q, want none so the app can be embedded", got)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want default nosniff", got)
	}
	if got := resp.Header.Get("X-Xss-Protection"); got != "" {
		t.Errorf("X-XSS-Protection = %q, want none (deprecated)", got)
	}
}

func TestE2E_ServerErrorsKeepSecurityHeaders(t *testing.T) {
	tt := startTestTunnel(t, http.NotFoundHandler())

	req, _ := http.NewRequest(http.MethodGet, tt.public.URL+"/", nil)
	req.Host = "calm-eagle-00000000." + config.DefaultDomain // no such tunnel
	resp, err := tt.public.Client().Do(req)
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options on server error = %q, want DENY", got)
	}
}

func TestE2E_ForwardedHeaders(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "for=%s host=%s proto=%s",
			r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-Forwarded-Proto"))
	}))

	req, _ := http.NewRequest(http.MethodGet, tt.public.URL+"/", nil)
	req.Host = tt.host()
	req.Header.Set("X-Forwarded-For", "203.0.113.66") // spoofed by the visitor
	resp, err := tt.public.Client().Do(req)
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// The test server is plain HTTP; production terminates TLS, giving https
	if want := "for=127.0.0.1 host=" + tt.host() + " proto=http"; string(body) != want {
		t.Errorf("backend saw %q, want %q", body, want)
	}
}

// serveDirect sends a request straight to the server's handler as if it came
// from peer remoteAddr, and returns the response.
func (tt *testTunnel) serveDirect(remoteAddr string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "https://"+tt.host()+"/", nil)
	req.RemoteAddr = remoteAddr
	req.Header.Set("User-Agent", "curl/8.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	tt.srv.ServeHTTP(rec, req)
	return rec
}

// echoClientHeaders reports the client identity headers the app receives.
func echoClientHeaders(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "for=%s cf=%s", r.Header.Get("X-Forwarded-For"), r.Header.Get("CF-Connecting-IP"))
}

func TestE2E_DirectDeploymentIgnoresClientIPHeaders(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(echoClientHeaders))

	rec := tt.serveDirect("203.0.113.7:4321", map[string]string{
		"CF-Connecting-IP": "6.6.6.6",
		"X-Forwarded-For":  "6.6.6.6",
	})
	if want := "for=203.0.113.7 cf="; rec.Body.String() != want {
		t.Errorf("app saw %q, want %q (spoofed headers dropped)", rec.Body.String(), want)
	}
}

func TestE2E_CloudflareVisitorResolved(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(echoClientHeaders))
	resolver, _ := clientip.Parse("cloudflare")
	tt.srv.SetTrustedProxies(resolver)

	rec := tt.serveDirect("173.245.48.10:443", map[string]string{"CF-Connecting-IP": "198.51.100.9"})
	if want := "for=198.51.100.9 cf=198.51.100.9"; rec.Body.String() != want {
		t.Errorf("app saw %q, want %q", rec.Body.String(), want)
	}

	// Connecting to the origin directly can't claim to be Cloudflare
	rec = tt.serveDirect("203.0.113.7:4321", map[string]string{"CF-Connecting-IP": "6.6.6.6"})
	if want := "for=203.0.113.7 cf="; rec.Body.String() != want {
		t.Errorf("direct request: app saw %q, want %q", rec.Body.String(), want)
	}
}

func TestE2E_CloudflareVisitorsRateLimitedSeparately(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	resolver, _ := clientip.Parse("cloudflare")
	tt.srv.SetTrustedProxies(resolver)

	// Two visitors reach the origin through the same Cloudflare edge IP
	const edge = "173.245.48.10:443"
	limited := false
	for i := 0; i < config.VisitorBurstSize*2 && !limited; i++ {
		limited = tt.serveDirect(edge, map[string]string{"CF-Connecting-IP": "198.51.100.1"}).Code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("flooding visitor should be rate limited")
	}
	if code := tt.serveDirect(edge, map[string]string{"CF-Connecting-IP": "198.51.100.2"}).Code; code != http.StatusOK {
		t.Errorf("other visitor behind the same edge got %d, want %d", code, http.StatusOK)
	}
}

func TestE2E_OnPremProxyVisitorResolved(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(echoClientHeaders))
	resolver, _ := clientip.Parse("10.0.0.0/8")
	tt.srv.SetTrustedProxies(resolver)

	rec := tt.serveDirect("10.0.0.5:51000", map[string]string{
		"X-Forwarded-For":  "6.6.6.6, 198.51.100.9",
		"CF-Connecting-IP": "6.6.6.6",
	})
	if want := "for=198.51.100.9 cf="; rec.Body.String() != want {
		t.Errorf("app saw %q, want %q", rec.Body.String(), want)
	}
}

func TestE2E_WebSocketForwardedHeaders(t *testing.T) {
	seen := make(chan string, 1)
	tt := startTestTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- fmt.Sprintf("for=%s host=%s proto=%s cf=%s", r.Header.Get("X-Forwarded-For"),
			r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-Forwarded-Proto"), r.Header.Get("CF-Connecting-IP"))
		echoWebSocketBackend(w, r)
	}))

	conn, err := net.Dial("tcp", tt.public.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"X-Forwarded-For: 6.6.6.6\r\nCF-Connecting-IP: 6.6.6.6\r\n\r\n", tt.host())

	if got, want := <-seen, "for=127.0.0.1 host="+tt.host()+" proto=http cf="; got != want {
		t.Errorf("app saw %q on the upgrade, want %q", got, want)
	}
}

func TestE2E_UnansweredChannelOpensAreBounded(t *testing.T) {
	srv, addr := startSSHServer(t)
	client, err := dialSSH(addr)
	if err != nil {
		t.Fatalf("ssh.Dial() error: %v", err)
	}

	// A malicious client: registers a tunnel but never answers channel opens
	var mu sync.Mutex
	var held []ssh.NewChannel
	opens := client.HandleChannelOpen("forwarded-tcpip")
	go func() {
		for nc := range opens {
			mu.Lock()
			held = append(held, nc)
			mu.Unlock()
		}
	}()
	pending := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(held)
	}
	if ok, _, err := client.SendRequest("tcpip-forward", true, ssh.Marshal(&tcpipForwardRequest{BindAddr: "0.0.0.0", BindPort: 80})); err != nil || !ok {
		t.Fatalf("tcpip-forward: ok=%v err=%v", ok, err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}
	stdin, _ := session.StdinPipe()
	defer stdin.Close()
	stdout, _ := session.StdoutPipe()
	session.RequestPty("xterm", 24, 80, ssh.TerminalModes{})
	session.Shell()
	output := &syncBuffer{}
	go io.Copy(output, stdout)
	var sub string
	waitFor(t, "tunnel banner", func() bool {
		if m := publicURLPattern.FindStringSubmatch(output.String()); m != nil {
			sub = m[1]
		}
		return sub != ""
	})

	request := func(ctx context.Context) int {
		req := httptest.NewRequest(http.MethodGet, "https://"+sub+"."+config.DefaultDomain+"/", nil)
		req = req.WithContext(ctx)
		req.RemoteAddr = "198.51.100.1:1234"
		req.Header.Set("User-Agent", "curl/8.0")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec.Code
	}

	// Take every slot with requests whose channel opens go unanswered
	var wg sync.WaitGroup
	for i := 0; i < config.MaxPendingChannelOpens; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request(context.Background())
		}()
	}
	waitFor(t, "all channel opens to reach the client", func() bool {
		return pending() == config.MaxPendingChannelOpens
	})

	// Another request waits for a slot until it gives up, without opening a
	// channel the client would also ignore
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if code := request(ctx); code != http.StatusBadGateway {
		t.Errorf("request over the pending limit: status %d, want %d", code, http.StatusBadGateway)
	}
	if got := pending(); got != config.MaxPendingChannelOpens {
		t.Errorf("client received %d channel opens, want at most %d", got, config.MaxPendingChannelOpens)
	}

	// Disconnecting releases everything
	client.Close()
	wg.Wait()
}

func TestE2E_InFlightRequestsCapped(t *testing.T) {
	arrived := make(chan struct{}, 16)
	release := make(chan struct{})
	tt := startTestTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-release // an app that holds requests open
	}))
	tt.srv.reqPerVisitor = newConnLimiter(2)
	tt.srv.reqPerTunnel = newConnLimiter(3)

	codes := make(chan int, 16)
	hold := func(remoteAddr string) {
		go func() { codes <- tt.serveDirect(remoteAddr, nil).Code }()
		<-arrived
	}
	hold("198.51.100.1:1000")
	hold("198.51.100.1:1001")

	if code := tt.serveDirect("198.51.100.1:1002", nil).Code; code != http.StatusTooManyRequests {
		t.Errorf("visitor over its in-flight limit: status %d, want %d", code, http.StatusTooManyRequests)
	}
	hold("198.51.100.2:1000") // another visitor still gets through
	if got := tt.srv.GetStats(false).ActiveRequests; got != 3 {
		t.Errorf("active_requests = %d, want 3", got)
	}
	if code := tt.serveDirect("198.51.100.3:1000", nil).Code; code != http.StatusServiceUnavailable {
		t.Errorf("tunnel over its in-flight limit: status %d, want %d", code, http.StatusServiceUnavailable)
	}

	close(release)
	for i := 0; i < 3; i++ {
		if code := <-codes; code != http.StatusOK {
			t.Errorf("held request finished with %d, want %d", code, http.StatusOK)
		}
	}
	if code := tt.serveDirect("198.51.100.1:1003", nil).Code; code != http.StatusOK {
		t.Errorf("request after the others finished: status %d, want %d", code, http.StatusOK)
	}
}

func TestE2E_ConcurrentBurstSucceeds(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond) // slow enough for requests to overlap
		fmt.Fprint(w, "ok")
	}))

	// More concurrent requests than there are channel open slots, from
	// different visitors so rate limits don't apply
	const n = 3 * config.MaxPendingChannelOpens
	codes := make(chan int, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			codes <- tt.serveDirect(fmt.Sprintf("198.51.100.%d:1000", i), nil).Code
		}(i)
	}
	failed := map[int]int{}
	for i := 0; i < n; i++ {
		if code := <-codes; code != http.StatusOK {
			failed[code]++
		}
	}
	if len(failed) > 0 {
		t.Errorf("burst of %d concurrent requests: non-200 responses %v, want none", n, failed)
	}
}

func TestE2E_ExtraChannelOpensRejected(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))

	// More opens than the SSH library queues, like ControlMaster sessions or
	// -L forwards: each must be answered, not left to stall the connection
	for i := 0; i < 20; i++ {
		kind := "direct-tcpip"
		if i%2 == 0 {
			kind = "session"
		}
		opened := make(chan error, 1)
		go func() {
			_, _, err := tt.client.OpenChannel(kind, nil)
			opened <- err
		}()
		select {
		case err := <-opened:
			if err == nil {
				t.Fatalf("open %d (%s) was accepted, want rejected", i, kind)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("open %d (%s) was never answered", i, kind)
		}
	}

	if resp := tt.get(t, "/"); resp.StatusCode != http.StatusOK {
		t.Errorf("tunnel status after extra opens = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
