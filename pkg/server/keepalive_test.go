package server

import (
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// freezableProxy relays TCP connections to an address until frozen, then
// stops reading either side without closing anything: like a client whose
// network vanished, or whose kernel still holds the connection while its ssh
// stopped reading. Nothing more reaches the server, and the server's writes
// back up.
type freezableProxy struct {
	addr   string
	ln     net.Listener
	frozen chan struct{}
	once   sync.Once
	mu     sync.Mutex
	conns  []net.Conn
}

func startFreezableProxy(t *testing.T, target string) *freezableProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error: %v", err)
	}
	p := &freezableProxy{addr: ln.Addr().String(), ln: ln, frozen: make(chan struct{})}
	t.Cleanup(p.close)
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			server, err := net.Dial("tcp", target)
			if err != nil {
				client.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, client, server)
			p.mu.Unlock()
			go p.relay(server, client)
			go p.relay(client, server)
		}
	}()
	return p
}

// close closes the listener and every relayed connection, both ends.
func (p *freezableProxy) close() {
	p.ln.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
}

func (p *freezableProxy) relay(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		select {
		case <-p.frozen:
			return // drop what was read, and read no more
		default:
		}
		if n > 0 {
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (p *freezableProxy) freeze() {
	p.once.Do(func() { close(p.frozen) })
}

// zeros reads as an endless stream of zero bytes.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestKeepAlive_KeepsQuietClient(t *testing.T) {
	srv := newTestServer(t)
	srv.keepAliveInterval, srv.keepAliveTimeout = 30*time.Millisecond, 150*time.Millisecond
	tt := openTunnel(t, srv, serveSSH(t, srv), anonymousClient(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))

	// Quiet for many timeouts: the client's answers to keepalives keep it
	time.Sleep(600 * time.Millisecond)
	if srv.GetTunnel(tt.sub) == nil {
		t.Fatal("tunnel closed although its client answered keepalives")
	}
	if got := srv.metrics.keepAliveCloses.Load(); got != 0 {
		t.Errorf("keepalive closes = %d, want 0", got)
	}
	if resp := tt.get(t, "/"); resp.StatusCode != http.StatusOK {
		t.Errorf("status after a quiet spell = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestKeepAlive_ClosesClientThatStopsResponding(t *testing.T) {
	srv := newTestServer(t)
	srv.keepAliveInterval, srv.keepAliveTimeout = 50*time.Millisecond, 300*time.Millisecond
	proxy := startFreezableProxy(t, serveSSH(t, srv))
	var received atomic.Int64
	tt := openTunnel(t, srv, proxy.addr, anonymousClient(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Body.Read(buf)
			received.Add(int64(n))
			if err != nil {
				return
			}
		}
	}))
	// The frozen client never learns that its connection closed, so its
	// forwarded channel would keep the app waiting for the rest of the upload.
	// Without the fix, the server's write to it stays stuck too. Close both
	// before the test servers wait for their handlers: cleanups run last first.
	t.Cleanup(func() {
		tt.client.Close()
		proxy.close()
	})

	// An upload is on its way to the client when it stops responding
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, err := http.NewRequest(http.MethodPost, tt.public.URL+"/upload", io.LimitReader(zeros{}, 1<<30))
		if err != nil {
			return
		}
		req.Host = tt.host()
		if resp, err := tt.public.Client().Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	waitFor(t, "the upload to reach the app", func() bool { return received.Load() > 1<<20 })
	proxy.freeze()

	// The connection closes once nothing has come from the client for the
	// timeout, which ends the upload stuck writing to it
	start := time.Now()
	waitFor(t, "the tunnel to close", func() bool { return srv.GetTunnel(tt.sub) == nil })
	if took := time.Since(start); took < 250*time.Millisecond {
		t.Errorf("tunnel closed %v after the client froze, before the 300ms timeout", took)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("upload still running after its connection closed")
	}
	if got := srv.metrics.keepAliveCloses.Load(); got != 1 {
		t.Errorf("keepalive closes = %d, want 1", got)
	}
}
