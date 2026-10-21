package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// reuseOpener adds a controlled channel-open delay, not a simulated WAN:
// payloads still travel over loopback without delay. Its observer is the same
// interface used by the production channel-close metrics.
type reuseOpener struct {
	ChannelOpener
	delay       time.Duration
	opens       atomic.Int64
	closedByApp atomic.Int64
	closedHere  atomic.Int64
}

func (o *reuseOpener) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	o.opens.Add(1)
	if o.delay > 0 {
		time.Sleep(o.delay)
	}
	return o.ChannelOpener.OpenChannel(name, data)
}

func (o *reuseOpener) PooledChannelClosed(byApp bool, _ time.Duration) {
	if byApp {
		o.closedByApp.Add(1)
	} else {
		o.closedHere.Add(1)
	}
}

type reuseFixture struct {
	tun     *Tunnel
	opener  *reuseOpener
	backend *httptest.Server
	client  *http.Client
	live    atomic.Int64
	used    atomic.Int64
	full    atomic.Int64
}

func newReuseFixture(t *testing.T, pool int, openDelay, responseDelay, appIdle time.Duration, beforeResponse func()) *reuseFixture {
	t.Helper()
	f := &reuseFixture{}
	f.backend = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if beforeResponse != nil {
			beforeResponse()
		}
		time.Sleep(responseDelay)
		io.WriteString(w, r.URL.Path)
	}))
	f.backend.Config.IdleTimeout = appIdle
	f.backend.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			f.live.Add(1)
		case http.StateClosed:
			f.live.Add(-1)
		}
	}
	f.backend.Start()
	t.Cleanup(f.backend.Close)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	type accepted struct {
		conn *ssh.ServerConn
		err  error
	}
	ready := make(chan accepted, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ready <- accepted{err: err}
			return
		}
		sc, channels, requests, err := ssh.NewServerConn(conn, cfg)
		ready <- accepted{sc, err}
		if err != nil {
			conn.Close()
			return
		}
		go func() {
			for ch := range channels {
				ch.Reject(ssh.UnknownChannelType, "forwarding fixture only")
			}
		}()
		for req := range requests {
			req.Reply(req.Type == "tcpip-forward" || req.Type == "cancel-tcpip-forward", nil)
		}
	}()
	sshClient, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User: "test", HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sshClient.Close() })
	sc := <-ready
	if sc.err != nil {
		t.Fatal(sc.err)
	}
	t.Cleanup(func() { sc.conn.Close() })
	forwarded, err := sshClient.Listen("tcp", "127.0.0.1:80")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { forwarded.Close() })
	go func() {
		for {
			ch, err := forwarded.Accept()
			if err != nil {
				return
			}
			go func() {
				defer ch.Close()
				local, err := net.DialTimeout("tcp", f.backend.Listener.Addr().String(), 5*time.Second)
				if err != nil {
					return
				}
				defer local.Close()
				go func() {
					io.Copy(local, ch)
					local.(*net.TCPConn).CloseWrite()
				}()
				io.Copy(ch, local)
			}()
		}
	}()
	f.opener = &reuseOpener{ChannelOpener: sc.conn, delay: openDelay}
	f.tun = New("reuse", f.opener, "127.0.0.1", 80, "127.0.0.1")
	t.Cleanup(f.tun.Close)
	if pool > 0 {
		f.tun.Transport().MaxIdleConns = pool
		f.tun.Transport().MaxIdleConnsPerHost = pool
	}
	f.client = &http.Client{Transport: f.tun.Transport(), Timeout: 5 * time.Second}
	return f
}

func (f *reuseFixture) burst(t *testing.T, n int) []time.Duration {
	t.Helper()
	latencies := make([]time.Duration, n)
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start
			now := time.Now()
			path := fmt.Sprintf("/request-%d", i)
			trace := &httptrace.ClientTrace{
				GotConn: func(info httptrace.GotConnInfo) {
					if info.Reused {
						f.used.Add(1)
					}
				},
				PutIdleConn: func(err error) {
					if err != nil && strings.Contains(err.Error(), "too many idle connections") {
						f.full.Add(1)
					}
				},
			}
			req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, "http://reuse.tunnl.gg"+path, nil)
			if err != nil {
				errs[i] = err
				return
			}
			resp, err := f.client.Do(req)
			if err != nil {
				errs[i] = err
				return
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK || string(body) != path {
				errs[i] = fmt.Errorf("response: %d %q %v", resp.StatusCode, body, err)
			}
			latencies[i] = time.Since(now)
		})
	}
	close(start)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	return latencies
}

func waitReuse(t *testing.T, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for " + what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTransportRetainsBurstChannels(t *testing.T) {
	for _, concurrency := range []int{8, 24, 40} {
		t.Run(fmt.Sprint(concurrency), func(t *testing.T) {
			arrived := make(chan struct{}, concurrency)
			release := make(chan struct{})
			f := newReuseFixture(t, 0, 0, 0, 0, func() {
				select {
				case arrived <- struct{}{}:
				default:
				}
				<-release
			})
			// Hold the first responses until all requests reach the backend:
			// concurrency is deterministic, rather than based on a sleep.
			allArrived := make(chan bool, 1)
			go func() {
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				defer close(release)
				for range concurrency {
					select {
					case <-arrived:
					case <-timer.C:
						allArrived <- false
						return
					}
				}
				allArrived <- true
			}()
			f.burst(t, concurrency)
			if !<-allArrived {
				t.Fatal("requests could not reach the backend concurrently")
			}
			wantIdle := int64(min(concurrency, maxIdleChannelsPerTunnel))
			waitReuse(t, "bounded idle pool", func() bool { return f.live.Load() == wantIdle })
			if got := f.opener.opens.Load(); got != int64(concurrency) {
				t.Fatalf("warmup opened %d channels, want %d", got, concurrency)
			}
			if concurrency <= maxIdleChannelsPerTunnel {
				f.used.Store(0)
				f.burst(t, concurrency)
				waitReuse(t, "finished opens", func() bool { return f.tun.PendingOpens() == 0 })
				if got := f.opener.opens.Load(); got != int64(concurrency) {
					t.Fatalf("warm burst opened extra channels: total=%d, want %d", got, concurrency)
				}
				if got := f.used.Load(); got != int64(concurrency) {
					t.Fatalf("reused %d channels, want %d", got, concurrency)
				}
			}
			f.tun.Close()
			waitReuse(t, "closed channels", func() bool { return f.live.Load() == 0 })
		})
	}
}

func TestTransportExpiresIdleChannels(t *testing.T) {
	f := newReuseFixture(t, 0, 0, 0, 0, nil)
	f.tun.Transport().IdleConnTimeout = 20 * time.Millisecond
	f.burst(t, 1)
	waitReuse(t, "pool idle timeout", func() bool { return f.opener.closedHere.Load() == 1 && f.live.Load() == 0 })
	f.burst(t, 1)
	if got := f.opener.opens.Load(); got != 2 {
		t.Fatalf("opened %d channels after expiry, want 2", got)
	}
}

// Opt-in comparison: real SSH channels and TCP backends, no public handler,
// TLS, request logger or admission limits. Retained heap and goroutines include
// the client and backend too. Pool sizes are varied within the same binary.
func TestChannelReusePerformance(t *testing.T) {
	if os.Getenv("TUNNL_REUSE_PERF") != "1" {
		t.Skip("set TUNNL_REUSE_PERF=1 to compare channel pools")
	}
	pools := []int{10, 16, 32}
	if os.Getenv("TUNNL_REUSE_REVERSE") == "1" {
		slices.Reverse(pools)
	}
	for _, scenario := range []struct {
		name        string
		concurrency int
		appIdle     time.Duration
	}{
		{"LowConcurrency", 8, 0},
		{"Burst32", 32, 0},
		{"AppCloses", 32, 30 * time.Millisecond},
	} {
		for _, pool := range pools {
			t.Run(fmt.Sprintf("%s/pool%d", scenario.name, pool), func(t *testing.T) {
				runtime.GC()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				goroutines := runtime.NumGoroutine()
				f := newReuseFixture(t, pool, 130*time.Millisecond, 50*time.Millisecond, scenario.appIdle, nil)
				f.burst(t, scenario.concurrency)
				// Let unused dials finish and excess channels close before
				// the next burst, as between browser page loads.
				settle := func() {
					waitReuse(t, "channel opens", func() bool { return f.tun.PendingOpens() == 0 })
					time.Sleep(60 * time.Millisecond)
					if scenario.appIdle > 0 {
						waitReuse(t, "backend idle closes", func() bool { return f.live.Load() == 0 })
					}
				}
				settle()
				opens, app, here := f.opener.opens.Load(), f.opener.closedByApp.Load(), f.opener.closedHere.Load()
				f.used.Store(0)
				f.full.Store(0)
				var latencies []time.Duration
				for range 4 {
					latencies = append(latencies, f.burst(t, scenario.concurrency)...)
					settle()
				}
				runtime.GC()
				runtime.ReadMemStats(&after)
				slices.Sort(latencies)
				n := len(latencies)
				fmt.Printf("BenchmarkChannelReuse/%s/pool%d %d %.0f p50-ns %.0f p95-ns %.0f p99-ns %d opens %d reused %d pool-rejections %d relay-closes %d app-closes %d live-channels %d retained-B %d goroutines\n",
					scenario.name, pool, n, float64(latencies[n/2]), float64(latencies[n*95/100]), float64(latencies[n*99/100]),
					f.opener.opens.Load()-opens, f.used.Load(), f.full.Load(), f.opener.closedHere.Load()-here,
					f.opener.closedByApp.Load()-app, f.live.Load(), int64(after.HeapAlloc)-int64(before.HeapAlloc), runtime.NumGoroutine()-goroutines)
				f.tun.Close()
				waitReuse(t, "closed pool", func() bool { return f.live.Load() == 0 })
			})
		}
	}
}
