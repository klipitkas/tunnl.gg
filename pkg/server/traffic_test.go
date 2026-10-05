package server

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

func TestE2E_TrafficReports(t *testing.T) {
	srv, addr := startSSHServer(t)
	var mu sync.Mutex
	total := map[string]tunnel.Traffic{}
	srv.SetTrafficSink(func(r TrafficReport) {
		mu.Lock()
		defer mu.Unlock()
		sum := total[r.Subdomain]
		sum.Requests += r.Requests
		sum.ClientErrors += r.ClientErrors
		sum.Errors += r.Errors
		sum.BytesIn += r.BytesIn
		sum.BytesOut += r.BytesOut
		sum.Latency += r.Latency
		total[r.Subdomain] = sum
	}, 20*time.Millisecond)
	got := func(sub string) tunnel.Traffic {
		mu.Lock()
		defer mu.Unlock()
		return total[sub]
	}

	tt := openTunnelCommand(t, srv, addr, anonymousClient(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, "got "+string(body))
	}), "allow=127.0.0.1")
	tt.get(t, "/")        // 200, 4 bytes out
	tt.get(t, "/missing") // 404
	req, _ := http.NewRequest(http.MethodPost, tt.public.URL+"/hook", strings.NewReader("hello"))
	req.Host = tt.host()
	resp, err := tt.public.Client().Do(req) // 200, 5 in, 9 out
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	tt.serveDirect("203.0.113.9:1", nil) // refused by the allowlist: a 403 from tunnl

	waitFor(t, "the traffic", func() bool { return got(tt.sub).Requests == 4 })
	sum := got(tt.sub)
	if sum.ClientErrors != 2 || sum.Errors != 0 || sum.BytesIn != 5 || sum.BytesOut < 13 || sum.Latency <= 0 {
		t.Errorf("traffic = %+v", sum)
	}

	// The app going away counts as errors, reported when the tunnel closes
	tt.local.Close()
	tt.get(t, "/")
	tt.client.Close()
	waitFor(t, "the closed tunnel's traffic", func() bool { return got(tt.sub).Errors == 1 })
}
