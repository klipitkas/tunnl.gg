package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestRelayPerformance is an opt-in, bounded comparison through real TLS,
// SSH forwarding, a TCP backend and session logging. It is not a capacity
// test: 180 arrivals at 100/s stay within the existing visitor burst budget.
// Run the identical harness on both revisions, without -race, with:
// TUNNL_PERF=1 go test ./pkg/server -run '^TestRelayPerformance$' -count=10 -v
// All processes share this machine; B/op and allocs/op include the clients.
func TestRelayPerformance(t *testing.T) {
	if os.Getenv("TUNNL_PERF") != "1" {
		t.Skip("set TUNNL_PERF=1 to collect local forwarding measurements")
	}
	command, logMode := "", "terminal"
	if os.Getenv("TUNNL_PERF_JSON") == "1" {
		command, logMode = "output=json", "json"
	}
	for _, h2 := range []bool{false, true} {
		name := "HTTP1"
		if h2 {
			name = "HTTP2"
		}
		name += "/" + logMode
		t.Run(name, func(t *testing.T) {
			const requests, warmup, workers = 180, 16, 4
			const interval = 10 * time.Millisecond
			small := bytes.Repeat([]byte("s"), 1024)
			large := bytes.Repeat([]byte("L"), 64<<10)
			upload := bytes.Repeat([]byte("u"), 16<<10)
			srv, addr := startSSHServer(t)
			tt := openTunnelCommand(t, srv, addr, anonymousClient(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil || (r.Method == http.MethodPost && !bytes.Equal(body, upload)) ||
					(r.Method == http.MethodGet && len(body) != 0) {
					http.Error(w, "bad upload", http.StatusBadRequest)
					return
				}
				w.Header().Set("X-Perf-Request", r.Header.Get("X-Perf-Request"))
				if r.Method == http.MethodPost {
					w.Write(large)
				} else {
					w.Write(small)
				}
			}), command)
			public := httptest.NewUnstartedServer(tt.srv)
			public.EnableHTTP2 = h2
			public.StartTLS()
			defer public.Close()
			client := public.Client() // trusts this fixture's certificate
			client.Timeout = 5 * time.Second

			send := func(i int) error {
				method, want := http.MethodGet, small
				var body io.Reader
				if i%10 == 9 {
					method, want, body = http.MethodPost, large, bytes.NewReader(upload)
				}
				r, err := http.NewRequest(method, public.URL+"/perf/"+strconv.Itoa(i), body)
				if err != nil {
					return err
				}
				r.Host = tt.host()
				r.Header.Set("X-Perf-Request", strconv.Itoa(i))
				resp, err := client.Do(r)
				if err != nil {
					return err
				}
				got, readErr := io.ReadAll(resp.Body)
				resp.Body.Close()
				proto := 1
				if h2 {
					proto = 2
				}
				if readErr != nil || resp.StatusCode != http.StatusOK || resp.ProtoMajor != proto ||
					resp.Header.Get("X-Perf-Request") != strconv.Itoa(i) || !bytes.Equal(got, want) {
					return fmt.Errorf("request %d: status=%d protocol=%s bytes=%d read=%v", i, resp.StatusCode, resp.Proto, len(got), readErr)
				}
				return nil
			}
			logged := func(n int) bool {
				tt.output.mu.Lock()
				defer tt.output.mu.Unlock()
				return bytes.Count(tt.output.buf.Bytes(), []byte("/perf/")) == n
			}
			for i := range warmup {
				if err := send(i); err != nil {
					t.Fatal(err)
				}
			}
			waitFor(t, "warmup logs", func() bool { return logged(warmup) })
			latencies := make([]time.Duration, requests)
			errs := make([]error, requests)
			jobs := make(chan int, workers)
			var wg sync.WaitGroup
			start := time.Now().Add(20 * time.Millisecond)
			for range workers {
				wg.Go(func() {
					for i := range jobs {
						errs[i] = send(i + warmup)
						// Include generator scheduling and queue delays.
						latencies[i] = time.Since(start.Add(time.Duration(i) * interval))
					}
				})
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			dropped := 0
			for i := range requests {
				time.Sleep(time.Until(start.Add(time.Duration(i) * interval)))
				select {
				case jobs <- i:
				default:
					dropped++
				}
			}
			close(jobs)
			wg.Wait()
			elapsed := time.Since(start)
			if dropped != 0 {
				t.Fatalf("dropped %d arrivals", dropped)
			}
			for _, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			waitFor(t, "all request logs", func() bool { return logged(warmup + requests) })
			runtime.ReadMemStats(&after)
			slices.Sort(latencies)
			// Standard benchmark lines allow benchstat to compare all samples.
			fmt.Printf("BenchmarkRelay/%s %d %.0f ns/op %.0f B/op %.2f allocs/op %.0f p50-ns %.0f p95-ns %.0f p99-ns %.2f requests/s\n",
				name, requests, float64(elapsed.Nanoseconds())/requests,
				float64(after.TotalAlloc-before.TotalAlloc)/requests, float64(after.Mallocs-before.Mallocs)/requests,
				float64(latencies[requests*50/100]), float64(latencies[requests*95/100]), float64(latencies[requests*99/100]),
				requests/elapsed.Seconds())
		})
	}
}
