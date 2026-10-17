package serve

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func TestProfileListenerIsPrivateAndOptional(t *testing.T) {
	s, err := newProfileServer("", nil)
	if s != nil || err != nil {
		t.Fatalf("empty address must disable profiling: %v, %v", s, err)
	}
	for _, addr := range []string{":9092", "0.0.0.0:9092", "[::]:9092", "192.0.2.1:9092", "localhost:9092", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:http"} {
		if _, err := newProfileServer(addr, nil); err == nil {
			t.Errorf("accepted unsafe or invalid address %q", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:9092", "[::1]:9092"} {
		s, err := newProfileServer(addr, nil)
		if err != nil {
			t.Fatal(err)
		}
		for path, want := range map[string]int{"/debug/pprof/goroutine": 200, "/debug/pprof/cmdline": 404, "/": 404,
			"/debug/pprof/trace-window": 404} {
			w := httptest.NewRecorder()
			s.Handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			if w.Code != want {
				t.Errorf("%s: status %d, want %d", path, w.Code, want)
			}
		}
	}
}

func TestFlightRecorderWindow(t *testing.T) {
	for _, window := range []string{"0s", "-5s", "ten seconds"} {
		if _, err := newFlightRecorder(window); err == nil {
			t.Errorf("accepted invalid window %q", window)
		}
	}
	if recorder, err := newFlightRecorder(""); recorder != nil || err != nil {
		t.Fatalf("empty window must disable the recorder: %v, %v", recorder, err)
	}

	recorder, err := newFlightRecorder("5s")
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Stop()
	s, err := newProfileServer("127.0.0.1:9092", recorder)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/debug/pprof/trace-window", nil))
	if w.Code != 200 {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
	// Execution traces start with a header naming the Go version
	if !bytes.HasPrefix(w.Body.Bytes(), []byte("go 1.")) {
		t.Errorf("snapshot doesn't look like an execution trace: %q", w.Body.Bytes()[:min(16, w.Body.Len())])
	}
}
