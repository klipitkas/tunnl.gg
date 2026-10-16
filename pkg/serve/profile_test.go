package serve

import (
	"net/http/httptest"
	"testing"
)

func TestProfileListenerIsPrivateAndOptional(t *testing.T) {
	s, err := newProfileServer("")
	if s != nil || err != nil {
		t.Fatalf("empty address must disable profiling: %v, %v", s, err)
	}
	for _, addr := range []string{":9092", "0.0.0.0:9092", "[::]:9092", "192.0.2.1:9092", "localhost:9092", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:http"} {
		if _, err := newProfileServer(addr); err == nil {
			t.Errorf("accepted unsafe or invalid address %q", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:9092", "[::1]:9092"} {
		s, err := newProfileServer(addr)
		if err != nil {
			t.Fatal(err)
		}
		for path, want := range map[string]int{"/debug/pprof/goroutine": 200, "/debug/pprof/cmdline": 404, "/": 404} {
			w := httptest.NewRecorder()
			s.Handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			if w.Code != want {
				t.Errorf("%s: status %d, want %d", path, w.Code, want)
			}
		}
	}
}
