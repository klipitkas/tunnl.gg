package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProxyDeadlines_CancelsIdleRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, r, stop := newProxyDeadlines(httptest.NewRecorder(), req, 50*time.Millisecond)
	defer stop()

	select {
	case <-r.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("request without progress should be canceled after the idle timeout")
	}
}

func TestProxyDeadlines_ProgressKeepsRequestAlive(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w, r, stop := newProxyDeadlines(httptest.NewRecorder(), req, 100*time.Millisecond)
	defer stop()

	// Write for well past the idle timeout, never pausing for longer than it
	for i := 0; i < 10; i++ {
		w.Write([]byte("x"))
		time.Sleep(30 * time.Millisecond)
	}
	if err := r.Context().Err(); err != nil {
		t.Fatalf("request making progress was canceled: %v", err)
	}
}
