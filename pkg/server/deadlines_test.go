package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProxyDeadlinesPreservesContextAndCancellation(t *testing.T) {
	type key struct{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx, cancel := context.WithCancel(context.WithValue(req.Context(), key{}, "origin"))
	defer cancel()
	_, proxied, stop := newProxyDeadlines(ctx, httptest.NewRecorder(), req, time.Minute)
	defer stop()
	if proxied.Context().Value(key{}) != "origin" || req.Context().Value(key{}) != nil {
		t.Fatal("composed context was lost or the original request was changed")
	}
	cancel()
	select {
	case <-proxied.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not reach the proxied request")
	}
}

func TestProxyDeadlines_CancelsIdleRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, r, stop := newProxyDeadlines(req.Context(), httptest.NewRecorder(), req, 50*time.Millisecond)
	defer stop()

	select {
	case <-r.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("request without progress should be canceled after the idle timeout")
	}
}

func TestProxyDeadlines_ProgressKeepsRequestAlive(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w, r, stop := newProxyDeadlines(req.Context(), httptest.NewRecorder(), req, 100*time.Millisecond)
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
