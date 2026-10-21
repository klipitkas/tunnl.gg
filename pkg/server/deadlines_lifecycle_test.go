package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type deadlineRecordingWriter struct {
	*httptest.ResponseRecorder
	reads, writes []time.Time
}

func (w *deadlineRecordingWriter) SetReadDeadline(d time.Time) error {
	w.reads = append(w.reads, d)
	return nil
}

func (w *deadlineRecordingWriter) SetWriteDeadline(d time.Time) error {
	w.writes = append(w.writes, d)
	return nil
}

type deadlineTrackingBody struct {
	io.Reader
	closed bool
}

func (b *deadlineTrackingBody) Close() error { b.closed = true; return nil }

func TestProxyDeadlinesBodyOwnership(t *testing.T) {
	for _, kind := range []string{"nil", "empty", "upload"} {
		t.Run(kind, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			body := &deadlineTrackingBody{Reader: strings.NewReader("payload")}
			switch kind {
			case "nil":
				req.Body = nil
			case "upload":
				req.Body = body
				req.ContentLength = -1
			}
			original := req.Body
			out := &deadlineRecordingWriter{ResponseRecorder: httptest.NewRecorder()}
			w, r := newProxyDeadlines(req.Context(), out, req, time.Hour)
			defer w.stop()
			if r == req || req.Body != original || req.Context().Err() != nil {
				t.Fatal("deadline setup mutated the original request")
			}
			if len(out.reads) != 1 || out.reads[0].IsZero() != (kind != "upload") {
				t.Fatalf("initial read deadlines: %v", out.reads)
			}
			if kind == "upload" {
				got, err := io.ReadAll(r.Body)
				if err != nil || string(got) != "payload" || !out.reads[len(out.reads)-1].IsZero() {
					t.Fatalf("body or EOF deadline changed: body=%q err=%v deadlines=%v", got, err, out.reads)
				}
				r.Body.Close()
				if !body.closed {
					t.Fatal("Close did not reach the original body")
				}
			} else if r.Body != original {
				t.Fatal("recognized empty body acquired a wrapper")
			}
			w.stop()
			w.stop()
			if !errors.Is(r.Context().Err(), context.Canceled) || req.Context().Err() != nil {
				t.Fatal("stop did not cancel only the proxied request")
			}
		})
	}
}

func TestProxyDeadlinesWriterPassthrough(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	out := &deadlineRecordingWriter{ResponseRecorder: httptest.NewRecorder()}
	w, _ := newProxyDeadlines(req.Context(), out, req, time.Hour)
	defer w.stop()
	w.Header().Set("X-Test", "kept")
	w.WriteHeader(http.StatusCreated)
	if n, err := w.Write([]byte("stream")); n != 6 || err != nil {
		t.Fatalf("write: %d, %v", n, err)
	}
	if err := http.NewResponseController(w).Flush(); err != nil {
		t.Fatal(err)
	}
	if w.Unwrap() != out || !out.Flushed || out.Code != http.StatusCreated || out.Body.String() != "stream" || out.Header().Get("X-Test") != "kept" {
		t.Fatal("writer methods or flush no longer reach the original writer")
	}
	if len(out.writes) != 2 || out.writes[0].IsZero() || out.writes[1].IsZero() {
		t.Fatalf("response progress did not extend write deadlines: %v", out.writes)
	}
}

func TestProxyDeadlinesConcurrentProgressAndStop(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 1024)))
	out := &deadlineRecordingWriter{ResponseRecorder: httptest.NewRecorder()}
	w, r := newProxyDeadlines(req.Context(), out, req, time.Hour)
	defer w.stop()
	var wg sync.WaitGroup
	wg.Go(func() {
		if n, err := io.Copy(io.Discard, r.Body); n != 1024 || err != nil {
			t.Errorf("upload: %d, %v", n, err)
		}
		r.Body.Close()
	})
	wg.Go(func() {
		for range 64 {
			w.Write([]byte("x"))
		}
	})
	wg.Go(func() {
		for range 64 {
			w.stop()
		}
	})
	wg.Wait()
	w.stop()
	if !errors.Is(r.Context().Err(), context.Canceled) || out.Body.Len() != 64 {
		t.Fatal("concurrent progress and cleanup lost cancellation or response data")
	}
}
