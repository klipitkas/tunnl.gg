package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

// proxyDeadlines replaces the server-wide read and write timeouts for a
// proxied request with idle timeouts. Every request body read and response
// write extends the connection deadlines, and the request is canceled once it
// goes idleTimeout without progress in either direction. Long polls, streaming
// responses and slow uploads can run as long as they keep making progress.
type proxyDeadlines struct {
	rc          *http.ResponseController
	idleTimeout time.Duration
	watchdog    *time.Timer
	cancel      context.CancelFunc
}

// newProxyDeadlines applies idle timeouts to r and w. It returns the request
// and response writer to proxy with, and a stop function to call when done.
func newProxyDeadlines(w http.ResponseWriter, r *http.Request, idleTimeout time.Duration) (http.ResponseWriter, *http.Request, func()) {
	ctx, cancel := context.WithCancel(r.Context())
	d := &proxyDeadlines{
		rc:          http.NewResponseController(w),
		idleTimeout: idleTimeout,
		watchdog:    time.AfterFunc(idleTimeout, cancel),
		cancel:      cancel,
	}

	r = r.WithContext(ctx)
	if r.Body == nil || r.Body == http.NoBody {
		// The server cancels the request when a read deadline expires while it
		// waits for the next request, so only a real disconnect should end it.
		d.clearReadDeadline()
	} else {
		d.extendRead()
		r.Body = &deadlineBody{ReadCloser: r.Body, d: d}
	}

	stop := func() {
		d.watchdog.Stop()
		cancel()
	}
	return &deadlineWriter{ResponseWriter: w, d: d}, r, stop
}

// Deadline errors are ignored: they only fail for writers that don't support
// deadlines, which then keep the server-wide timeouts.

func (d *proxyDeadlines) extendRead() {
	d.watchdog.Reset(d.idleTimeout)
	_ = d.rc.SetReadDeadline(time.Now().Add(d.idleTimeout))
}

func (d *proxyDeadlines) clearReadDeadline() {
	_ = d.rc.SetReadDeadline(time.Time{})
}

func (d *proxyDeadlines) extendWrite() {
	d.watchdog.Reset(d.idleTimeout)
	_ = d.rc.SetWriteDeadline(time.Now().Add(d.idleTimeout))
}

// deadlineBody extends the read deadline before each read of the request body
// and clears it once the body has been fully read.
type deadlineBody struct {
	io.ReadCloser
	d *proxyDeadlines
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	b.d.extendRead()
	n, err := b.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) {
		b.d.clearReadDeadline()
	}
	return n, err
}

// deadlineWriter extends the write deadline before each write of the response.
type deadlineWriter struct {
	http.ResponseWriter
	d *proxyDeadlines
}

func (w *deadlineWriter) WriteHeader(code int) {
	w.d.extendWrite()
	w.ResponseWriter.WriteHeader(code)
}

func (w *deadlineWriter) Write(b []byte) (int, error) {
	w.d.extendWrite()
	return w.ResponseWriter.Write(b)
}

// Unwrap returns the underlying ResponseWriter for interface passthrough (e.g., http.Flusher).
func (w *deadlineWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
