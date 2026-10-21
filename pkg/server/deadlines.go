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
	http.ResponseWriter
	rc          http.ResponseController
	body        deadlineBody
	idleTimeout time.Duration
	watchdog    *time.Timer
	cancel      context.CancelFunc
}

// newProxyDeadlines applies idle timeouts to r and w. It returns the response
// writer and request to proxy with. Call the writer's stop method when done.
// Accept the composed context separately so origin metadata and cancellation
// only require one request copy.
func newProxyDeadlines(ctx context.Context, w http.ResponseWriter, r *http.Request, idleTimeout time.Duration) (*proxyDeadlines, *http.Request) {
	ctx, cancel := context.WithCancel(ctx)
	// The writer, controller and optional body wrapper share this request's
	// lifetime. Keep them in one allocation; none of this state is pooled.
	d := &proxyDeadlines{
		ResponseWriter: w,
		rc:             *http.NewResponseController(w),
		idleTimeout:    idleTimeout,
		watchdog:       time.AfterFunc(idleTimeout, cancel),
		cancel:         cancel,
	}

	r = r.WithContext(ctx)
	if r.Body == nil || r.Body == http.NoBody {
		// The server cancels the request when a read deadline expires while it
		// waits for the next request, so only a real disconnect should end it.
		d.clearReadDeadline()
	} else {
		d.extendRead()
		d.body = deadlineBody{ReadCloser: r.Body, d: d}
		r.Body = &d.body
	}

	return d, r
}

func (d *proxyDeadlines) stop() {
	d.watchdog.Stop()
	d.cancel()
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

func (d *proxyDeadlines) WriteHeader(code int) {
	d.extendWrite()
	d.ResponseWriter.WriteHeader(code)
}

func (d *proxyDeadlines) Write(b []byte) (int, error) {
	d.extendWrite()
	return d.ResponseWriter.Write(b)
}

// Unwrap returns the underlying ResponseWriter for interface passthrough (e.g., http.Flusher).
func (d *proxyDeadlines) Unwrap() http.ResponseWriter {
	return d.ResponseWriter
}
