package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// The request inspector keeps a tunnel's latest requests, with their
// headers and the start of their bodies, so its owner can look at them and
// send one again. They're kept in memory only, and only for tunnels whose
// limits allow it.

// Exchange is a request through a tunnel and its response.
type Exchange struct {
	ID      uint64
	Time    time.Time
	Method  string
	Target  string // path and query
	Host    string // the Host header the app got
	Visitor string // the visitor's IP, or "replay"

	RequestHeader  http.Header // as sent to the app
	RequestBody    Body
	Status         int // 0 if the app never answered
	ResponseHeader http.Header
	ResponseBody   Body
	Duration       time.Duration
	Note           string // why tunnl answered itself, or why the request failed
	Replay         bool   // sent again from the inspector
}

// Body is the start of a request or response body.
type Body struct {
	Data      []byte
	Size      int64 // bytes in the whole body, as far as it was read
	Truncated bool  // Data is only the start of it
}

// Inspector limits, so a busy tunnel holds at most about 3 MB.
const (
	InspectorSize    = 50       // exchanges kept per tunnel
	MaxInspectedBody = 32 << 10 // bytes kept of each body
)

// Inspector keeps a tunnel's latest exchanges and tells subscribers about
// new ones.
type Inspector struct {
	mu   sync.Mutex
	next uint64
	ring []Exchange // oldest first
	subs map[chan Exchange]struct{}
}

func NewInspector() *Inspector {
	return &Inspector{subs: map[chan Exchange]struct{}{}}
}

// Add records e, giving it an ID, and tells subscribers.
func (i *Inspector) Add(e Exchange) Exchange {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.next++
	e.ID = i.next
	if len(i.ring) == InspectorSize {
		copy(i.ring, i.ring[1:])
		i.ring = i.ring[:InspectorSize-1]
	}
	i.ring = append(i.ring, e)
	for ch := range i.subs {
		// A subscriber that can't keep up misses exchanges rather than
		// holding up the tunnel; it can list them again
		select {
		case ch <- e:
		default:
		}
	}
	return e
}

// List returns the exchanges kept, oldest first.
func (i *Inspector) List() []Exchange {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]Exchange(nil), i.ring...)
}

// Get returns the exchange with id, if it's still kept.
func (i *Inspector) Get(id uint64) (Exchange, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, e := range i.ring {
		if e.ID == id {
			return e, true
		}
	}
	return Exchange{}, false
}

// Subscribe returns new exchanges as they're added, until cancel is called.
func (i *Inspector) Subscribe() (exchanges <-chan Exchange, cancel func()) {
	ch := make(chan Exchange, 16)
	i.mu.Lock()
	i.subs[ch] = struct{}{}
	i.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			i.mu.Lock()
			delete(i.subs, ch)
			i.mu.Unlock()
		})
	}
}

// Capture keeps the start of a body while it's read, and counts it all.
type Capture struct {
	io.ReadCloser
	mu  sync.Mutex
	buf bytes.Buffer
	n   int64
}

// NewCapture wraps rc to capture what's read from it.
func NewCapture(rc io.ReadCloser) *Capture {
	return &Capture{ReadCloser: rc}
}

func (c *Capture) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.n += int64(n)
		if room := MaxInspectedBody - c.buf.Len(); room > 0 {
			c.buf.Write(p[:min(n, room)])
		}
		c.mu.Unlock()
	}
	return n, err
}

// Body returns what was captured so far.
func (c *Capture) Body() Body {
	if c == nil {
		return Body{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return Body{Data: bytes.Clone(c.buf.Bytes()), Size: c.n, Truncated: c.n > int64(c.buf.Len())}
}

// Hop-by-hop headers aren't sent again when replaying.
var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// replayTimeout bounds how long a replayed request waits for the app.
const replayTimeout = 30 * time.Second

var (
	ErrNotInspected   = errors.New("this tunnel doesn't keep its requests")
	ErrGone           = errors.New("that request is no longer kept: only the latest 50 are")
	ErrBodyTruncated  = errors.New("that request's body was too large to keep in full, so it can't be sent again")
	ErrCantReplayUpgr = errors.New("WebSocket requests can't be sent again")
)

// Replay sends the exchange with id to the app again, as it was sent the
// first time, and records the new exchange.
func (t *Tunnel) Replay(ctx context.Context, id uint64) (Exchange, error) {
	insp := t.Inspector()
	if insp == nil {
		return Exchange{}, ErrNotInspected
	}
	orig, ok := insp.Get(id)
	switch {
	case !ok:
		return Exchange{}, ErrGone
	case orig.RequestBody.Truncated:
		return Exchange{}, ErrBodyTruncated
	case orig.Method == "WS":
		return Exchange{}, ErrCantReplayUpgr
	}

	ctx, cancel := context.WithTimeout(ctx, replayTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, orig.Method, "http://"+orig.Host+orig.Target, bytes.NewReader(orig.RequestBody.Data))
	if err != nil {
		return Exchange{}, fmt.Errorf("rebuilding the request: %w", err)
	}
	req.Header = orig.RequestHeader.Clone()
	for _, h := range hopHeaders {
		req.Header.Del(h)
	}
	req.Host = orig.Host
	req.ContentLength = int64(len(orig.RequestBody.Data))

	e := Exchange{
		Time:          time.Now(),
		Method:        orig.Method,
		Target:        orig.Target,
		Host:          orig.Host,
		Visitor:       "replay",
		RequestHeader: req.Header.Clone(),
		RequestBody:   orig.RequestBody,
		Replay:        true,
	}
	defer t.BeginRequest()() // counts as activity, like a visitor's request
	resp, err := t.Transport().RoundTrip(req)
	if err != nil {
		e.Duration = time.Since(e.Time)
		e.Note = "the app didn't answer: " + err.Error()
		return insp.Add(e), nil
	}
	defer resp.Body.Close()
	body := NewCapture(resp.Body)
	io.Copy(io.Discard, io.LimitReader(body, 1<<20))
	e.Status = resp.StatusCode
	e.ResponseHeader = resp.Header.Clone()
	e.ResponseBody = body.Body()
	e.Duration = time.Since(e.Time)
	return insp.Add(e), nil
}
