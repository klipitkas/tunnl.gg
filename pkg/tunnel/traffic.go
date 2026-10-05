package tunnel

import (
	"sync/atomic"
	"time"
)

// Traffic counts a tunnel's requests since it was last taken.
type Traffic struct {
	Requests     int64
	ClientErrors int64 // 4xx answers, from the app or from tunnl
	Errors       int64 // 5xx answers, and requests the app never answered
	BytesIn      int64 // request bodies
	BytesOut     int64 // response bodies
	Latency      time.Duration
}

// Zero reports whether nothing was counted.
func (t Traffic) Zero() bool { return t == Traffic{} }

// trafficCounters are a tunnel's running counts.
type trafficCounters struct {
	requests, clientErrors, errors, bytesIn, bytesOut, latency atomic.Int64
}

// CountRequest counts a request with the status it got (0 if none), the
// bytes sent each way (negative for unknown) and how long it took.
func (t *Tunnel) CountRequest(status int, bytesIn, bytesOut int64, latency time.Duration) {
	c := &t.traffic
	c.requests.Add(1)
	switch {
	case status == 0 || status >= 500:
		c.errors.Add(1)
	case status >= 400:
		c.clientErrors.Add(1)
	}
	c.bytesIn.Add(max(bytesIn, 0))
	c.bytesOut.Add(max(bytesOut, 0))
	c.latency.Add(int64(latency))
}

// TakeTraffic returns the counts since the last call and starts over.
func (t *Tunnel) TakeTraffic() Traffic {
	c := &t.traffic
	return Traffic{
		Requests:     c.requests.Swap(0),
		ClientErrors: c.clientErrors.Swap(0),
		Errors:       c.errors.Swap(0),
		BytesIn:      c.bytesIn.Swap(0),
		BytesOut:     c.bytesOut.Swap(0),
		Latency:      time.Duration(c.latency.Swap(0)),
	}
}
