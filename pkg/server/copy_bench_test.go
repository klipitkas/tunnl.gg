package server

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// No sockets or goroutines: isolate buffer and deadline overhead. Check every
// transfer so dropped bytes cannot look like a performance improvement.
type benchmarkCopyConn struct {
	net.Conn
	r *bytes.Reader
}

func (c *benchmarkCopyConn) Read(p []byte) (int, error)     { return c.r.Read(p) }
func (*benchmarkCopyConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*benchmarkCopyConn) SetReadDeadline(time.Time) error  { return nil }
func (*benchmarkCopyConn) SetWriteDeadline(time.Time) error { return nil }

func BenchmarkWebSocketCopy(b *testing.B) {
	payload := make([]byte, 64<<10)
	src := &benchmarkCopyConn{r: bytes.NewReader(payload)}
	dst := &benchmarkCopyConn{}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		src.r.Reset(payload)
		n, err := copyWithLimits(dst, src, int64(len(payload)), time.Minute)
		if err != nil || n != int64(len(payload)) {
			b.Fatalf("copy = %d, %v", n, err)
		}
	}
}
