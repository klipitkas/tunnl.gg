package server

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type copyTestConn struct {
	net.Conn
	reader io.Reader
	writer io.Writer
}

func (c *copyTestConn) Read(p []byte) (int, error)     { return c.reader.Read(p) }
func (c *copyTestConn) Write(p []byte) (int, error)    { return c.writer.Write(p) }
func (*copyTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*copyTestConn) SetWriteDeadline(time.Time) error { return nil }

func TestWebSocketCopyConcurrentIntegrity(t *testing.T) {
	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Go(func() {
			for n := range 10 {
				payload := bytes.Repeat([]byte{byte(worker), byte(n)}, 32<<10)
				var dst bytes.Buffer
				written, err := copyWithLimits(&copyTestConn{writer: &dst},
					&copyTestConn{reader: bytes.NewReader(payload)}, int64(len(payload)), time.Minute)
				if err != nil || written != int64(len(payload)) || !bytes.Equal(dst.Bytes(), payload) {
					t.Errorf("corrupt copy for worker %d: bytes=%d err=%v", worker, written, err)
				}
			}
		})
	}
	wg.Wait()
}

type shortCopyWriter struct{ err error }

func (w shortCopyWriter) Write(p []byte) (int, error) { return len(p) / 2, w.err }

func TestWebSocketCopyCountsOnlyWrittenBytes(t *testing.T) {
	failure := errors.New("connection closed")
	for _, writeErr := range []error{nil, failure} {
		n, err := copyWithLimits(&copyTestConn{writer: shortCopyWriter{writeErr}},
			&copyTestConn{reader: bytes.NewReader([]byte("123456"))}, 6, time.Minute)
		want := writeErr
		if want == nil {
			want = io.ErrShortWrite
		}
		if n != 3 || !errors.Is(err, want) {
			t.Errorf("short write: bytes=%d err=%v, want 3 and %v", n, err, want)
		}
	}
}
