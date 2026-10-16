package tunnel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type countedLogWriter struct {
	bytes.Buffer
	writes int
}

func (w *countedLogWriter) Write(p []byte) (int, error) {
	w.writes++
	return w.Buffer.Write(p)
}

func TestQueuedLogsBatchWithoutChangingOutput(t *testing.T) {
	for _, large := range []bool{false, true} {
		t.Run(fmt.Sprint(large), func(t *testing.T) {
			w := &countedLogWriter{}
			l := &RequestLogger{w: w, ch: make(chan *bytes.Buffer, 64), done: make(chan struct{})}
			var want strings.Builder
			for i := range 64 {
				line := fmt.Sprintf("line %d\r\n", i)
				if large && i == 31 {
					line = strings.Repeat("x", 2*maxLogBuffer) + "\r\n"
				}
				want.WriteString(line)
				l.send(line)
			}
			l.stop()
			l.drain()
			if got := w.String(); got != want.String() {
				t.Fatal("batching reordered, truncated or corrupted queued lines")
			}
			if w.writes >= 64 {
				t.Fatalf("queued logs were not combined: %d writes", w.writes)
			}
		})
	}
}

func TestSingleLogFlushesWithoutClosing(t *testing.T) {
	w := logAckWriter{make(chan struct{})}
	l := NewJSONRequestLogger(w, 16)
	l.Log(testEntry())
	select {
	case <-w.done:
	case <-time.After(time.Second):
		t.Fatal("a quiet tunnel's log was held waiting for a batch")
	}
	l.Close()
}

func TestPooledJSONLogsStayWithTheirTunnel(t *testing.T) {
	var wg sync.WaitGroup
	for tunnelID := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var output bytes.Buffer
			l := NewJSONRequestLogger(&output, 256)
			var senders sync.WaitGroup
			for sender := range 4 {
				senders.Add(1)
				go func() {
					defer senders.Done()
					for i := range 32 {
						e := testEntry()
						e.Target = fmt.Sprintf("/%d/%d/%d?value=<>&\r\n\x1b", tunnelID, sender, i)
						l.Log(e)
					}
				}()
			}
			senders.Wait()
			l.Close()
			seen := make(map[string]bool)
			decoder := json.NewDecoder(&output)
			for {
				var e requestJSON
				if err := decoder.Decode(&e); err != nil {
					if err != io.EOF {
						t.Errorf("invalid JSON: %v", err)
					}
					break
				}
				if !strings.HasPrefix(e.Path, fmt.Sprintf("/%d/", tunnelID)) || seen[e.Path] ||
					!strings.HasSuffix(e.Path, "?value=<>&\r\n\x1b") || e.Status != 200 ||
					e.Bytes == nil || *e.Bytes != 1234 || e.DurationMS == nil || *e.DurationMS != 12 {
					t.Errorf("corrupted or cross-tunnel log: %+v", e)
				}
				seen[e.Path] = true
			}
			if len(seen) != 128 {
				t.Errorf("got %d distinct logs, want 128", len(seen))
			}
		}()
	}
	wg.Wait()
}

func TestJSONLineRetainsItsContentsAfterBufferReuse(t *testing.T) {
	want := "{\"value\":\"<>&\\r\\n\\u001b\"}\r\n"
	line := JSONLine(map[string]string{"value": "<>&\r\n\x1b"})
	for range 100 {
		_ = JSONLine(map[string]string{"other": strings.Repeat("z", 1024)})
	}
	if line != want {
		t.Fatalf("line = %q, want %q", line, want)
	}
	if got := JSONLine(make(chan int)); got != "" {
		t.Fatalf("encoding failure returned %q", got)
	}
}
