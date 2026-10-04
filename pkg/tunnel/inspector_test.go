package tunnel

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestInspectorKeepsTheLatest(t *testing.T) {
	insp := NewInspector()
	events, cancel := insp.Subscribe()
	defer cancel()
	for i := range InspectorSize + 5 {
		insp.Add(Exchange{Target: "/" + strings.Repeat("x", i)})
	}
	list := insp.List()
	if len(list) != InspectorSize || list[0].ID != 6 || list[len(list)-1].ID != InspectorSize+5 {
		t.Fatalf("kept %d, IDs %d to %d", len(list), list[0].ID, list[len(list)-1].ID)
	}
	if _, ok := insp.Get(1); ok {
		t.Error("the oldest exchange should be gone")
	}
	if e, ok := insp.Get(10); !ok || e.Target != "/"+strings.Repeat("x", 9) {
		t.Errorf("Get(10) = %+v", e)
	}
	// A slow subscriber gets what fits and the tunnel isn't held up
	got := 0
	for {
		select {
		case <-events:
			got++
			continue
		case <-time.After(50 * time.Millisecond):
		}
		break
	}
	if got != 16 {
		t.Errorf("subscriber got %d, want its buffer of 16", got)
	}
	cancel()
	insp.Add(Exchange{}) // after cancelling, nothing is sent
}

func TestCapture(t *testing.T) {
	small := NewCapture(io.NopCloser(strings.NewReader("hello")))
	io.ReadAll(small)
	if b := small.Body(); string(b.Data) != "hello" || b.Size != 5 || b.Truncated {
		t.Errorf("small body = %+v", b)
	}
	big := NewCapture(io.NopCloser(bytes.NewReader(make([]byte, MaxInspectedBody+100))))
	io.ReadAll(big)
	if b := big.Body(); len(b.Data) != MaxInspectedBody || b.Size != MaxInspectedBody+100 || !b.Truncated {
		t.Errorf("big body: %d bytes kept of %d, truncated %v", len(b.Data), b.Size, b.Truncated)
	}
	var none *Capture
	if b := none.Body(); b.Size != 0 {
		t.Error("a nil capture is an empty body")
	}
}
