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

func TestInspectorMemoryBudget(t *testing.T) {
	insp := NewInspector()
	big := Body{Data: make([]byte, MaxInspectedBody), Size: MaxInspectedBody}
	for range InspectorSize {
		insp.Add(Exchange{RequestBody: big, ResponseBody: big})
	}
	list := insp.List()
	kept := 0
	for _, e := range list {
		kept += len(e.RequestBody.Data) + len(e.ResponseBody.Data)
	}
	if kept > MaxInspectorBytes {
		t.Errorf("kept %d bytes of bodies, over %d", kept, MaxInspectorBytes)
	}
	if first, last := list[0], list[len(list)-1]; !first.RequestBody.Dropped || first.RequestBody.Size != MaxInspectedBody || last.RequestBody.Dropped || len(last.ResponseBody.Data) != MaxInspectedBody {
		t.Errorf("the oldest should let their bodies go, the newest keep them: first %+v, last dropped %v", first.RequestBody.Dropped, last.RequestBody.Dropped)
	}
	if len(list) != InspectorSize {
		t.Errorf("kept %d exchanges, want all %d with or without bodies", len(list), InspectorSize)
	}
}

func TestCaptureTransferKeepsSnapshotsIndependent(t *testing.T) {
	c := NewCapture(io.NopCloser(strings.NewReader("firstsecond")))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	snapshot := c.Body()
	body := c.TakeBody()
	if string(body.Data) != "first" || body.Size != 5 || body.Truncated {
		t.Fatalf("bad transfer: %+v", body)
	}
	// Neither an old snapshot nor a subsequent read may change transferred data.
	snapshot.Data[0] = 'X'
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatal(err)
	}
	if string(body.Data) != "first" {
		t.Fatalf("transferred body mutated: %q", body.Data)
	}
	body.Data[0] = 'Y'
	if got := c.Body(); string(got.Data) != "second" {
		t.Fatalf("new capture aliases transfer: %q", got.Data)
	}
	var none *Capture
	if got := none.TakeBody(); got.Size != 0 || len(got.Data) != 0 {
		t.Fatal("nil transfer is not empty")
	}
}

func TestCaptureTransferTruncation(t *testing.T) {
	c := NewCapture(io.NopCloser(strings.NewReader(strings.Repeat("x", MaxInspectedBody+100))))
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatal(err)
	}
	got := c.TakeBody()
	if len(got.Data) != MaxInspectedBody || got.Size != MaxInspectedBody+100 || !got.Truncated {
		t.Fatalf("bad transfer metadata: len=%d size=%d truncated=%v", len(got.Data), got.Size, got.Truncated)
	}
}

func TestInspectorBudgetsRetainedCapacity(t *testing.T) {
	insp := NewInspector()
	for range InspectorSize {
		insp.Add(Exchange{ResponseBody: Body{Data: make([]byte, 1, MaxInspectedBody), Size: 1}})
	}
	retained := 0
	for _, e := range insp.List() {
		retained += cap(e.RequestBody.Data) + cap(e.ResponseBody.Data)
	}
	if retained > MaxInspectorBytes {
		t.Fatalf("retained %d bytes, budget %d", retained, MaxInspectorBytes)
	}
	if !insp.List()[0].ResponseBody.Dropped {
		t.Fatal("old buffers should be released when their capacity exceeds the budget")
	}
}
