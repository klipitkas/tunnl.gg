package tunnel

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// Freeze the previous formatter as a byte-for-byte oracle: padding, rounding,
// colors, escaping, optional JSON fields and line endings are public output.
func TestRequestLogFormattingCompatibility(t *testing.T) {
	sizes := []int64{math.MinInt64, -1, 0, 1, 1023, 1024, 1280, 1048575, 1048576, 1073741823, 1073741824, math.MaxInt64}
	latencies := []time.Duration{math.MinInt64, -1, 0, 1, time.Millisecond - 1, time.Millisecond, time.Second - 1, time.Second, 1050 * time.Millisecond, 5 * time.Second, math.MaxInt64}
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "WS", "OPTIONS", "LONGMETHOD", "方法", "G\x1bET", "G\xffET"}
	targets := []string{"/", "/a?<>&=yes", strings.Repeat("路", 40), strings.Repeat("路", 41), "/" + strings.Repeat("path/", 100), "/\xff?\r\n\x1b\u202e"}
	statuses := []int{0, 200, 301, 404, 500, 1234567}
	for i := range 1000 {
		e := Entry{
			Time:   time.Date(2026, 10, 21, 1, 2, 3, 123456789, time.FixedZone("test", 3*3600)),
			Method: methods[i%len(methods)], Target: targets[i%len(targets)], Status: statuses[i%len(statuses)],
			Bytes: sizes[i%len(sizes)], Latency: latencies[i%len(latencies)], Visitor: "2001:db8::1", FromTunnl: i%7 == 0,
		}
		if i%3 == 0 {
			e.Note = "notice <>&\r\n\x1b\u202e"
			e.Detail = "detail\t\x00"
			e.Visitor = "bad\x1bvisitor"
		}
		var got, want bytes.Buffer
		formatEntryTo(&got, e)
		referenceFormatEntryTo(&want, e)
		if !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Fatalf("case %d terminal\ngot  %q\nwant %q", i, got.String(), want.String())
		}
		if got, want := JSONLine(jsonEntry(e)), JSONLine(referenceJsonEntry(e)); got != want {
			t.Fatalf("case %d JSON\ngot  %q\nwant %q", i, got, want)
		}
	}
	for _, size := range sizes {
		if got, want := formatBytes(size), referenceFormatBytes(size); got != want {
			t.Errorf("bytes %d: %q != %q", size, got, want)
		}
	}
	for _, latency := range latencies {
		if got, want := formatLatency(latency), referenceFormatLatency(latency); got != want {
			t.Errorf("latency %d: %q != %q", latency, got, want)
		}
	}
	// Both numeric pointers must survive later encodes, with explicit zero values.
	first := jsonEntry(Entry{Status: 200, Bytes: 0, Latency: time.Nanosecond})
	_ = JSONLine(jsonEntry(Entry{Status: 200, Bytes: 123, Latency: time.Second}))
	if first.Bytes == nil || *first.Bytes != 0 || first.DurationMS == nil || *first.DurationMS != 0 {
		t.Fatalf("optional zero values changed: %+v", first)
	}
}

func referenceFormatEntryTo(b *bytes.Buffer, e Entry) {
	b.WriteString("\r" + strings.Repeat(" ", indentWidth))
	b.WriteString(colorDim + e.Time.UTC().Format("15:04:05") + colorReset + "  ")

	method := sanitizeTerminalText(e.Method)
	b.WriteString(methodColor(method) + fmt.Sprintf("%-*s", methodWidth, method) + colorReset + "  ")
	b.WriteString(fmt.Sprintf("%-*s", targetWidth, fitTarget(e.Target)) + "  ")

	if e.Status > 0 {
		b.WriteString(statusColor(e.Status) + fmt.Sprintf("%-*d", statusWidth, e.Status) + colorReset + "  ")
	} else {
		b.WriteString(strings.Repeat(" ", statusWidth+2))
	}

	size := ""
	if e.Bytes >= 0 && e.Status > 0 && !e.FromTunnl {
		size = referenceFormatBytes(e.Bytes)
	}
	b.WriteString(colorDim + fmt.Sprintf("%*s", sizeWidth, size) + colorReset + "  ")

	latency := ""
	if e.Latency > 0 {
		latency = referenceFormatLatency(e.Latency)
	}
	b.WriteString(latencyColor(e.Latency) + fmt.Sprintf("%*s", latencyWidth, latency) + colorReset + "  ")

	b.WriteString(colorDim + sanitizeTerminalText(e.Visitor) + colorReset)
	if e.Note != "" {
		noteColor := colorDim
		if e.FromTunnl {
			noteColor = colorMagenta
		}
		b.WriteString("  " + noteColor + sanitizeTerminalText(e.Note) + colorReset)
	}
	b.WriteString("\r\n")

	if e.Detail != "" {
		b.WriteString("\r" + strings.Repeat(" ", indentWidth+timeWidth+2))
		b.WriteString(colorRed + "↳ " + sanitizeTerminalText(e.Detail) + colorReset + "\r\n")
	}
}

func referenceFormatBytes(b int64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%d B", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	case b < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	default:
		return fmt.Sprintf("%.1f GB", float64(b)/(1024*1024*1024))
	}
}

func referenceFormatLatency(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return "<1ms"
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	default:
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
}

func referenceJsonEntry(e Entry) requestJSON {
	r := requestJSON{
		Event:     "request",
		Time:      e.Time.UTC().Format(time.RFC3339),
		Method:    e.Method,
		Path:      e.Target,
		Status:    e.Status,
		Visitor:   e.Visitor,
		Note:      e.Note,
		Detail:    e.Detail,
		FromTunnl: e.FromTunnl,
	}
	if e.Bytes >= 0 && e.Status > 0 && !e.FromTunnl {
		r.Bytes = &e.Bytes
	}
	if e.Latency > 0 {
		ms := e.Latency.Milliseconds()
		r.DurationMS = &ms
	}
	return r
}
