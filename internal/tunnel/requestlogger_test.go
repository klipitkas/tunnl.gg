package tunnel

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// plain strips colors from log output.
func plain(s string) string {
	return ansiPattern.ReplaceAllString(s, "")
}

func testEntry() Entry {
	return Entry{
		Time:    time.Date(2026, 9, 26, 11, 2, 14, 0, time.UTC),
		Method:  "GET",
		Target:  "/api/users?page=2",
		Status:  200,
		Bytes:   1234,
		Latency: 12 * time.Millisecond,
		Visitor: "203.0.113.7",
	}
}

func TestLog_RequestLine(t *testing.T) {
	var buf bytes.Buffer
	l := NewRequestLogger(&buf, 16)
	l.Log(testEntry())
	l.Close()

	out := plain(buf.String())
	for _, want := range []string{"11:02:14", "GET", "/api/users?page=2", "200", "1.2 KB", "12ms", "203.0.113.7"} {
		if !strings.Contains(out, want) {
			t.Errorf("log line missing %q: %q", want, out)
		}
	}
	if !strings.HasPrefix(out, "\r") || !strings.HasSuffix(out, "\r\n") {
		t.Errorf("log line should start with \\r and end with \\r\\n: %q", out)
	}
}

func TestLog_TimesAreUTC(t *testing.T) {
	e := testEntry()
	e.Time = time.Date(2026, 9, 26, 14, 2, 14, 0, time.FixedZone("EEST", 3*60*60))
	if out := plain(formatEntry(e)); !strings.Contains(out, "11:02:14") {
		t.Errorf("time should be shown in UTC: %q", out)
	}
}

func TestLog_Colors(t *testing.T) {
	tests := []struct {
		status int
		color  string
	}{
		{200, colorGreen},
		{302, colorCyan},
		{404, colorYellow},
		{502, colorRed},
	}
	for _, tt := range tests {
		e := testEntry()
		e.Status = tt.status
		if out := formatEntry(e); !strings.Contains(out, colorBold+tt.color+strconv.Itoa(tt.status)) {
			t.Errorf("status %d should be colored %q: %q", tt.status, tt.color, out)
		}
	}

	slow := testEntry()
	slow.Latency = 6 * time.Second
	if out := formatEntry(slow); !strings.Contains(out, colorRed) || !strings.Contains(plain(out), "6.0s") {
		t.Errorf("a slow request should show its time in red: %q", out)
	}
}

func TestLog_TunnlEventAndDetail(t *testing.T) {
	e := testEntry()
	e.Status = 429
	e.Bytes = -1
	e.Latency = 0
	e.Note = "rate limited by tunnl"
	e.FromTunnl = true
	out := formatEntry(e)
	if !strings.Contains(out, colorMagenta+"rate limited by tunnl") {
		t.Errorf("tunnl notes should be highlighted: %q", out)
	}
	if strings.Contains(plain(out), " B ") {
		t.Errorf("tunnl events have no response size: %q", out)
	}

	failed := testEntry()
	failed.Status = 502
	failed.Detail = "your local app didn't accept the connection: connection refused"
	lines := strings.Split(strings.TrimSuffix(plain(formatEntry(failed)), "\r\n"), "\r\n")
	if len(lines) != 2 || !strings.Contains(lines[1], "↳ your local app didn't accept") {
		t.Errorf("the detail should be on its own line: %q", lines)
	}
}

func TestLog_TunnlEventsRateLimited(t *testing.T) {
	var buf bytes.Buffer
	l := NewRequestLogger(&buf, 1024)
	e := testEntry()
	e.Status = 429
	e.FromTunnl = true
	e.Note = "rate limited by tunnl"
	for i := 0; i < 50; i++ {
		l.Log(e)
	}
	l.Close()

	shown := strings.Count(buf.String(), "rate limited by tunnl")
	if shown > tunnlNotesPerSecond+1 {
		t.Errorf("%d tunnl notes shown for a burst of 50, want at most about %d", shown, tunnlNotesPerSecond)
	}
	if !strings.Contains(l.Summary(), "50 turned away by tunnl") {
		t.Errorf("summary should still count every request turned away: %q", l.Summary())
	}
}

func TestLog_HiddenNotesAreReported(t *testing.T) {
	var buf bytes.Buffer
	l := NewRequestLogger(&buf, 1024)
	e := testEntry()
	e.Status = 429
	e.FromTunnl = true
	e.Note = "rate limited by tunnl"
	for i := 0; i < tunnlNotesPerSecond+3; i++ {
		l.Log(e)
	}
	time.Sleep(300 * time.Millisecond) // refill a token
	l.Log(e)
	l.Close()

	if !strings.Contains(buf.String(), "(+3 similar not shown)") {
		t.Errorf("the next note shown should report the hidden ones: %q", plain(buf.String()))
	}
}

func TestSummary(t *testing.T) {
	l := NewRequestLogger(io.Discard, 16)
	defer l.Close()
	if got := l.Summary(); got != "0 requests" {
		t.Errorf("empty summary = %q", got)
	}

	ok := testEntry()
	l.Log(ok)
	failed := testEntry()
	failed.Status = 502
	failed.Bytes = 11
	l.Log(failed)
	ws := testEntry()
	ws.Method, ws.Status, ws.Note = "WS", 0, "open"
	l.Log(ws)

	if got, want := l.Summary(), "2 requests, 1 error, 1.2 KB served"; got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}
}

func TestFitTarget(t *testing.T) {
	short := "/api/users?page=2"
	if got := fitTarget(short); got != short {
		t.Errorf("short targets should be unchanged: %q", got)
	}

	long := "/api/v1/very/long/path/that/goes/on?and=has&a=long&query=string-end"
	got := fitTarget(long)
	if len([]rune(got)) != targetWidth || !strings.Contains(got, "…") {
		t.Errorf("fitTarget() = %q, want %d runes cut in the middle", got, targetWidth)
	}
	if !strings.HasPrefix(got, "/api/v1/") || !strings.HasSuffix(got, "string-end") {
		t.Errorf("both ends should stay visible: %q", got)
	}
}

func TestLog_EscapesTerminalControls(t *testing.T) {
	e := testEntry()
	e.Target = "/ok\x1b[31m\r\nspoofed\u202e"
	e.Visitor = "1.2.3.4\x1b[2J"
	line := strings.TrimSuffix(strings.TrimPrefix(formatEntry(e), "\r"), "\r\n")
	withoutOwnColors := ansiPattern.ReplaceAllString(line, "")
	if strings.Contains(withoutOwnColors, "\x1b") || strings.ContainsAny(withoutOwnColors, "\r\n") {
		t.Errorf("request data should be escaped: %q", line)
	}
	for _, want := range []string{`\x1b`, `\x0d`, `\x0a`, `\u202e`} {
		if !strings.Contains(line, want) {
			t.Errorf("output missing escaped sequence %q: %q", want, line)
		}
	}
}

func TestHeader(t *testing.T) {
	h := plain(Header())
	for _, want := range []string{"TIME UTC", "METHOD", "PATH", "STATUS", "SIZE", "TOOK", "VISITOR"} {
		if !strings.Contains(h, want) {
			t.Errorf("header missing %q: %q", want, h)
		}
	}
}

func TestNotice(t *testing.T) {
	var buf bytes.Buffer
	l := NewRequestLogger(&buf, 16)
	l.Notice("Stopped. 3 requests.")
	l.Close()
	if got := plain(buf.String()); got != "\r  Stopped. 3 requests.\r\n" {
		t.Errorf("Notice() wrote %q", got)
	}
}

func TestNonBlocking(t *testing.T) {
	var buf bytes.Buffer
	l := NewRequestLogger(&buf, 1)

	// Send 100 lines with buffer size 1 — should not block
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			l.Log(testEntry())
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Log blocked with full buffer")
	}
	l.Close()
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write error")
}

func TestClosedWriter(t *testing.T) {
	l := NewRequestLogger(errorWriter{}, 16)
	// Should not panic even though writer returns errors
	l.Log(testEntry())
	l.Close()
}

func TestCloseIdempotent(t *testing.T) {
	var buf bytes.Buffer
	l := NewRequestLogger(&buf, 16)
	l.Close()
	l.Close() // second call should not panic
}

func TestLogAfterClose(t *testing.T) {
	var buf bytes.Buffer
	l := NewRequestLogger(&buf, 16)
	l.Close()

	// Requests and WebSockets can finish after the SSH session is gone
	late := testEntry()
	late.Target = "/late"
	l.Log(late)
	l.Notice("/late")

	if strings.Contains(buf.String(), "/late") {
		t.Errorf("logs after Close should be dropped: %q", buf.String())
	}
}

func TestLogConcurrentWithClose(t *testing.T) {
	l := NewRequestLogger(io.Discard, 16)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				l.Log(testEntry())
			}
		}()
	}
	l.Close()
	wg.Wait()
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1572864, "1.5 MB"},
		{2469606195, "2.3 GB"},
	}
	for _, tt := range tests {
		if got := FormatBytes(tt.bytes); got != tt.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{5 * time.Second, "5s"},
		{2*time.Minute + 30*time.Second, "2m30s"},
		{time.Hour + 5*time.Minute, "1h5m"},
		{3 * time.Minute, "3m"},
		{2 * time.Hour, "2h"},
	}
	for _, tt := range tests {
		if got := FormatDuration(tt.d); got != tt.want {
			t.Errorf("FormatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestFormatLatency(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{500 * time.Microsecond, "<1ms"},
		{12 * time.Millisecond, "12ms"},
		{1500 * time.Millisecond, "1.5s"},
	}
	for _, tt := range tests {
		if got := formatLatency(tt.d); got != tt.want {
			t.Errorf("formatLatency(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}
