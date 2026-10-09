package tunnel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Terminal colors for the request log.
const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[38;5;245m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
)

// Column widths of a request log line.
const (
	indentWidth  = 2
	timeWidth    = 8 // "15:04:05"
	methodWidth  = 7 // "OPTIONS"
	targetWidth  = 40
	statusWidth  = 6 // "STATUS"
	sizeWidth    = 8 // "999.9 KB"
	latencyWidth = 6 // "10.0s"
)

// tunnlNotesPerSecond caps how many lines are shown for events handled by
// tunnl itself, such as throttled visitors, so a flood can't flood the terminal.
const tunnlNotesPerSecond = 5

// Entry is one request, WebSocket, or tunnl event in the request log.
type Entry struct {
	Time    time.Time
	Method  string        // HTTP method, or "WS" for a WebSocket
	Target  string        // path and query string
	Status  int           // HTTP status, or 0 if there is none
	Bytes   int64         // response body size, or -1 if not applicable
	Latency time.Duration // time to respond, or 0 if not applicable
	Visitor string        // visitor IP address
	Note    string        // shown at the end of the line
	Detail  string        // explanation shown on its own line underneath
	// FromTunnl marks events handled by tunnl rather than the tunneled app.
	FromTunnl bool
}

// RequestLogger writes formatted request logs to an io.Writer (typically an SSH channel).
// It uses a buffered channel and a single drain goroutine to avoid blocking callers.
// Logging after Close is a no-op, since requests and WebSockets can outlive the
// SSH session they are logged to.
type RequestLogger struct {
	w      io.Writer
	ch     chan string
	done   chan struct{}
	mu     sync.RWMutex // guards closed and sending on ch against close(ch)
	closed bool
	json   bool // one JSON object per line instead of a table, for scripts and agents

	statsMu     sync.Mutex // guards the fields below
	requests    int
	errors      int   // 5xx responses
	bytes       int64 // response bytes served
	turnedAway  int   // requests turned away by tunnl
	notes       *RateLimiter
	notesHidden int // tunnl notes left out since the last one shown
}

// NewRequestLogger creates a RequestLogger that writes to w with the given buffer size.
func NewRequestLogger(w io.Writer, bufSize int) *RequestLogger {
	l := &RequestLogger{
		w:     w,
		ch:    make(chan string, bufSize),
		done:  make(chan struct{}),
		notes: NewRateLimiter(tunnlNotesPerSecond, tunnlNotesPerSecond),
	}
	go l.drain()
	return l
}

// NewJSONRequestLogger is NewRequestLogger for output=json: every entry and
// notice is a JSON object on a line of its own.
func NewJSONRequestLogger(w io.Writer, bufSize int) *RequestLogger {
	l := NewRequestLogger(w, bufSize)
	l.json = true
	return l
}

// drain reads from the channel and writes to the underlying writer.
func (l *RequestLogger) drain() {
	defer close(l.done)
	for line := range l.ch {
		l.w.Write([]byte(line))
	}
}

// send queues a line without blocking, dropping it if the buffer is full or the
// logger is closed.
func (l *RequestLogger) send(line string) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return
	}
	select {
	case l.ch <- line:
	default:
	}
}

// Log counts an entry and writes it to the log. Entries from tunnl itself are
// rate limited; the next one shown says how many were left out.
func (l *RequestLogger) Log(e Entry) {
	l.statsMu.Lock()
	switch {
	case e.FromTunnl:
		if e.Status >= 400 {
			l.turnedAway++
		}
	case e.Status > 0:
		l.requests++
		if e.Status >= 500 {
			l.errors++
		}
		if e.Bytes > 0 {
			l.bytes += e.Bytes
		}
	}
	if e.FromTunnl {
		if !l.notes.Allow() {
			l.notesHidden++
			l.statsMu.Unlock()
			return
		}
		if l.notesHidden > 0 {
			e.Note += fmt.Sprintf(" (+%d similar not shown)", l.notesHidden)
			l.notesHidden = 0
		}
	}
	l.statsMu.Unlock()

	if l.json {
		l.send(JSONLine(jsonEntry(e)))
		return
	}
	l.send(formatEntry(e))
}

// Notice writes a message line to the log, such as a warning or a summary.
func (l *RequestLogger) Notice(message string) {
	if l.json {
		l.send(JSONLine(map[string]string{"event": "notice", "message": message}))
		return
	}
	l.send("\r" + strings.Repeat(" ", indentWidth) + colorYellow + sanitizeTerminalText(message) + colorReset + "\r\n")
}

// JSONLine encodes v as one line of output=json. Lines end in \r\n, which
// JSON parsers read as whitespace, so they look right in a terminal too.
// Control characters are escaped, so a value can't reach the terminal raw.
func JSONLine(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return strings.TrimSuffix(b.String(), "\n") + "\r\n"
}

// requestJSON is a request log entry in output=json.
type requestJSON struct {
	Event      string `json:"event"` // "request"
	Time       string `json:"time"`  // RFC 3339, UTC
	Method     string `json:"method"`
	Path       string `json:"path"`
	Status     int    `json:"status,omitempty"`
	Bytes      *int64 `json:"bytes,omitempty"`
	DurationMS *int64 `json:"duration_ms,omitempty"`
	Visitor    string `json:"visitor,omitempty"`
	Note       string `json:"note,omitempty"`
	Detail     string `json:"detail,omitempty"`
	FromTunnl  bool   `json:"from_tunnl,omitempty"` // handled by tunnl, not your app
}

func jsonEntry(e Entry) requestJSON {
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

// Summary describes the traffic logged so far, e.g. "12 requests, 1 error, 3.4 KB served".
func (l *RequestLogger) Summary() string {
	l.statsMu.Lock()
	defer l.statsMu.Unlock()
	parts := []string{plural(l.requests, "request")}
	if l.errors > 0 {
		parts = append(parts, plural(l.errors, "error"))
	}
	if l.bytes > 0 {
		parts = append(parts, formatBytes(l.bytes)+" served")
	}
	if l.turnedAway > 0 {
		parts = append(parts, fmt.Sprintf("%d turned away by tunnl", l.turnedAway))
	}
	return strings.Join(parts, ", ")
}

// Close stops the logger, draining any remaining messages. It is idempotent.
func (l *RequestLogger) Close() {
	l.stop()
	<-l.done
}

// CloseWithin is Close, but waits at most timeout for the remaining messages
// to be written. It reports whether they were. A writer that stays blocked
// keeps the drain goroutine running until the write fails.
func (l *RequestLogger) CloseWithin(timeout time.Duration) bool {
	l.stop()
	select {
	case <-l.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// stop stops accepting messages and lets drain finish once the queue is empty.
func (l *RequestLogger) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		close(l.ch)
	}
}

// Header returns the column headings of the request log.
func Header() string {
	return "\r" + strings.Repeat(" ", indentWidth) + colorDim +
		fmt.Sprintf("%-*s  %-*s  %-*s  %-*s  %*s  %*s  %s",
			timeWidth, "TIME UTC", methodWidth, "METHOD", targetWidth, "PATH",
			statusWidth, "STATUS", sizeWidth, "SIZE", latencyWidth, "TOOK", "VISITOR") +
		colorReset + "\r\n"
}

// Log lines start with \r so they begin at the left edge even when other output
// in the same terminal, such as a local server's own logs written with a bare
// \n, has left the cursor partway along a line.
func formatEntry(e Entry) string {
	var b strings.Builder
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
		size = formatBytes(e.Bytes)
	}
	b.WriteString(colorDim + fmt.Sprintf("%*s", sizeWidth, size) + colorReset + "  ")

	latency := ""
	if e.Latency > 0 {
		latency = formatLatency(e.Latency)
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
	return b.String()
}

// fitTarget escapes a request target and shortens it to the path column,
// cutting from the middle so the start of the path and the end of the query
// string both stay visible.
func fitTarget(target string) string {
	runes := []rune(sanitizeTerminalText(target))
	if len(runes) <= targetWidth {
		return string(runes)
	}
	head := (targetWidth - 1) / 2
	tail := targetWidth - 1 - head
	return string(runes[:head]) + "…" + string(runes[len(runes)-tail:])
}

func methodColor(method string) string {
	switch method {
	case "GET":
		return colorGreen
	case "POST":
		return colorYellow
	case "PUT":
		return colorBlue
	case "PATCH":
		return colorMagenta
	case "DELETE":
		return colorRed
	case "WS":
		return colorCyan
	default:
		return colorDim
	}
}

func statusColor(status int) string {
	switch {
	case status >= 500:
		return colorBold + colorRed
	case status >= 400:
		return colorBold + colorYellow
	case status >= 300:
		return colorBold + colorCyan
	default:
		return colorBold + colorGreen
	}
}

func latencyColor(d time.Duration) string {
	switch {
	case d >= 5*time.Second:
		return colorRed
	case d >= time.Second:
		return colorYellow
	default:
		return ""
	}
}

func formatLatency(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return "<1ms"
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	default:
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
}

// FormatDuration formats a duration for people, e.g. "2m31s" or "1h5m".
func FormatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) - m*60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm%ds", m, s)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) - h*60
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}

// FormatBytes formats a byte count for people, e.g. "1.2 MB".
func FormatBytes(b int64) string {
	return formatBytes(b)
}

func formatBytes(b int64) string {
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

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func sanitizeTerminalText(s string) string {
	for _, r := range s {
		if isUnsafeTerminalRune(r) {
			return escapeTerminalText(s)
		}
	}
	return s
}

func escapeTerminalText(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if !isUnsafeTerminalRune(r) {
			out = append(out, r)
			continue
		}
		escaped := fmt.Sprintf("\\x%02x", r)
		if r > 0xff {
			escaped = fmt.Sprintf("\\u%04x", r)
		}
		out = append(out, []rune(escaped)...)
	}
	return string(out)
}

func isUnsafeTerminalRune(r rune) bool {
	return r < 0x20 || r == 0x7f || unicode.Is(unicode.Cf, r)
}
