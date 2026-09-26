package tunnel

import (
	"fmt"
	"io"
	"sync"
	"time"
	"unicode"
)

const maxPathDisplay = 50

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
}

// NewRequestLogger creates a RequestLogger that writes to w with the given buffer size.
func NewRequestLogger(w io.Writer, bufSize int) *RequestLogger {
	l := &RequestLogger{
		w:    w,
		ch:   make(chan string, bufSize),
		done: make(chan struct{}),
	}
	go l.drain()
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

// LogRequest logs an HTTP request with method, path, status, and latency.
func (l *RequestLogger) LogRequest(method, path string, status int, latency time.Duration) {
	l.send(formatRequestLog(method, path, status, latency))
}

// LogWebSocketOpen logs a WebSocket connection opening.
func (l *RequestLogger) LogWebSocketOpen(path string) {
	l.send(formatWSOpen(path))
}

// LogWebSocketClose logs a WebSocket connection closing with duration and bytes transferred.
func (l *RequestLogger) LogWebSocketClose(path string, duration time.Duration, bytes int64) {
	l.send(formatWSClose(path, duration, bytes))
}

// Close stops the logger, draining any remaining messages. It is idempotent.
func (l *RequestLogger) Close() {
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.ch)
	}
	l.mu.Unlock()
	<-l.done
}

func truncatePath(path string) string {
	path = sanitizeTerminalText(path)
	if len(path) > maxPathDisplay {
		runes := []rune(path)
		if len(runes) > maxPathDisplay {
			return string(runes[:maxPathDisplay-3]) + "..."
		}
	}
	return path
}

func formatRequestLog(method, path string, status int, latency time.Duration) string {
	return fmt.Sprintf("  %-4s %-53s %d  %s\r\n", sanitizeTerminalText(method), truncatePath(path), status, formatLatency(latency))
}

func formatWSOpen(path string) string {
	return fmt.Sprintf("  %-4s %-53s -    OPEN\r\n", "WS", truncatePath(path))
}

func formatWSClose(path string, duration time.Duration, bytes int64) string {
	return fmt.Sprintf("  %-4s %-53s -    CLOSED (%s, %s)\r\n", "WS", truncatePath(path), formatDurationHuman(duration), formatBytes(bytes))
}

func formatLatency(d time.Duration) string {
	if d < time.Millisecond {
		us := d.Microseconds()
		if us == 0 {
			return "<1us"
		}
		return fmt.Sprintf("%dus", us)
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

func formatDurationHuman(d time.Duration) string {
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

func formatBytes(b int64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%dB", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	case b < 1024*1024*1024:
		return fmt.Sprintf("%.1fMB", float64(b)/(1024*1024))
	default:
		return fmt.Sprintf("%.1fGB", float64(b)/(1024*1024*1024))
	}
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
