package tunnel

import (
	"fmt"
	"io"
	"sync"
	"time"
)

const maxPathDisplay = 50

// RequestLogger writes formatted request logs to an io.Writer (typically an SSH channel).
// It uses a buffered channel and a single drain goroutine to avoid blocking callers.
type RequestLogger struct {
	w      io.Writer
	ch     chan string
	done   chan struct{}
	closeOnce sync.Once
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

// LogRequest logs an HTTP request with method, path, status, and latency.
func (l *RequestLogger) LogRequest(method, path string, status int, latency time.Duration) {
	line := formatRequestLog(method, path, status, latency)
	select {
	case l.ch <- line:
	default:
	}
}

// LogWebSocketOpen logs a WebSocket connection opening.
func (l *RequestLogger) LogWebSocketOpen(path string) {
	line := formatWSOpen(path)
	select {
	case l.ch <- line:
	default:
	}
}

// LogWebSocketClose logs a WebSocket connection closing with duration and bytes transferred.
func (l *RequestLogger) LogWebSocketClose(path string, duration time.Duration, bytes int64) {
	line := formatWSClose(path, duration, bytes)
	select {
	case l.ch <- line:
	default:
	}
}

// Close stops the logger, draining any remaining messages. It is idempotent.
func (l *RequestLogger) Close() {
	l.closeOnce.Do(func() {
		close(l.ch)
	})
	<-l.done
}

func truncatePath(path string) string {
	if len(path) > maxPathDisplay {
		return path[:maxPathDisplay-3] + "..."
	}
	return path
}

func formatRequestLog(method, path string, status int, latency time.Duration) string {
	return fmt.Sprintf("  %-4s %-53s %d  %s\r\n", method, truncatePath(path), status, formatLatency(latency))
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
