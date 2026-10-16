package tunnel

import (
	"strings"
	"testing"
)

type logAckWriter struct{ done chan struct{} }

func (w logAckWriter) Write(p []byte) (int, error) {
	w.done <- struct{}{}
	return len(p), nil
}

func BenchmarkFitTarget(b *testing.B) {
	for _, tc := range []struct{ name, target string }{
		{"short", "/api/hooks?source=test"},
		{"long", "/api/" + strings.Repeat("segment/", 8192) + "?end=yes"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if got := fitTarget(tc.target); got == "" {
					b.Fatal("empty path")
				}
			}
		})
	}
}

// Wait for each write so a full queue cannot make dropped logs look faster.
func BenchmarkRequestLogger(b *testing.B) {
	for _, json := range []bool{false, true} {
		name := "terminal"
		if json {
			name = "json"
		}
		b.Run(name, func(b *testing.B) {
			w := logAckWriter{make(chan struct{})}
			var l *RequestLogger
			if json {
				l = NewJSONRequestLogger(w, 16)
			} else {
				l = NewRequestLogger(w, 16)
			}
			defer l.Close()
			e := testEntry()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				l.Log(e)
				<-w.done
			}
		})
	}
}
