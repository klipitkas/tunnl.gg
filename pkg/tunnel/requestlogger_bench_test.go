package tunnel

import "testing"

type logAckWriter struct{ done chan struct{} }

func (w logAckWriter) Write(p []byte) (int, error) {
	w.done <- struct{}{}
	return len(p), nil
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
