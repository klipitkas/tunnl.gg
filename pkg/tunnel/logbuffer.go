package tunnel

import (
	"bytes"
	"encoding/json"
	"sync"
)

// Bound pooled retention and write batches; unusually large lines still pass
// through intact, but their backing storage is not kept for future requests.
const maxLogBuffer = 32 * 1024

var logBuffers = sync.Pool{New: func() any {
	return bytes.NewBuffer(make([]byte, 0, 512))
}}

func getLogBuffer() *bytes.Buffer {
	return logBuffers.Get().(*bytes.Buffer)
}

func putLogBuffer(b *bytes.Buffer) {
	if b.Cap() <= maxLogBuffer {
		b.Reset()
		logBuffers.Put(b)
	}
}

func jsonLogBuffer(v any) *bytes.Buffer {
	b := getLogBuffer()
	enc := json.NewEncoder(b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		putLogBuffer(b)
		return nil
	}
	// Encoder adds a newline. Reuse its bytes and extend it to terminal CRLF.
	b.Bytes()[b.Len()-1] = '\r'
	_ = b.WriteByte('\n')
	return b
}
