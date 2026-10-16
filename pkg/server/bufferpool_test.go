package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strconv"
	"sync"
	"testing"
)

type responseTransport struct{ payload []byte }

func (t responseTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: make(http.Header),
		Body: io.NopCloser(bytes.NewReader(t.payload)), ContentLength: int64(len(t.payload)), Request: r}, nil
}

func copyProxy(pool httputil.BufferPool, payload []byte) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "http"
			r.Out.URL.Host = "fixture"
		},
		BufferPool: pool,
		Transport:  responseTransport{payload},
	}
}

// Exercise concurrent responses of different sizes through the real proxy:
// a pooled buffer must neither cross-contaminate visitors nor truncate bodies.
func TestProxyBufferPoolConcurrentResponses(t *testing.T) {
	var pool proxyBufferPool
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := bytes.Repeat([]byte{byte(i + 1)}, 1+i*4096)
			proxy := copyProxy(&pool, payload)
			for range 10 {
				w := httptest.NewRecorder()
				proxy.ServeHTTP(w, httptest.NewRequest("GET", "http://fixture/", nil))
				if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), payload) {
					t.Errorf("response %d: wrong status, truncated body or cross-contamination", i)
					return
				}
			}
		}()
	}
	wg.Wait()
}

type discardResponseWriter struct{ header http.Header }

func (w discardResponseWriter) Header() http.Header       { return w.header }
func (discardResponseWriter) WriteHeader(int)             {}
func (discardResponseWriter) Write(b []byte) (int, error) { return len(b), nil }

// Isolate proxy copying from network latency to compare allocation cost.
func BenchmarkProxyResponseBuffers(b *testing.B) {
	for _, size := range []int{1024, 65536} {
		for _, pooled := range []bool{false, true} {
			b.Run(strconv.Itoa(size)+"/pooled="+strconv.FormatBool(pooled), func(b *testing.B) {
				var pool httputil.BufferPool
				if pooled {
					pool = &proxyBufferPool{}
				}
				proxy := copyProxy(pool, make([]byte, size))
				r := httptest.NewRequest("GET", "http://fixture/", nil)
				w := discardResponseWriter{make(http.Header)}
				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()
				for range b.N {
					proxy.ServeHTTP(w, r)
				}
			})
		}
	}
}
