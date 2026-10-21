package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

func TestProxyResponseStateLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name       string
		length     int64
		readErr    error
		backendErr error
		writeErr   error
		status     int
		abort      bool
		wantCloses int
		wantNote   string
	}{
		{name: "complete", length: 5, status: 201, wantCloses: 1},
		{name: "unknown length", length: -1, status: 201, wantCloses: 1},
		{name: "declared too large", length: config.MaxResponseBodySize + 1, status: 502, wantCloses: 1, wantNote: "not sent"},
		{name: "backend failure", backendErr: io.ErrUnexpectedEOF, status: 502, wantNote: "couldn't get a response"},
		{name: "body failure", length: -1, readErr: io.ErrUnexpectedEOF, status: 201, abort: true, wantCloses: 1, wantNote: "your local app stopped sending: unexpected EOF"},
		{name: "visitor failure", length: 5, writeErr: io.ErrClosedPipe, status: 201, abort: true, wantCloses: 1, wantNote: "visitor left"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			tun := tunnel.New("response-state", nil, "", 80, "")
			defer tun.Close()
			tun.EnableInspector()
			body := &responseStateBody{Reader: strings.NewReader("hello"), err: tc.readErr}
			tun.Transport().RegisterProtocol("http", responseStateTransport{body: body, length: tc.length, err: tc.backendErr})
			s.tunnels[tun.Subdomain] = tun
			r := httptest.NewRequest(http.MethodGet, "https://response-state.tunnl.gg/", nil)
			// Match a real HTTP server: failed body copies must abort the handler.
			r = r.WithContext(context.WithValue(r.Context(), http.ServerContextKey, &http.Server{}))
			w := &responseStateWriter{allocationRecorder: &allocationRecorder{httptest.NewRecorder()}, err: tc.writeErr}
			var caught any
			func() {
				defer func() { caught = recover() }()
				s.ServeHTTP(w, r)
			}()
			if (tc.abort && caught != http.ErrAbortHandler) || (!tc.abort && caught != nil) {
				t.Fatalf("panic = %v, abort expected = %v", caught, tc.abort)
			}
			if w.Code != tc.status || body.closes != tc.wantCloses {
				t.Fatalf("status=%d closes=%d, want %d/%d", w.Code, body.closes, tc.status, tc.wantCloses)
			}
			exchanges := tun.Inspector().List()
			if len(exchanges) != 1 || exchanges[0].Status != tc.status || !strings.Contains(exchanges[0].Note, tc.wantNote) {
				t.Fatalf("unexpected inspection: %+v", exchanges)
			}
			if tc.wantNote == "" && (w.Body.String() != "hello" || string(exchanges[0].ResponseBody.Data) != "hello" || exchanges[0].Note != "") {
				t.Fatalf("successful response or inspection changed: %+v", exchanges[0])
			}
		})
	}
}

type responseStateBody struct {
	*strings.Reader
	err    error
	closes int
}

func (b *responseStateBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if errors.Is(err, io.EOF) && b.err != nil {
		err = b.err
	}
	return n, err
}

func (b *responseStateBody) Close() error { b.closes++; return nil }

type responseStateTransport struct {
	body   io.ReadCloser
	length int64
	err    error
}

func (t responseStateTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.err != nil {
		return nil, t.err
	}
	return &http.Response{StatusCode: 201, Header: make(http.Header), Body: t.body, ContentLength: t.length, Request: r}, nil
}

type responseStateWriter struct {
	*allocationRecorder
	err error
}

func (w *responseStateWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	return w.allocationRecorder.Write(p)
}
