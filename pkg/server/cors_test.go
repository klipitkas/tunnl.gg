package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestE2E_CORS(t *testing.T) {
	srv, addr := startSSHServer(t)
	appSetsItsOwn := false
	tt := openTunnelCommand(t, srv, addr, anonymousClient(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if appSetsItsOwn {
			w.Header().Set("Access-Control-Allow-Origin", "https://app.example.com")
		}
		io.WriteString(w, "hi")
	}), "auth=me:secret cors=https://app.example.com")
	waitFor(t, "CORS in the banner", func() bool { return strings.Contains(tt.output.String(), "https://app.example.com") })

	send := func(method, origin string, headers map[string]string) *http.Response {
		req, _ := http.NewRequest(method, tt.public.URL+"/api", nil)
		req.Host = tt.host()
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := tt.public.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp
	}

	// A preflight is answered by tunnl, without the password browsers don't send
	pre := send(http.MethodOptions, "https://app.example.com", map[string]string{"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type,x-token"})
	if pre.StatusCode != http.StatusNoContent || pre.Header.Get("Access-Control-Allow-Origin") != "https://app.example.com" ||
		pre.Header.Get("Access-Control-Allow-Credentials") != "true" || pre.Header.Get("Access-Control-Allow-Methods") != "POST" ||
		pre.Header.Get("Access-Control-Allow-Headers") != "content-type,x-token" {
		t.Errorf("preflight: %d %v", pre.StatusCode, pre.Header)
	}
	// The real request still needs the password, and both answers can be read
	if r := send(http.MethodGet, "https://app.example.com", nil); r.StatusCode != http.StatusUnauthorized || r.Header.Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("without the password: %d %v", r.StatusCode, r.Header)
	}
	auth := map[string]string{"Authorization": "Basic bWU6c2VjcmV0"}
	if r := send(http.MethodGet, "https://app.example.com", auth); r.StatusCode != http.StatusOK || r.Header.Get("Access-Control-Allow-Origin") != "https://app.example.com" || r.Header.Get("Vary") != "Origin" {
		t.Errorf("with the password: %d %v", r.StatusCode, r.Header)
	}
	// Other sites get nothing, and their preflight goes to the app like any request
	if r := send(http.MethodGet, "https://evil.example", auth); r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("an unlisted origin got %q", r.Header.Get("Access-Control-Allow-Origin"))
	}
	if r := send(http.MethodOptions, "https://evil.example", map[string]string{"Access-Control-Request-Method": "POST"}); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("an unlisted origin's preflight: %d", r.StatusCode)
	}
	// An app that sets its own isn't doubled up
	appSetsItsOwn = true
	if r := send(http.MethodGet, "https://app.example.com", auth); len(r.Header.Values("Access-Control-Allow-Origin")) != 1 {
		t.Errorf("Access-Control-Allow-Origin = %v", r.Header.Values("Access-Control-Allow-Origin"))
	}
	// Errors from tunnl can be read too
	tt.local.Close()
	if r := send(http.MethodGet, "https://app.example.com", auth); r.StatusCode != http.StatusBadGateway || r.Header.Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("a 502: %d %v", r.StatusCode, r.Header)
	}
}

func TestE2E_CORSAnyOrigin(t *testing.T) {
	srv, addr := startSSHServer(t)
	tt := openTunnelCommand(t, srv, addr, anonymousClient(), echoBackend("hi"), "cors=*")
	req, _ := http.NewRequest(http.MethodGet, tt.public.URL+"/", nil)
	req.Host = tt.host()
	req.Header.Set("Origin", "https://anywhere.example")
	resp, err := tt.public.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" || resp.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Errorf("cors=*: %v", resp.Header)
	}
}
