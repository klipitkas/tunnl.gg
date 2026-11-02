package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

func TestE2E_PasswordAllowlistAndHost(t *testing.T) {
	srv, addr := startSSHServer(t)
	tt := openTunnelCommand(t, srv, addr, anonymousClient(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s fwd=%s auth=%s", r.Host, r.Header.Get("X-Forwarded-Host"), r.Header.Get("Authorization"))
	}), "host=localhost:5173 auth=me:pa:ss allow=127.0.0.1,198.51.100.0/24")

	waitFor(t, "options in the banner", func() bool {
		out := tt.output.String()
		return strings.Contains(out, "visitors sign in as "+bannerReset+"me") &&
			strings.Contains(out, "localhost:5173"+bannerGray+" is sent to your app") &&
			strings.Contains(out, "127.0.0.1, 198.51.100.0/24")
	})

	do := func(user, pass string) (*http.Response, string) {
		req, _ := http.NewRequest(http.MethodGet, tt.public.URL+"/", nil)
		req.Host = tt.host()
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := tt.public.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, string(body)
	}

	resp, _ := do("", "")
	if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic realm=") {
		t.Errorf("without a password: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if resp, _ := do("me", "wrong"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", resp.StatusCode)
	}
	resp, body := do("me", "pa:ss")
	if want := "host=localhost:5173 fwd=" + tt.host() + " auth="; resp.StatusCode != http.StatusOK || body != want {
		t.Errorf("with the password: %d %q, want %q", resp.StatusCode, body, want)
	}

	// From outside the allowlist, even with the password
	if rec := tt.serveDirect("203.0.113.9:1234", map[string]string{"Authorization": "Basic bWU6cGE6c3M="}); rec.Code != http.StatusForbidden {
		t.Errorf("from outside the allowlist: %d", rec.Code)
	}
	waitFor(t, "refusals in the request log", func() bool {
		out := tt.output.String()
		return strings.Contains(out, "no or wrong password") && strings.Contains(out, "not on the tunnel's allowlist")
	})
}

func TestE2E_HostRedirectsBackToPublicHost(t *testing.T) {
	srv, addr := startSSHServer(t)
	tt := openTunnelCommand(t, srv, addr, anonymousClient(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=1; Path=/; Domain="+r.Host+"; HttpOnly")
		w.Header().Add("Set-Cookie", "other=1; Domain=example.com")
		http.Redirect(w, r, r.URL.Query().Get("to"), http.StatusFound)
	}), "host=myapp.test")

	client := *tt.public.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	get := func(to string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, tt.public.URL+"/?to="+url.QueryEscape(to), nil)
		req.Host = tt.host()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}

	public := strings.SplitN(tt.public.URL, ":", 2)[0] + "://" + tt.host()
	for to, want := range map[string]string{
		"http://myapp.test/login?x=1": public + "/login?x=1",
		"http://MyApp.test:80/":       public + "/",
		"//myapp.test/a":              "//" + tt.host() + "/a",
		"/dashboard":                  "/dashboard",
		"http://myapp.test:8080/":     "http://myapp.test:8080/",
		"https://accounts.example/":   "https://accounts.example/",
	} {
		if got := get(to).Header.Get("Location"); got != want {
			t.Errorf("app redirect to %q: Location %q, want %q", to, got, want)
		}
	}
	cookies := get("/").Header.Values("Set-Cookie")
	if want := []string{"session=1; Path=/; HttpOnly", "other=1; Domain=example.com"}; strings.Join(cookies, "|") != strings.Join(want, "|") {
		t.Errorf("Set-Cookie %q, want %q", cookies, want)
	}
}

// runCommand connects anonymously with a tunnel request and command, and
// returns the session's output and exit status.
func runCommand(t *testing.T, srv *Server, addr, command string) (string, int) {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, anonymousClient())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Listen("tcp", "0.0.0.0:80"); err != nil {
		t.Fatal(err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out := &syncBuffer{}
	session.Stdout = out
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the session didn't end")
	}
	var exit *ssh.ExitError
	switch {
	case err == nil:
		return out.String(), 0
	case errors.As(err, &exit):
		return out.String(), exit.ExitStatus()
	}
	t.Fatalf("session error: %v", err)
	return "", 0
}

func TestE2E_OptionErrors(t *testing.T) {
	srv, addr := startSSHServer(t)

	out, status := runCommand(t, srv, addr, "auth=nopassword")
	if status != 1 || !strings.Contains(out, "auth= needs a user name and a password") || !strings.Contains(out, "allow=") {
		t.Errorf("invalid option: status %d, output %q", status, out)
	}
	out, status = runCommand(t, srv, addr, "help")
	if status != 0 || !strings.Contains(out, "host=localhost:3000") || strings.Contains(out, "ERROR") {
		t.Errorf("help: status %d, output %q", status, out)
	}
	waitFor(t, "the refused tunnels to close", func() bool { return len(srv.Tunnels()) == 0 })
}

func TestE2E_OptionsLimitedByPlan(t *testing.T) {
	srv, addr := startSSHServer(t)
	free := config.FreeLimits()
	free.Options = []string{config.OptionHost}
	free.OptionsNote = "Passwords come with Pro."
	srv.SetFreeLimits(free)

	out, status := runCommand(t, srv, addr, "host=localhost auth=me:secret")
	if status != 1 || !strings.Contains(out, "auth= isn't available for this tunnel. Passwords come with Pro.") {
		t.Errorf("status %d, output %q", status, out)
	}
	// Allowed options still work
	tt := openTunnelCommand(t, srv, addr, anonymousClient(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Host)
	}), "host=localhost")
	resp := tt.get(t, "/")
	if body, _ := io.ReadAll(resp.Body); string(body) != "localhost" {
		t.Errorf("host= with the free plan: %q", body)
	}
}

func TestE2E_PasswordGuessingLimited(t *testing.T) {
	srv, addr := startSSHServer(t)
	tt := openTunnelCommand(t, srv, addr, anonymousClient(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}), "auth=me:right")

	try := func(pass string) int {
		headers := map[string]string{}
		if pass != "" {
			headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte("me:"+pass))
		}
		return tt.serveDirect("198.51.100.7:1234", headers).Code
	}
	// Asking without credentials, as browsers do first, doesn't count
	for range config.PasswordFailureBurst * 2 {
		if code := try(""); code != http.StatusUnauthorized {
			t.Fatalf("without credentials: %d", code)
		}
	}
	for i := range config.PasswordFailureBurst {
		if code := try(fmt.Sprint("guess", i)); code != http.StatusUnauthorized {
			t.Fatalf("guess %d: %d", i, code)
		}
	}
	// Out of tries: even the right password isn't checked
	if code := try("right"); code != http.StatusTooManyRequests {
		t.Errorf("after %d wrong passwords: %d, want 429", config.PasswordFailureBurst, code)
	}
	// Other visitors aren't affected
	if rec := tt.serveDirect("203.0.113.1:1234", map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("me:right"))}); rec.Code != http.StatusOK {
		t.Errorf("another visitor with the password: %d", rec.Code)
	}
}

func TestE2E_AccountSavedOptions(t *testing.T) {
	srv, addr := startSSHServer(t)
	key := newTestKey(t)
	acct := &Account{ID: "acct_pro", Limits: config.Limits{Options: config.AllOptions}, Subdomain: "myapp",
		Subdomains: map[string]tunnel.Options{"myapp": {Host: "saved.test", Auth: tunnel.NewBasicAuth("me", func(p string) bool { return p == "saved" })}}}
	withAccounts(srv, []ssh.Signer{key}, []*Account{acct})

	tt := openTunnelCommand(t, srv, addr, accountClient(key), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Host)
	}), "host=cmd.test")
	if !strings.Contains(tt.output.String(), "visitors sign in as "+bannerReset+"me") {
		t.Errorf("the banner should show the saved password: %q", tt.output.String())
	}
	try := func(pass string) (int, string) {
		headers := map[string]string{}
		if pass != "" {
			headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte("me:"+pass))
		}
		rec := tt.serveDirect("198.51.100.7:1234", headers)
		return rec.Code, rec.Body.String()
	}
	if code, _ := try(""); code != http.StatusUnauthorized {
		t.Errorf("saved password not asked for: %d", code)
	}
	// The command's host= overrides the saved one; the saved password stays
	if code, body := try("saved"); code != http.StatusOK || body != "cmd.test" {
		t.Errorf("with the saved password: %d %q", code, body)
	}

	// Changing the settings applies to the open tunnel
	if !srv.SetTunnelOptions("acct_pro", "myapp", tunnel.Options{}) {
		t.Fatal("SetTunnelOptions() found no tunnel")
	}
	if code, _ := try(""); code != http.StatusOK {
		t.Errorf("after removing the password: %d", code)
	}
	if srv.SetTunnelOptions("acct_other", "myapp", tunnel.Options{}) {
		t.Error("another account changed the tunnel's settings")
	}
}
