package server

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

func TestE2E_ChooseSubdomainByName(t *testing.T) {
	srv, addr := startSSHServer(t)
	key := newTestKey(t)
	acct := &Account{ID: "acct_pro", Limits: config.Limits{MaxTunnels: 10, Options: config.AllOptions}, Subdomain: "myapp",
		Subdomains: map[string]tunnel.Options{"myapp": {}, "api": {Host: "api.saved"}}}
	withAccounts(srv, []ssh.Signer{key}, []*Account{acct})
	hostEcho := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.Host) })

	// One key, two subdomains at once: a name picks one, no name the default
	api := openTunnelAt(t, srv, addr, accountClient(key), hostEcho, "api:80", "")
	def := openTunnelAt(t, srv, addr, accountClient(key), hostEcho, "0.0.0.0:80", "")
	if api.sub != "api" || def.sub != "myapp" {
		t.Fatalf("got %q and %q, want api and myapp", api.sub, def.sub)
	}
	// Each gets its own saved settings
	if body, _ := io.ReadAll(api.get(t, "/").Body); string(body) != "api.saved" {
		t.Errorf("api's saved Host header: app got %q", body)
	}
	if body, _ := io.ReadAll(def.get(t, "/").Body); string(body) != def.host() {
		t.Errorf("myapp: app got %q", body)
	}
	if !strings.Contains(api.output.String(), "reserved for your account") {
		t.Error("the banner should say the subdomain is reserved")
	}
	// The name can be the full domain too
	full := openTunnelAt(t, srv, addr, accountClient(key), hostEcho, "api.tunnl.gg:80", "")
	if full.sub != "api" {
		t.Errorf("api.tunnl.gg opened %q", full.sub)
	}
}

func TestE2E_ChooseSubdomainRefused(t *testing.T) {
	srv, addr := startSSHServer(t)
	key := newTestKey(t)
	withAccounts(srv, []ssh.Signer{key}, []*Account{{ID: "acct_pro", Limits: config.Limits{MaxTunnels: 10},
		Subdomains: map[string]tunnel.Options{"myapp": {}}}})

	client, err := ssh.Dial("tcp", addr, accountClient(key))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Listen("tcp", "someone-else:80"); err == nil {
		t.Fatal("forwarding a subdomain the account doesn't have should fail")
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	// Read the output directly: the server sends the error and closes the
	// session without waiting for the shell request, as OpenSSH shows it
	stdout, _ := session.StdoutPipe()
	out := &syncBuffer{}
	go io.Copy(out, stdout)
	session.Shell()
	waitFor(t, "the error", func() bool {
		return strings.Contains(out.String(), "someone-else isn't one of your account's subdomains")
	})
	if len(srv.Tunnels()) != 0 {
		t.Error("a refused forward left a tunnel")
	}
}

func TestE2E_AnonymousNameIgnored(t *testing.T) {
	srv, addr := startSSHServer(t)
	tt := openTunnelAt(t, srv, addr, anonymousClient(), echoBackend("hi"), "myapp:80", "")
	if tt.sub == "myapp" {
		t.Fatal("an anonymous client got the subdomain it named")
	}
	waitFor(t, "the note", func() bool {
		return strings.Contains(tt.output.String(), "myapp ignored: choosing a subdomain needs an account")
	})
}
