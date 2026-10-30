package server

import (
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

// refusedForward asks for a tunnel and waits for the server's message.
func refusedForward(t *testing.T, addr string, cfg *ssh.ClientConfig, listenAddr, want string) {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if ln, err := client.Listen("tcp", listenAddr); err == nil {
		ln.Close()
		t.Fatal("the forward should be refused")
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdout, _ := session.StdoutPipe()
	out := &syncBuffer{}
	go io.Copy(out, stdout)
	session.Shell()
	waitFor(t, "the refusal", func() bool { return strings.Contains(out.String(), want) })
}

func TestE2E_DeniedSubdomainIsRefused(t *testing.T) {
	srv, addr := startSSHServer(t)
	key := newTestKey(t)
	first := openTunnel(t, srv, addr, stableClient(key), echoBackend("first"))

	srv.SetDeniedSubdomains([]string{first.sub})
	if ti := srv.Tunnels(); len(ti) != 1 || !ti[0].Stable {
		t.Fatalf("a denied subdomain's open tunnel stays until closed: %+v", ti)
	}
	if !srv.CloseSubdomain(first.sub) {
		t.Fatal("CloseSubdomain found no connection")
	}
	waitFor(t, "the tunnel to close", func() bool { return srv.GetTunnel(first.sub) == nil })
	if srv.CloseSubdomain(first.sub) {
		t.Error("CloseSubdomain found a connection on a free subdomain")
	}

	// Refused outright: falling back to a random name would let it carry on
	refusedForward(t, addr, stableClient(key), "0.0.0.0:80", "isn't available")
	if n := len(srv.Tunnels()); n != 0 {
		t.Errorf("a refused forward left %d tunnel(s)", n)
	}

	other := openTunnel(t, srv, addr, stableClient(newTestKey(t)), echoBackend("other"))
	if other.sub == first.sub {
		t.Errorf("another key got the denied subdomain")
	}
	if srv.GetTunnel(other.sub) == nil {
		t.Error("another key's tunnel should stay open")
	}

	srv.SetDeniedSubdomains(nil)
	again := openTunnel(t, srv, addr, stableClient(key), echoBackend("again"))
	if again.sub != first.sub {
		t.Errorf("after lifting it, the key got %q, want %q", again.sub, first.sub)
	}
}

func TestE2E_DeniedReservedSubdomainIsRefused(t *testing.T) {
	srv, addr := startSSHServer(t)
	key := newTestKey(t)
	withAccounts(srv, []ssh.Signer{key}, []*Account{{ID: "acct_1", Limits: proLimits, Subdomain: "myapp",
		Subdomains: map[string]tunnel.Options{"myapp": {}}}})

	srv.SetDeniedSubdomains([]string{"myapp"})
	refusedForward(t, addr, accountClient(key), "0.0.0.0:80", "isn't available")
	refusedForward(t, addr, accountClient(key), "myapp:80", "isn't available")
}

func TestReserveSubdomain_SkipsDeniedSubdomains(t *testing.T) {
	s := newTestServer(t)
	candidates := []string{"happy-tiger-00000001", "happy-tiger-00000002"}
	s.newSubdomain = func() (string, error) {
		sub := candidates[0]
		candidates = candidates[1:]
		return sub, nil
	}
	s.SetDeniedSubdomains([]string{"happy-tiger-00000001"})
	sub, err := s.ReserveSubdomain(nil)
	if err != nil {
		t.Fatal(err)
	}
	if sub != "happy-tiger-00000002" {
		t.Errorf("ReserveSubdomain() = %q, a denied name", sub)
	}
}
