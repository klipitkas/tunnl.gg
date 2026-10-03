package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/internal/config"
	"github.com/klipitkas/tunnl.gg/internal/subdomain"
)

func newTestKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error: %v", err)
	}
	return signer
}

type fakeConnMetadata struct{ user string }

func (f fakeConnMetadata) User() string          { return f.user }
func (f fakeConnMetadata) SessionID() []byte     { return nil }
func (f fakeConnMetadata) ClientVersion() []byte { return nil }
func (f fakeConnMetadata) ServerVersion() []byte { return nil }
func (f fakeConnMetadata) RemoteAddr() net.Addr  { return &net.TCPAddr{} }
func (f fakeConnMetadata) LocalAddr() net.Addr   { return &net.TCPAddr{} }

// fakeSSHConn stands in for a connection that holds a subdomain.
type fakeSSHConn struct{ closed bool }

func (f *fakeSSHConn) OpenChannel(string, []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, fmt.Errorf("not implemented")
}
func (f *fakeSSHConn) Close() error { f.closed = true; return nil }

func TestAuthNone(t *testing.T) {
	s := newTestServer(t)

	if _, err := s.authNone(fakeConnMetadata{user: "anyone"}); err != nil {
		t.Errorf("authNone() should accept users other than %q: %v", config.StableSSHUser, err)
	}
	if _, err := s.authNone(fakeConnMetadata{user: config.StableSSHUser}); err == nil {
		t.Errorf("authNone() should refuse %q so the client offers its key", config.StableSSHUser)
	}
}

func TestAuthPublicKey(t *testing.T) {
	s := newTestServer(t)
	key := newTestKey(t).PublicKey()

	perms, err := s.authPublicKey(fakeConnMetadata{user: config.StableSSHUser}, key)
	if err != nil {
		t.Fatalf("authPublicKey() should accept any key for %q: %v", config.StableSSHUser, err)
	}
	if got := perms.Extensions[permKeyFingerprint]; got != ssh.FingerprintSHA256(key) {
		t.Errorf("fingerprint = %q, want %q", got, ssh.FingerprintSHA256(key))
	}
	if sub := perms.Extensions[permStableSubdomain]; !subdomain.IsValid(sub) {
		t.Errorf("stable subdomain %q is not valid", sub)
	}

	if _, err := s.authPublicKey(fakeConnMetadata{user: "anyone"}, key); err == nil {
		t.Error("authPublicKey() should only be used by the stable user")
	}
}

func TestStableSubdomain(t *testing.T) {
	s := newTestServer(t)
	key, other := newTestKey(t).PublicKey(), newTestKey(t).PublicKey()

	first, _ := s.stableSubdomain(key)
	again, _ := s.stableSubdomain(key)
	if first != again {
		t.Errorf("same key gave %q then %q", first, again)
	}
	if different, _ := s.stableSubdomain(other); different == first {
		t.Errorf("different keys both gave %q", first)
	}

	// Another server (another host key) derives different subdomains, so they
	// can't be computed from the public key alone
	if elsewhere, _ := newTestServer(t).stableSubdomain(key); elsewhere == first {
		t.Errorf("servers with different host keys both gave %q", first)
	}
}

func TestClaimSubdomain(t *testing.T) {
	s := newTestServer(t)
	const sub = "happy-tiger-00000001"
	owner, sameKey, otherKey := &fakeSSHConn{}, &fakeSSHConn{}, &fakeSSHConn{}

	if _, ok := s.claimSubdomain(sub, owner, "SHA256:a"); !ok {
		t.Fatal("claiming a free subdomain should succeed")
	}
	if holder, ok := s.claimSubdomain(sub, sameKey, "SHA256:a"); ok || holder != owner {
		t.Errorf("same key: got holder=%v ok=%v, want the current holder to replace", holder, ok)
	}
	if holder, ok := s.claimSubdomain(sub, otherKey, "SHA256:b"); ok || holder != nil {
		t.Errorf("different key: got holder=%v ok=%v, want no claim and no holder", holder, ok)
	}

	// Random subdomains are never taken over, even by a keyless connection
	random, err := s.ReserveSubdomain(owner)
	if err != nil {
		t.Fatalf("ReserveSubdomain() error: %v", err)
	}
	if holder, ok := s.claimSubdomain(random, otherKey, ""); ok || holder != nil {
		t.Errorf("keyless claim of a random subdomain: holder=%v ok=%v", holder, ok)
	}
}

func TestRemoveTunnel_OnlyByOwner(t *testing.T) {
	s := newTestServer(t)
	owner, previous := &fakeSSHConn{}, &fakeSSHConn{}
	const sub = "happy-tiger-00000001"
	s.claimSubdomain(sub, owner, "SHA256:a")
	s.RegisterTunnel(sub, owner, "localhost", 80, "192.0.2.1")

	// A replaced connection's cleanup runs after the new owner registered
	s.RemoveTunnel(sub, previous)
	if s.GetTunnel(sub) == nil {
		t.Fatal("cleanup by a previous owner removed the new owner's tunnel")
	}
	if tun := s.RegisterTunnel(sub, previous, "localhost", 80, "192.0.2.1"); tun != nil {
		t.Error("a connection that doesn't hold the subdomain registered a tunnel under it")
	}

	s.RemoveTunnel(sub, owner)
	if s.GetTunnel(sub) != nil {
		t.Error("owner's RemoveTunnel should remove its tunnel")
	}
}

func echoBackend(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, name) })
}

func TestE2E_StableUserKeepsURLAcrossReconnects(t *testing.T) {
	srv, addr := startSSHServer(t)
	key := newTestKey(t)

	first := openTunnel(t, srv, addr, stableClient(key), echoBackend("first"))
	if !strings.Contains(first.output.String(), "stays the same for your SSH key") {
		t.Errorf("banner should say the URL is stable: %q", first.output.String())
	}
	first.client.Close()
	waitFor(t, "first tunnel cleanup", func() bool { return srv.GetTunnel(first.sub) == nil })

	second := openTunnel(t, srv, addr, stableClient(key), echoBackend("second"))
	if second.sub != first.sub {
		t.Errorf("reconnect with the same key got %q, want %q", second.sub, first.sub)
	}

	other := openTunnel(t, srv, addr, stableClient(newTestKey(t)), echoBackend("other"))
	if other.sub == first.sub {
		t.Errorf("a different key got the same subdomain %q", other.sub)
	}
}

func TestE2E_StableReconnectReplacesOldSession(t *testing.T) {
	srv, addr := startSSHServer(t)
	key := newTestKey(t)

	old := openTunnel(t, srv, addr, stableClient(key), echoBackend("old"))
	oldClosed := make(chan struct{})
	go func() { old.client.Wait(); close(oldClosed) }()

	// The old connection is still up, e.g. left over from before a laptop slept
	replacement := openTunnel(t, srv, addr, stableClient(key), echoBackend("new"))
	if replacement.sub != old.sub {
		t.Fatalf("reconnect got %q, want the same subdomain %q", replacement.sub, old.sub)
	}
	waitFor(t, "old session to be closed", func() bool {
		select {
		case <-oldClosed:
			return true
		default:
			return false
		}
	})

	resp := replacement.get(t, "/")
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "new" {
		t.Errorf("traffic went to %q, want the new session", body)
	}
}

func TestE2E_AnonymousClientsGetRandomURLs(t *testing.T) {
	srv, addr := startSSHServer(t)

	first := openTunnel(t, srv, addr, anonymousClient(), echoBackend("a"))
	second := openTunnel(t, srv, addr, anonymousClient(), echoBackend("b"))
	if first.sub == second.sub {
		t.Errorf("anonymous clients both got %q", first.sub)
	}
	if !strings.Contains(first.output.String(), "connect as "+config.StableSSHUser+"@") {
		t.Errorf("banner should explain how to keep the URL: %q", first.output.String())
	}
}

func TestE2E_StableUserWithoutKeyIsRefused(t *testing.T) {
	_, addr := startSSHServer(t)

	cfg := anonymousClient()
	cfg.User = config.StableSSHUser
	if client, err := ssh.Dial("tcp", addr, cfg); err == nil {
		client.Close()
		t.Fatalf("%q without a key should be refused", config.StableSSHUser)
	}
}
