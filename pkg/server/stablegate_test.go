package server

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/config"
)

func TestStableRefusal(t *testing.T) {
	s := newTestServer(t)
	key := newTestKey(t).PublicKey()
	perms, err := s.authPublicKey(fakeConnMetadata{user: config.StableSSHUser}, key)
	if err != nil {
		t.Fatal(err)
	}
	keyed := &ssh.ServerConn{Permissions: perms}
	keyless := &ssh.ServerConn{Permissions: &ssh.Permissions{}}

	if got := s.stableRefusal(keyed); got != "" {
		t.Errorf("without SetStableGate, stableRefusal() = %q, want everyone let in", got)
	}
	var gotKey ssh.PublicKey
	s.SetStableGate(func(k ssh.PublicKey) string {
		gotKey = k
		return "register this key first\r\n"
	})
	if got := s.stableRefusal(keyed); got != "register this key first\r\n" {
		t.Errorf("stableRefusal() = %q, want the gate's message", got)
	}
	if gotKey == nil || !bytes.Equal(gotKey.Marshal(), key.Marshal()) {
		t.Error("the gate didn't get the client's key")
	}
	if got := s.stableRefusal(keyless); got != "" {
		t.Errorf("a client without a stable key was refused: %q", got)
	}
}

func TestE2E_StableGate(t *testing.T) {
	srv, addr := startSSHServer(t)
	allowed, refused := newTestKey(t), newTestKey(t)
	srv.SetStableGate(func(k ssh.PublicKey) string {
		if bytes.Equal(k.Marshal(), refused.PublicKey().Marshal()) {
			return "\r\n  Register this key first.\r\n\r\n"
		}
		return ""
	})

	// A refused key sees the message, exits with status 1 and opens nothing
	client, err := ssh.Dial("tcp", addr, stableClient(refused))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdout, _ := session.StdoutPipe()
	out := &syncBuffer{}
	go io.Copy(out, stdout)
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	err = session.Wait()
	var exit *ssh.ExitError
	if !errors.As(err, &exit) || exit.ExitStatus() != 1 {
		t.Errorf("session ended with %v, want exit status 1", err)
	}
	if !strings.Contains(out.String(), "Register this key first.") {
		t.Errorf("output = %q, want the gate's message", out.String())
	}
	if n := len(srv.Tunnels()); n != 0 {
		t.Errorf("a refused key left %d tunnel(s)", n)
	}

	// Another key gets its stable tunnel, and clients without a stable key
	// aren't asked
	if tt := openTunnel(t, srv, addr, stableClient(allowed), echoBackend("ok")); tt.sub == "" {
		t.Error("an allowed key got no tunnel")
	}
	openTunnel(t, srv, addr, anonymousClient(), echoBackend("random"))
}
