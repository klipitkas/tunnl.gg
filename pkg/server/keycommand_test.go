package server

import (
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/config"
)

// keyClient connects as user with key.
func keyClient(user string, key ssh.Signer) *ssh.ClientConfig {
	cfg := anonymousClient()
	cfg.User = user
	cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(key)}
	return cfg
}

// shellOutput opens a shell, as "ssh -t user@host" does, and returns what
// the server writes before closing it.
func shellOutput(t *testing.T, client *ssh.Client) string {
	t.Helper()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}
	defer session.Close()
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty() error: %v", err)
	}
	out, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Shell() error: %v", err)
	}
	b, _ := io.ReadAll(out)
	return string(b)
}

func TestE2E_KeyCommand(t *testing.T) {
	srv := newTestServer(t)
	var mu sync.Mutex
	var got []string
	srv.SetKeyCommand("link", func(key ssh.PublicKey) (string, error) {
		mu.Lock()
		got = append(got, ssh.FingerprintSHA256(key))
		mu.Unlock()
		return "Open https://example.test/claim/abc\nKey " + ssh.FingerprintSHA256(key) + "\n", nil
	})
	addr := serveSSH(t, srv)
	key := newTestKey(t)
	fp := ssh.FingerprintSHA256(key.PublicKey())

	client, err := ssh.Dial("tcp", addr, keyClient("link", key))
	if err != nil {
		t.Fatalf("Dial() as the command's user error: %v", err)
	}
	defer client.Close()
	// Port forwarding doesn't open a tunnel for the command's user
	if ok, _, err := client.SendRequest("tcpip-forward", true, ssh.Marshal(struct {
		Addr string
		Port uint32
	}{"0.0.0.0", 80})); err == nil && ok {
		t.Error("the command's user was allowed to forward a port")
	}
	out := shellOutput(t, client)
	if !strings.Contains(out, "Open https://example.test/claim/abc\r\nKey "+fp+"\r\n") {
		t.Errorf("output = %q, want the command's text with \\r\\n line endings", out)
	}
	mu.Lock()
	if len(got) != 1 || got[0] != fp {
		t.Errorf("command got keys %v, want [%s]", got, fp)
	}
	mu.Unlock()
	if n := srv.GetStats(false).ActiveTunnels; n != 0 {
		t.Errorf("%d tunnels open, want none", n)
	}

	// "ssh user@host anything" gets the same text
	client2, err := ssh.Dial("tcp", addr, keyClient("link", key))
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()
	session, err := client2.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	// and exits with status 0
	if b, err := session.Output("whatever"); err != nil || !strings.Contains(string(b), "claim/abc") {
		t.Errorf("exec output = %q, %v; want the command's text and status 0", b, err)
	}
}

func TestE2E_KeyCommandNeedsKey(t *testing.T) {
	srv := newTestServer(t)
	srv.SetKeyCommand("link", func(ssh.PublicKey) (string, error) { return "linked", nil })
	addr := serveSSH(t, srv)

	cfg := anonymousClient()
	cfg.User = "link"
	if client, err := ssh.Dial("tcp", addr, cfg); err == nil {
		client.Close()
		t.Error("the command's user connected without a key")
	}
	// Other users are unchanged
	if client, err := ssh.Dial("tcp", addr, anonymousClient()); err != nil {
		t.Errorf("anonymous clients should still connect: %v", err)
	} else {
		client.Close()
	}
}

func TestE2E_KeyCommandFails(t *testing.T) {
	srv := newTestServer(t)
	srv.SetKeyCommand("link", func(ssh.PublicKey) (string, error) { return "", errors.New("database is down") })
	addr := serveSSH(t, srv)

	client, err := ssh.Dial("tcp", addr, keyClient("link", newTestKey(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	out := shellOutput(t, client)
	if !strings.Contains(out, "ERROR: something went wrong") || strings.Contains(out, "database") {
		t.Errorf("output = %q, want a generic error without the cause", out)
	}
}

func TestE2E_KeyCommandRateLimited(t *testing.T) {
	srv := newTestServer(t)
	var mu sync.Mutex
	runs := 0
	srv.SetKeyCommand("link", func(ssh.PublicKey) (string, error) {
		mu.Lock()
		runs++
		mu.Unlock()
		return "linked", nil
	})
	addr := serveSSH(t, srv)
	key := newTestKey(t)

	var last string
	for range config.MaxConnectionsPerMinute + 1 {
		client, err := ssh.Dial("tcp", addr, keyClient("link", key))
		if err != nil {
			t.Fatal(err)
		}
		last = shellOutput(t, client)
		client.Close()
	}
	if !strings.Contains(last, "rate limit") {
		t.Errorf("connection %d: output = %q, want the rate limit", config.MaxConnectionsPerMinute+1, last)
	}
	mu.Lock()
	defer mu.Unlock()
	if runs != config.MaxConnectionsPerMinute {
		t.Errorf("command ran %d times, want %d", runs, config.MaxConnectionsPerMinute)
	}
}

func TestSetKeyCommand_RefusesReservedUsers(t *testing.T) {
	for _, user := range []string{"", config.StableSSHUser, config.AccountSSHUser} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("SetKeyCommand(%q) didn't panic", user)
				}
			}()
			newTestServer(t).SetKeyCommand(user, func(ssh.PublicKey) (string, error) { return "", nil })
		}()
	}
}
