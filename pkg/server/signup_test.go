package server

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

func TestSessionBannerSignupNote(t *testing.T) {
	limits := config.FreeLimits()
	plain := sessionBanner("https://x.example.com", "example.com", "note", limits, 0, tunnel.Options{})
	if strings.Contains(plain, "Account") {
		t.Errorf("banner without a signup note has an Account line:\n%s", plain)
	}

	limits.SignupNote = "Free account: see every request at https://example.com/signup"
	withNote := sessionBanner("https://x.example.com", "example.com", "note", limits, 0, tunnel.Options{})
	if !strings.Contains(withNote, "Account") || !strings.Contains(withNote, limits.SignupNote) {
		t.Errorf("banner is missing the signup note:\n%s", withNote)
	}
	if strings.Count(withNote, "\r\n") != strings.Count(plain, "\r\n")+1 {
		t.Errorf("the note should add exactly one line")
	}
}

func TestNoteSignupOnFailure(t *testing.T) {
	const note = "Free account: see what was sent at https://example.com/signup"
	newTun := func(limits config.Limits) (*tunnel.Tunnel, *syncBuffer, *tunnel.RequestLogger) {
		tun := tunnel.New("signup-note-00000001", nil, "", 80, "")
		tun.Limits = limits
		var out syncBuffer
		logger := tunnel.NewRequestLogger(&out, 16)
		tun.SetLogger(logger)
		return tun, &out, logger
	}
	limits := config.FreeLimits()
	limits.SignupNote = note

	tun, out, logger := newTun(limits)
	noteSignupOnFailure(tun, result2xx)
	noteSignupOnFailure(tun, resultCanceled) // the visitor's doing, not the app's
	noteSignupOnFailure(tun, resultAppRefused)
	noteSignupOnFailure(tun, result5xx)
	logger.Close()
	if got := strings.Count(out.String(), note); got != 1 {
		t.Errorf("note shown %d times, want once on the first failure:\n%q", got, out.String())
	}

	// Tunnels that already have the inspector, or no note, show nothing
	withInspect := limits
	withInspect.Inspect = true
	for _, l := range []config.Limits{withInspect, config.FreeLimits()} {
		tun, out, logger := newTun(l)
		noteSignupOnFailure(tun, result5xx)
		logger.Close()
		if strings.Contains(out.String(), "Free account") {
			t.Errorf("note shown with Inspect=%v, SignupNote=%q", l.Inspect, l.SignupNote)
		}
	}
}

func TestKeySignupNote(t *testing.T) {
	s := newTestServer(t)
	key := newTestKey(t).PublicKey()
	perms, err := s.authPublicKey(fakeConnMetadata{user: config.StableSSHUser}, key)
	if err != nil {
		t.Fatal(err)
	}
	keyed := &ssh.ServerConn{Permissions: perms}
	keyless := &ssh.ServerConn{Permissions: &ssh.Permissions{}}

	if got := s.keySignupNote(keyed, "fallback"); got != "fallback" {
		t.Errorf("without SetSignupNote, keySignupNote() = %q, want the fallback", got)
	}
	var gotKey ssh.PublicKey
	s.SetSignupNote(func(k ssh.PublicKey) string {
		gotKey = k
		return "link for this key"
	})
	if got := s.keySignupNote(keyed, "fallback"); got != "link for this key" {
		t.Errorf("keySignupNote() = %q, want the key's note", got)
	}
	if gotKey == nil || !bytes.Equal(gotKey.Marshal(), key.Marshal()) {
		t.Error("SetSignupNote's func didn't get the client's key")
	}
	if got := s.keySignupNote(keyless, "fallback"); got != "fallback" {
		t.Errorf("for a keyless client, keySignupNote() = %q, want the fallback", got)
	}
	s.SetSignupNote(func(ssh.PublicKey) string { return "" })
	if got := s.keySignupNote(keyed, "fallback"); got != "fallback" {
		t.Errorf("when the func returns \"\", keySignupNote() = %q, want the fallback", got)
	}
}

func TestAuthNoKey(t *testing.T) {
	s := newTestServer(t)
	limits := s.FreeLimits()
	limits.SignupNote = "Free account at https://example.com/signup"
	s.SetFreeLimits(limits)

	_, err := s.authNoKey(fakeConnMetadata{user: config.StableSSHUser}, nil)
	var banner *ssh.BannerError
	if !errors.As(err, &banner) {
		t.Fatalf("authNoKey() = %v, want a BannerError telling the stable user to make a key", err)
	}
	if !errors.Is(err, errStableNeedsKey) {
		t.Errorf("authNoKey() = %v, want it to wrap errStableNeedsKey (the daily report counts it)", err)
	}
	for _, want := range []string{"ssh-keygen -t ed25519", limits.SignupNote} {
		if !strings.Contains(banner.Message, want) {
			t.Errorf("banner is missing %q:\n%s", want, banner.Message)
		}
	}

	_, err = s.authNoKey(fakeConnMetadata{user: "anyone"}, nil)
	if err == nil || errors.As(err, &banner) {
		t.Errorf("authNoKey() for other users = %v, want a plain refusal", err)
	}
}

// A real client without keys sees the stable user's banner before it's
// refused; one with a key never sees it.
func TestStableWithoutKeyE2E(t *testing.T) {
	s := newTestServer(t)
	addr := serveSSH(t, s)

	var mu sync.Mutex
	var banners []string
	bannerCB := func(msg string) error {
		mu.Lock()
		banners = append(banners, msg)
		mu.Unlock()
		return nil
	}
	noKey := &ssh.ClientConfig{
		User: config.StableSSHUser,
		Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
			t.Error("the server asked a question; it should only refuse")
			return nil, nil
		})},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		BannerCallback:  bannerCB,
	}
	if c, err := ssh.Dial("tcp", addr, noKey); err == nil {
		c.Close()
		t.Fatal("a keyless client got in as the stable user")
	}
	mu.Lock()
	got := strings.Join(banners, "")
	banners = nil
	mu.Unlock()
	if !strings.Contains(got, "ssh-keygen") {
		t.Errorf("keyless client saw banner %q, want how to make a key", got)
	}

	withKey := &ssh.ClientConfig{
		User:            config.StableSSHUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(newTestKey(t))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		BannerCallback:  bannerCB,
	}
	c, err := ssh.Dial("tcp", addr, withKey)
	if err != nil {
		t.Fatalf("a client with a key was refused: %v", err)
	}
	c.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(banners) != 0 {
		t.Errorf("a client with a key saw banners %q", banners)
	}
}
