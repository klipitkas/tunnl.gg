package server

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

func TestLifetimeNote(t *testing.T) {
	s := newTestServer(t)
	key := newTestKey(t).PublicKey()
	perms, err := s.authPublicKey(fakeConnMetadata{user: config.StableSSHUser}, key)
	if err != nil {
		t.Fatal(err)
	}
	keyed := &ssh.ServerConn{Permissions: perms}
	keyless := &ssh.ServerConn{Permissions: &ssh.Permissions{}}

	// By default, as open-source servers run, there's nothing to show
	if got := s.lifetimeNote(keyed, nil, config.FreeLimits()); got != "" {
		t.Errorf("default lifetimeNote() = %q, want none", got)
	}

	limits := config.FreeLimits()
	limits.UpgradeNote = "upgrade note"
	if got := s.lifetimeNote(keyed, nil, limits); got != "upgrade note" {
		t.Errorf("without a LimitNote, lifetimeNote() = %q, want the UpgradeNote", got)
	}
	limits.LimitNote = "limit note"
	if got := s.lifetimeNote(keyed, nil, limits); got != "limit note" {
		t.Errorf("lifetimeNote() = %q, want the LimitNote", got)
	}

	var gotKey ssh.PublicKey
	s.SetLimitNote(func(k ssh.PublicKey) string {
		gotKey = k
		return "link for this key"
	})
	if got := s.lifetimeNote(keyed, nil, limits); got != "link for this key" {
		t.Errorf("lifetimeNote() = %q, want the key's note", got)
	}
	if gotKey == nil || !bytes.Equal(gotKey.Marshal(), key.Marshal()) {
		t.Error("SetLimitNote's func didn't get the client's key")
	}
	if got := s.lifetimeNote(keyless, nil, limits); got != "limit note" {
		t.Errorf("for a keyless client, lifetimeNote() = %q, want the LimitNote", got)
	}
	// An account's limits say what to show its clients
	gotKey = nil
	if got := s.lifetimeNote(keyed, &Account{ID: "acct"}, limits); got != "limit note" || gotKey != nil {
		t.Errorf("for an account, lifetimeNote() = %q (asked for the key: %v), want its LimitNote", got, gotKey != nil)
	}
	s.SetLimitNote(func(ssh.PublicKey) string { return "" })
	if got := s.lifetimeNote(keyed, nil, limits); got != "limit note" {
		t.Errorf("when the func returns \"\", lifetimeNote() = %q, want the LimitNote", got)
	}
}

func TestNoticeEnd(t *testing.T) {
	for _, tc := range []struct {
		note  string
		lines int
	}{{"", 1}, {"Lift the limit at https://example.com", 2}} {
		var out syncBuffer
		logger := tunnel.NewRequestLogger(&out, 16)
		noticeEnd(logger, "Tunnel closed: reached the 24h limit", tc.note)
		logger.Close()
		got := out.String()
		if !strings.Contains(got, "Tunnel closed: reached the 24h limit. 0 requests.") {
			t.Errorf("end notice is missing the reason and summary:\n%q", got)
		}
		if n := strings.Count(got, "\r\n"); n != tc.lines {
			t.Errorf("with note %q, end notice has %d lines, want %d:\n%q", tc.note, n, tc.lines, got)
		}
		if tc.note != "" && !strings.Contains(got, tc.note) {
			t.Errorf("end notice is missing the note:\n%q", got)
		}
	}
}
