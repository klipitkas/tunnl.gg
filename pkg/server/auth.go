package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/subdomain"
)

// Permission extensions set during SSH authentication.
const (
	permOwner           = "owner" // who may take over the stable subdomain: a key fingerprint or an account
	permStableSubdomain = "stable-subdomain"
	permKeyFingerprint  = "key-fingerprint" // the key the client authenticated with
)

var errStableNeedsKey = errors.New("the stable user requires an SSH key")

// authNone accepts clients without a key, as long as they didn't connect as
// the stable user, a key command's user, or the account user on a server
// with accounts. That
// keeps every existing client working unchanged: it never asks for a key or
// prompts for anything. Those users are refused, so their clients fall back
// to offering their SSH keys.
func (s *Server) authNone(conn ssh.ConnMetadata) (*ssh.Permissions, error) {
	switch {
	case s.keyCommands[conn.User()] != nil:
		return nil, fmt.Errorf("the %s user requires an SSH key", conn.User())
	case conn.User() == config.StableSSHUser:
		return nil, errStableNeedsKey
	case conn.User() == config.AccountSSHUser && s.accounts != nil:
		return nil, errAccountNeedsKey
	}
	return &ssh.Permissions{}, nil
}

// authNoKey refuses keyboard-interactive authentication, which clients try
// only once no key worked: none is refused for the stable user, and one with
// keys would have been accepted by authPublicKey. So a stable client that
// gets here has no key, and is told how to make one instead of only
// "Permission denied". It asks nothing, so it never prompts.
func (s *Server) authNoKey(conn ssh.ConnMetadata, _ ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	if conn.User() != config.StableSSHUser {
		return nil, errors.New("keyboard-interactive authentication is not used")
	}
	msg := "\r\n  " + s.domain + ": " + config.StableSSHUser + "@ keeps the same URL for your SSH key, but your SSH client\r\n" +
		"  has no key to offer. Create one, then connect again:\r\n\r\n" +
		"    ssh-keygen -t ed25519\r\n\r\n" +
		"  Or connect without " + config.StableSSHUser + "@ for a random URL.\r\n"
	// Only a hosted deployment sets one; open-source servers show just the help
	if note := s.FreeLimits().SignupNote; note != "" {
		msg += "  " + note + "\r\n"
	}
	return nil, &ssh.BannerError{Err: errStableNeedsKey, Message: msg + "\r\n"}
}

// authPublicKey accepts any key offered by the stable user. The key identifies
// the client to give it a stable subdomain; it doesn't authorize anything.
// The account user is handled by authAccount instead. x/crypto/ssh only
// grants these permissions once the client has proven it holds the private
// key.
func (s *Server) authPublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if s.keyCommands[conn.User()] != nil {
		return authKeyCommand(key), nil
	}
	if conn.User() == config.AccountSSHUser && s.accounts != nil {
		return s.authAccount(key)
	}
	if conn.User() != config.StableSSHUser {
		return nil, errors.New("public key authentication is only used by the stable and account users")
	}
	sub, err := s.stableSubdomain(key)
	if err != nil {
		return nil, err
	}
	return &ssh.Permissions{
		Extensions: map[string]string{
			permOwner:           ssh.FingerprintSHA256(key),
			permStableSubdomain: sub,
			permKeyFingerprint:  ssh.FingerprintSHA256(key),
		},
		ExtraData: map[any]any{stableKey{}: key},
	}, nil
}

// stableKey keys the Permissions.ExtraData entry holding the key a stable
// client authenticated with.
type stableKey struct{}

// SetSignupNote sets what a client that connected with a key but without an
// account sees in the banner instead of its Limits.SignupNote, e.g. a link
// that adds that key to a new account. note returns "" to keep SignupNote.
// Set it before serving.
func (s *Server) SetSignupNote(note func(key ssh.PublicKey) string) {
	s.signupNote = note
}

// keySignupNote is the SignupNote for conn's banner: SetSignupNote's for its
// key, if it has one, else fallback.
func (s *Server) keySignupNote(conn *ssh.ServerConn, fallback string) string {
	return keyNote(s.signupNote, conn, fallback)
}

// SetLimitNote sets what a client that connected with a key but without an
// account sees when its tunnel is closed for reaching MaxLifetime, instead of
// its Limits.LimitNote, e.g. a link that adds that key to a new account
// without the limit. note returns "" to keep LimitNote. Set it before
// serving.
func (s *Server) SetLimitNote(note func(key ssh.PublicKey) string) {
	s.limitNote = note
}

// keyLimitNote is the note shown when conn's tunnel reaches MaxLifetime:
// SetLimitNote's for its key, if it has one, else fallback.
func (s *Server) keyLimitNote(conn *ssh.ServerConn, fallback string) string {
	return keyNote(s.limitNote, conn, fallback)
}

// keyNote is note's answer for the key a stable client authenticated with,
// or fallback if there's no note, no key, or note returns "".
func keyNote(note func(ssh.PublicKey) string, conn *ssh.ServerConn, fallback string) string {
	if note == nil || conn.Permissions == nil {
		return fallback
	}
	key, _ := conn.Permissions.ExtraData[stableKey{}].(ssh.PublicKey)
	if key == nil {
		return fallback
	}
	if n := note(key); n != "" {
		return n
	}
	return fallback
}

// stableSubdomain derives a client key's subdomain. The key is public, so it
// is keyed with a secret held only by this server: the subdomain is the same
// for every connection with that key, but can't be computed from the key alone.
// StableSubdomain returns the subdomain key gets when it connects as the
// stable user, or as an account's key with no subdomain of its own, so a
// dashboard can show it.
func (s *Server) StableSubdomain(key ssh.PublicKey) (string, error) {
	return s.stableSubdomain(key)
}

func (s *Server) stableSubdomain(key ssh.PublicKey) (string, error) {
	mac := hmac.New(sha256.New, s.subdomainSecret)
	mac.Write(key.Marshal())
	return subdomain.FromHash(mac.Sum(nil))
}

// subdomainSecretFromHostKey derives the stable subdomain secret from the
// server's private host key, so no separate secret has to be stored. Stable
// subdomains change if the host key does.
func subdomainSecretFromHostKey(hostKeyPEM []byte) []byte {
	h := sha256.New()
	h.Write([]byte("tunnl stable subdomains v1\x00"))
	h.Write(hostKeyPEM)
	return h.Sum(nil)
}
