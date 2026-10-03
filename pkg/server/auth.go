package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"

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
// the stable user, or as the account user on a server with accounts. That
// keeps every existing client working unchanged: it never asks for a key or
// prompts for anything. Those users are refused, so their clients fall back
// to offering their SSH keys.
func (s *Server) authNone(conn ssh.ConnMetadata) (*ssh.Permissions, error) {
	switch {
	case conn.User() == config.StableSSHUser:
		return nil, errStableNeedsKey
	case conn.User() == config.AccountSSHUser && s.accounts != nil:
		return nil, errAccountNeedsKey
	}
	return &ssh.Permissions{}, nil
}

// authPublicKey accepts any key offered by the stable user. The key identifies
// the client to give it a stable subdomain; it doesn't authorize anything.
// The account user is handled by authAccount instead. x/crypto/ssh only
// grants these permissions once the client has proven it holds the private
// key.
func (s *Server) authPublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
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
	return &ssh.Permissions{Extensions: map[string]string{
		permOwner:           ssh.FingerprintSHA256(key),
		permStableSubdomain: sub,
		permKeyFingerprint:  ssh.FingerprintSHA256(key),
	}}, nil
}

// stableSubdomain derives a client key's subdomain. The key is public, so it
// is keyed with a secret held only by this server: the subdomain is the same
// for every connection with that key, but can't be computed from the key alone.
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
