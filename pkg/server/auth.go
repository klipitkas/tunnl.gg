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
	permKeyFingerprint  = "key-fingerprint"
	permStableSubdomain = "stable-subdomain"
)

var errStableNeedsKey = errors.New("the stable user requires an SSH key")

// authNone accepts clients without a key, as long as they didn't connect as
// the stable user. That keeps every existing client working unchanged: it
// never asks for a key or prompts for anything. The stable user is refused, so
// its client falls back to offering its SSH keys.
func (s *Server) authNone(conn ssh.ConnMetadata) (*ssh.Permissions, error) {
	if conn.User() == config.StableSSHUser {
		return nil, errStableNeedsKey
	}
	return &ssh.Permissions{}, nil
}

// authPublicKey accepts any key offered by the stable user. The key identifies
// the client to give it a stable subdomain; it doesn't authorize anything.
// x/crypto/ssh only grants these permissions once the client has proven it
// holds the private key.
func (s *Server) authPublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if conn.User() != config.StableSSHUser {
		return nil, errors.New("public key authentication is only used by the stable user")
	}
	sub, err := s.stableSubdomain(key)
	if err != nil {
		return nil, err
	}
	return &ssh.Permissions{Extensions: map[string]string{
		permKeyFingerprint:  ssh.FingerprintSHA256(key),
		permStableSubdomain: sub,
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
