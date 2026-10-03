package server

import (
	"errors"
	"log"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/subdomain"
)

// Account is a customer of a hosted deployment, such as a paid plan. Its
// clients connect as config.AccountSSHUser with one of the account's SSH keys.
type Account struct {
	ID     string        // unique and non-empty; shown in logs
	Limits config.Limits // apply to the account's tunnels instead of the free limits
	// Subdomain is reserved for the account and shared by all its keys, or
	// "" to give each key its stable subdomain. Don't reserve names in the
	// generated format (subdomain.IsValid): anonymous clients may hold them.
	Subdomain string
}

// AccountStore finds the account an SSH key belongs to.
type AccountStore interface {
	// Lookup returns the account key belongs to, or nil if it belongs to none.
	// It runs during SSH handshakes, so it should be fast. The returned
	// account must not be modified afterwards.
	Lookup(key ssh.PublicKey) (*Account, error)
}

// accountKey is the ssh.Permissions.ExtraData key holding a connection's
// *Account.
type accountKey struct{}

var (
	errAccountNeedsKey = errors.New("the account user requires an SSH key")
	errUnknownKey      = errors.New("the SSH key doesn't belong to an account")
	errAccountLookup   = errors.New("the account couldn't be looked up")
)

// SetAccounts lets clients connect as config.AccountSSHUser with an
// account's SSH key, to get that account's limits and subdomain. Without an
// AccountStore, the default, that user is anonymous like any other.
func (s *Server) SetAccounts(store AccountStore) {
	s.accounts = store
}

// authAccount accepts key if it belongs to an account. Accounts with a
// reserved subdomain share it across all their keys; others get the key's
// stable subdomain.
func (s *Server) authAccount(key ssh.PublicKey) (*ssh.Permissions, error) {
	acct, err := s.accounts.Lookup(key)
	if err != nil {
		// The client only learns that the key was refused
		log.Printf("Account lookup failed: %v", err)
		return nil, errAccountLookup
	}
	if acct == nil {
		return nil, errUnknownKey
	}
	if acct.ID == "" || (acct.Subdomain != "" && !subdomain.IsLabel(acct.Subdomain)) {
		log.Printf("Account lookup returned an invalid account: ID %q, subdomain %q", acct.ID, acct.Subdomain)
		return nil, errAccountLookup
	}

	sub, owner := acct.Subdomain, "account:"+acct.ID
	if sub == "" {
		if sub, err = s.stableSubdomain(key); err != nil {
			return nil, err
		}
		owner = ssh.FingerprintSHA256(key)
	}
	return &ssh.Permissions{
		Extensions: map[string]string{
			permOwner:           owner,
			permStableSubdomain: sub,
			permKeyFingerprint:  ssh.FingerprintSHA256(key),
		},
		ExtraData: map[any]any{accountKey{}: acct},
	}, nil
}

// connAccount returns the account conn authenticated as, or nil.
func connAccount(conn *ssh.ServerConn) *Account {
	if conn.Permissions == nil {
		return nil
	}
	acct, _ := conn.Permissions.ExtraData[accountKey{}].(*Account)
	return acct
}

// CloseAccount closes the SSH connections of the account with the given ID,
// for example after its subscription ends, and returns how many it closed.
// The AccountStore should stop returning the account first, or its clients
// can reconnect.
func (s *Server) CloseAccount(id string) int {
	return closeConns(s.takeConns(s.accountConns, id))
}

// CloseKey closes the SSH connections that authenticated with the key with
// the given fingerprint (as ssh.FingerprintSHA256 formats it), for example
// after it's removed from its account, and returns how many it closed. Other
// connections of the same account stay open. The AccountStore should stop
// accepting the key first, or its client can reconnect.
func (s *Server) CloseKey(fingerprint string) int {
	return closeConns(s.takeConns(s.keyConns, fingerprint))
}
