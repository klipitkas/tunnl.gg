package server

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/subdomain"
	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
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
	// Subdomains are the account's reserved subdomains, each with its saved
	// options, such as a password; options in the ssh command override them
	// one by one. A client opens one by naming it as the bind address,
	// like ssh -R myapp:80:localhost:3000; without a name it gets Subdomain.
	Subdomains map[string]tunnel.Options
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
	valid := acct.ID != "" && (acct.Subdomain == "" || subdomain.IsLabel(acct.Subdomain))
	for name := range acct.Subdomains {
		valid = valid && subdomain.IsLabel(name)
	}
	if !valid {
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

// SetTunnelOptions replaces the saved options of the account's open tunnel
// on sub, if there is one, for example after its settings change. It
// reports whether there was.
func (s *Server) SetTunnelOptions(accountID, sub string, o tunnel.Options) bool {
	tun := s.GetTunnel(sub)
	if tun == nil || accountID == "" || tun.AccountID != accountID {
		return false
	}
	tun.SetBaseOptions(o)
	return true
}

// reserved reports whether sub is one of the account's subdomains, with its
// saved options. A nil account has none.
func (a *Account) reserved(sub string) (tunnel.Options, bool) {
	if a == nil {
		return tunnel.Options{}, false
	}
	opts, ok := a.Subdomains[sub]
	return opts, ok
}

// defaultBindAddrs are the bind addresses that ask for no particular name:
// what clients send for ssh -R 80:..., -R 0.0.0.0:80:... and the like.
var defaultBindAddrs = map[string]bool{"": true, "localhost": true, "0.0.0.0": true, "127.0.0.1": true, "::": true, "::1": true, "*": true}

// requestedName is the subdomain a forward's bind address names, without
// the domain if it was given in full; "" when it names none.
func (s *Server) requestedName(bindAddr string) string {
	name := strings.ToLower(strings.TrimSpace(bindAddr))
	if defaultBindAddrs[name] {
		return ""
	}
	return strings.TrimSuffix(name, "."+strings.ToLower(s.domain))
}

// claimForward picks and claims the subdomain for a connection's forward:
// one of the account's subdomains if the bind address names it, or else the
// connection's default, its key's stable subdomain or a random one. It
// returns the subdomain's saved options, and a note for the banner when a
// requested name isn't used.
func (s *Server) claimForward(conn *ssh.ServerConn, acct *Account, bindAddr string) (sub string, stable bool, opts tunnel.Options, note string, err error) {
	if name := s.requestedName(bindAddr); name != "" {
		if acct == nil {
			note = " (" + name + " ignored: choosing a subdomain needs an account)"
		} else {
			opts, ok := acct.reserved(name)
			if !ok {
				return "", false, tunnel.Options{}, "", fmt.Errorf("%s isn't one of your account's subdomains: reserve it in the dashboard first, or leave it out for your key's default", name)
			}
			if !s.claimStableSubdomain(name, conn, "account:"+acct.ID) {
				return "", false, tunnel.Options{}, "", fmt.Errorf("%s is in use and couldn't be taken over: try again in a moment", name)
			}
			return name, true, opts, "", nil
		}
	}
	if perms := conn.Permissions; perms != nil && perms.Extensions[permStableSubdomain] != "" {
		sub = perms.Extensions[permStableSubdomain]
		stable = s.claimStableSubdomain(sub, conn, perms.Extensions[permOwner])
	}
	if !stable {
		if sub, err = s.ReserveSubdomain(conn); err != nil {
			return "", false, tunnel.Options{}, "", fmt.Errorf("no subdomain is free right now: try again in a moment")
		}
	}
	opts, _ = acct.reserved(sub)
	return sub, stable, opts, note, nil
}
