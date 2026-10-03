package server

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/config"
)

// fakeAccounts finds accounts by key fingerprint.
type fakeAccounts struct {
	byKey map[string]*Account
	err   error
}

func (f *fakeAccounts) Lookup(key ssh.PublicKey) (*Account, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byKey[ssh.FingerprintSHA256(key)], nil
}

// withAccounts gives each key the matching account and enables accounts on s.
func withAccounts(s *Server, keys []ssh.Signer, accts []*Account) *fakeAccounts {
	store := &fakeAccounts{byKey: map[string]*Account{}}
	for i, key := range keys {
		store.byKey[ssh.FingerprintSHA256(key.PublicKey())] = accts[i]
	}
	s.SetAccounts(store)
	return store
}

// accountClient connects as the account user with key.
func accountClient(key ssh.Signer) *ssh.ClientConfig {
	cfg := anonymousClient()
	cfg.User = config.AccountSSHUser
	cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(key)}
	return cfg
}

var proLimits = config.Limits{MaxTunnels: 2}

func TestAuthNone_AccountUser(t *testing.T) {
	s := newTestServer(t)
	user := fakeConnMetadata{user: config.AccountSSHUser}

	if _, err := s.authNone(user); err != nil {
		t.Errorf("without accounts, %q should be anonymous: %v", config.AccountSSHUser, err)
	}
	s.SetAccounts(&fakeAccounts{})
	if _, err := s.authNone(user); err == nil {
		t.Errorf("with accounts, authNone() should refuse %q so the client offers its key", config.AccountSSHUser)
	}
}

func TestAuthPublicKey_Accounts(t *testing.T) {
	s := newTestServer(t)
	user := fakeConnMetadata{user: config.AccountSSHUser}
	derivedKey, reservedKey, unknownKey := newTestKey(t), newTestKey(t), newTestKey(t)
	derived := &Account{ID: "acct_derived", Limits: proLimits}
	reserved := &Account{ID: "acct_reserved", Limits: proLimits, Subdomain: "myapp"}
	store := withAccounts(s, []ssh.Signer{derivedKey, reservedKey}, []*Account{derived, reserved})

	perms, err := s.authPublicKey(user, derivedKey.PublicKey())
	if err != nil {
		t.Fatalf("authPublicKey() for an account key: %v", err)
	}
	want, _ := s.stableSubdomain(derivedKey.PublicKey())
	if got := perms.Extensions[permStableSubdomain]; got != want {
		t.Errorf("subdomain = %q, want the key's stable subdomain %q", got, want)
	}
	if got := perms.Extensions[permOwner]; got != ssh.FingerprintSHA256(derivedKey.PublicKey()) {
		t.Errorf("owner = %q, want the key fingerprint", got)
	}
	if got := perms.ExtraData[accountKey{}]; got != derived {
		t.Errorf("account = %v, want %v", got, derived)
	}

	perms, err = s.authPublicKey(user, reservedKey.PublicKey())
	if err != nil {
		t.Fatalf("authPublicKey() for an account with a reserved subdomain: %v", err)
	}
	if got := perms.Extensions[permStableSubdomain]; got != "myapp" {
		t.Errorf("subdomain = %q, want the reserved %q", got, "myapp")
	}
	if got := perms.Extensions[permOwner]; got != "account:acct_reserved" {
		t.Errorf("owner = %q, want the account, so all its keys share the subdomain", got)
	}

	if _, err := s.authPublicKey(user, unknownKey.PublicKey()); !errors.Is(err, errUnknownKey) {
		t.Errorf("unknown key: got %v, want %v", err, errUnknownKey)
	}

	for _, invalid := range []*Account{{ID: ""}, {ID: "acct_bad", Subdomain: "Not.A.Label"}} {
		store.byKey[ssh.FingerprintSHA256(unknownKey.PublicKey())] = invalid
		if _, err := s.authPublicKey(user, unknownKey.PublicKey()); !errors.Is(err, errAccountLookup) {
			t.Errorf("invalid account %+v: got %v, want %v", invalid, err, errAccountLookup)
		}
	}

	store.err = errors.New("database down")
	if _, err := s.authPublicKey(user, derivedKey.PublicKey()); !errors.Is(err, errAccountLookup) {
		t.Errorf("failed lookup: got %v, want %v", err, errAccountLookup)
	}
}

func TestCheckAndReserveConnection_AccountsLimitedPerAccount(t *testing.T) {
	s := newTestServer(t)
	acct := &Account{ID: "acct_1", Limits: config.Limits{MaxTunnels: 1}}

	slot, err := s.CheckAndReserveConnection("192.0.2.1", acct)
	if err != nil {
		t.Fatalf("first account connection: %v", err)
	}
	if _, err := s.CheckAndReserveConnection("198.51.100.1", acct); err == nil {
		t.Error("the account's limit should apply across IPs")
	}
	for i := 0; i < config.MaxTunnelsPerIP; i++ {
		if _, err := s.CheckAndReserveConnection("192.0.2.1", nil); err != nil {
			t.Fatalf("anonymous connection %d from the account's IP: %v", i+1, err)
		}
	}

	s.ReleaseConnection(slot)
	if _, err := s.CheckAndReserveConnection("198.51.100.1", acct); err != nil {
		t.Errorf("account connection after releasing its slot: %v", err)
	}

	unlimited := &Account{ID: "acct_unlimited"}
	for i := 0; i < config.MaxTunnelsPerIP+1; i++ {
		if _, err := s.CheckAndReserveConnection("203.0.113.1", unlimited); err != nil {
			t.Fatalf("connection %d for an account without a tunnel limit: %v", i+1, err)
		}
	}
}

func TestE2E_AccountWithReservedSubdomain(t *testing.T) {
	srv, addr := startSSHServer(t)
	alice, bob := newTestKey(t), newTestKey(t)
	team := &Account{ID: "acct_team", Limits: proLimits, Subdomain: "myapp"}
	withAccounts(srv, []ssh.Signer{alice, bob}, []*Account{team, team})

	first := openTunnel(t, srv, addr, accountClient(alice), echoBackend("alice"))
	if first.sub != "myapp" {
		t.Fatalf("account got subdomain %q, want its reserved %q", first.sub, "myapp")
	}
	banner := first.output.String()
	for _, want := range []string{"reserved for your account", "never\r\n"} {
		if !strings.Contains(banner, want) {
			t.Errorf("banner should contain %q: %q", want, banner)
		}
	}

	// No warning page: the account's limits turn it off
	req := httptest.NewRequest(http.MethodGet, "https://myapp."+config.DefaultDomain+"/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "alice" {
		t.Errorf("browser got %d %q, want the app without the warning page", rec.Code, rec.Body.String())
	}

	// Another key of the same account takes the subdomain over
	second := openTunnel(t, srv, addr, accountClient(bob), echoBackend("bob"))
	if second.sub != "myapp" {
		t.Fatalf("second key got %q, want the account's %q", second.sub, "myapp")
	}
	body, _ := io.ReadAll(second.get(t, "/").Body)
	if string(body) != "bob" {
		t.Errorf("traffic went to %q, want the newest session", body)
	}

	waitFor(t, "first session to be replaced", func() bool {
		srv.mu.RLock()
		defer srv.mu.RUnlock()
		return len(srv.accountConns[team.ID]) == 1
	})
	if n := srv.CloseAccount(team.ID); n != 1 {
		t.Errorf("CloseAccount() closed %d connections, want 1", n)
	}
	waitFor(t, "closed account's tunnel to be removed", func() bool { return srv.GetTunnel("myapp") == nil })
}

func TestE2E_AccountKeyRequired(t *testing.T) {
	srv, addr := startSSHServer(t)
	withAccounts(srv, []ssh.Signer{newTestKey(t)}, []*Account{{ID: "acct_1", Limits: proLimits}})

	if client, err := ssh.Dial("tcp", addr, accountClient(newTestKey(t))); err == nil {
		client.Close()
		t.Error("a key that belongs to no account should be refused")
	}
	if client, err := ssh.Dial("tcp", addr, anonymousClient()); err != nil {
		t.Errorf("anonymous clients should still connect: %v", err)
	} else {
		client.Close()
	}
}
