package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/clientip"
	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/subdomain"
	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

// sshConnection is the SSH connection a tunnel belongs to (an *ssh.ServerConn).
type sshConnection interface {
	tunnel.ChannelOpener
	Close() error
}

// subdomainOwner is the connection holding a subdomain, from when it is
// reserved until its tunnel is removed.
type subdomainOwner struct {
	conn  sshConnection
	owner string // who may take a stable subdomain over (see permOwner), "" for a random one
}

// Server manages SSH tunnels and HTTP proxying
type Server struct {
	tunnels         map[string]*tunnel.Tunnel
	owners          map[string]subdomainOwner // every reserved or registered subdomain
	slots           map[string]int            // reserved connection slots per IP or account
	totalReserved   int                       // reserved connection slots server-wide
	newSubdomain    func() (string, error)
	sshConns        map[string][]*ssh.ServerConn // SSH connections per IP for forced closure
	accountConns    map[string][]*ssh.ServerConn // SSH connections per account ID for forced closure
	keyConns        map[string][]*ssh.ServerConn // SSH connections per client key fingerprint for forced closure
	accounts        AccountStore                 // nil unless the deployment has accounts
	freeLimits      config.Limits                // for anonymous clients; see SetFreeLimits
	mu              sync.RWMutex
	sshConfig       *ssh.ServerConfig
	domain          string
	subdomainSecret []byte // keys the derivation of stable subdomains

	// Stats
	totalConnections uint64
	totalRequests    uint64

	// Abuse protection
	abuseTracker  *AbuseTracker
	wsPerTunnel   *connLimiter       // concurrent WebSockets keyed by subdomain
	wsPerVisitor  *connLimiter       // concurrent WebSockets keyed by visitor IP
	reqPerTunnel  *connLimiter       // in-flight proxied requests keyed by subdomain
	reqPerVisitor *connLimiter       // in-flight proxied requests keyed by visitor IP
	handshakes    *connLimiter       // in-progress SSH handshakes keyed by client IP
	clientIPs     *clientip.Resolver // resolves visitors behind trusted proxies
	// in-progress SSH handshakes server-wide, all under the single key ""
	allHandshakes *connLimiter
}

// New creates a new server instance
func New(hostKeyPath string, domain string) (*Server, error) {
	s := &Server{
		tunnels:       make(map[string]*tunnel.Tunnel),
		owners:        make(map[string]subdomainOwner),
		newSubdomain:  subdomain.Generate,
		slots:         make(map[string]int),
		sshConns:      make(map[string][]*ssh.ServerConn),
		accountConns:  make(map[string][]*ssh.ServerConn),
		keyConns:      make(map[string][]*ssh.ServerConn),
		abuseTracker:  NewAbuseTracker(),
		freeLimits:    config.FreeLimits(),
		wsPerTunnel:   newConnLimiter(config.MaxWebSocketsPerTunnel),
		wsPerVisitor:  newConnLimiter(config.MaxWebSocketsPerVisitor),
		reqPerTunnel:  newConnLimiter(config.MaxInFlightPerTunnel),
		reqPerVisitor: newConnLimiter(config.MaxInFlightPerVisitor),
		handshakes:    newConnLimiter(config.MaxHandshakesPerIP),
		allHandshakes: newConnLimiter(config.MaxConcurrentHandshakes),
		domain:        domain,
	}

	// Set callback to close SSH connections when IP is blocked
	// Closing SSH connections triggers cleanup which removes tunnels via defers
	s.abuseTracker.SetOnBlockCallback(func(ip string) {
		connCount := s.CloseAllForIP(ip)
		if connCount > 0 {
			log.Printf("Closed %d SSH connection(s) for blocked IP %s", connCount, ip)
		}
	})

	s.sshConfig = &ssh.ServerConfig{
		NoClientAuth:         true,
		NoClientAuthCallback: s.authNone,
		PublicKeyCallback:    s.authPublicKey,
	}

	hostKey, hostKeyPEM, err := loadOrGenerateHostKey(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load host key: %w", err)
	}
	s.sshConfig.AddHostKey(hostKey)
	s.subdomainSecret = subdomainSecretFromHostKey(hostKeyPEM)

	return s, nil
}

// SetTrustedProxies sets the proxies whose forwarding headers identify
// visitors. By default no proxies are trusted.
func (s *Server) SetTrustedProxies(r *clientip.Resolver) {
	s.clientIPs = r
}

// loadOrGenerateHostKey returns the SSH host key and its PEM encoding,
// generating the key first if it doesn't exist.
func loadOrGenerateHostKey(path string) (ssh.Signer, []byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("Generating new host key at %s", path)

		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		pemBlock := &pem.Block{
			Type:  "OPENSSH PRIVATE KEY",
			Bytes: edkey.MarshalED25519PrivateKey(priv),
		}

		if err := os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0600); err != nil {
			return nil, nil, err
		}
	}

	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	return signer, keyBytes, err
}

// ReserveSubdomain generates a random subdomain that isn't in use and reserves
// it for conn until RemoveTunnel is called.
func (s *Server) ReserveSubdomain(conn sshConnection) (string, error) {
	const maxAttempts = 10
	for i := 0; i < maxAttempts; i++ {
		sub, err := s.newSubdomain()
		if err != nil {
			return "", err
		}

		s.mu.Lock()
		if _, held := s.owners[sub]; !held {
			s.owners[sub] = subdomainOwner{conn: conn}
			s.mu.Unlock()
			return sub, nil
		}
		s.mu.Unlock()
	}
	return "", fmt.Errorf("failed to generate unique subdomain after %d attempts", maxAttempts)
}

// claimSubdomain reserves sub for conn, on behalf of owner (see permOwner),
// if sub is free. If it is held by a connection with the same owner, that
// connection is returned so the caller can replace it. Otherwise sub is held
// by someone else and neither is returned.
func (s *Server) claimSubdomain(sub string, conn sshConnection, owner string) (holder sshConnection, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, held := s.owners[sub]
	if !held {
		s.owners[sub] = subdomainOwner{conn: conn, owner: owner}
		return nil, true
	}
	if owner != "" && current.owner == owner {
		return current.conn, false
	}
	return nil, false
}

// CheckAndReserveConnection checks if a new connection from the given IP, on
// behalf of acct if it isn't nil, is allowed and atomically reserves a slot if
// so. Anonymous clients are limited per IP, accounts per account. If it
// returns no error, the caller MUST call ReleaseConnection with the returned
// slot when done.
func (s *Server) CheckAndReserveConnection(clientIP string, acct *Account) (slot string, err error) {
	// Check if IP is blocked
	if expiry := s.abuseTracker.GetBlockExpiry(clientIP); !expiry.IsZero() {
		remaining := time.Until(expiry).Round(time.Minute)
		return "", fmt.Errorf("IP %s is temporarily blocked. Try again in %v", clientIP, remaining)
	}

	// Check connection rate limit
	if !s.abuseTracker.CheckConnectionRate(clientIP) {
		return "", fmt.Errorf("connection rate limit exceeded: max %d connections per minute. Repeated violations will result in a temporary block", config.MaxConnectionsPerMinute)
	}

	// A zero limit means no limit for accounts. The prefix keeps account IDs
	// from colliding with IPs.
	slot, limit, per := clientIP, s.FreeLimits().MaxTunnels, "IP"
	if acct != nil {
		slot, limit, per = "account:"+acct.ID, acct.Limits.MaxTunnels, "account"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if limit > 0 && s.slots[slot] >= limit {
		return "", fmt.Errorf("rate limit exceeded: max %d tunnels per %s", limit, per)
	}
	// Count reservations rather than registered tunnels, since tunnels are
	// registered later and concurrent connections could otherwise overshoot
	if s.totalReserved >= config.MaxTotalTunnels {
		return "", fmt.Errorf("server capacity reached: max %d total tunnels", config.MaxTotalTunnels)
	}

	// Atomically reserve the connection slot
	s.slots[slot]++
	s.totalReserved++
	return slot, nil
}

// ReleaseConnection releases a slot reserved by CheckAndReserveConnection.
func (s *Server) ReleaseConnection(slot string) {
	s.mu.Lock()
	s.slots[slot]--
	s.totalReserved--
	if s.slots[slot] <= 0 {
		delete(s.slots, slot)
	}
	s.mu.Unlock()
}

// SetFreeLimits sets the limits for anonymous clients' tunnels, instead of
// config.FreeLimits. Call it before serving.
func (s *Server) SetFreeLimits(l config.Limits) {
	s.mu.Lock()
	s.freeLimits = l
	s.mu.Unlock()
}

// FreeLimits returns the limits for anonymous clients' tunnels.
func (s *Server) FreeLimits() config.Limits {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.freeLimits
}

// RegisterTunnel registers a tunnel for conn, with the given limits, under a
// subdomain it reserved. It returns nil if conn no longer holds sub, so a late
// registration can't outlive its connection's cleanup or take over another
// connection's subdomain.
func (s *Server) RegisterTunnel(sub string, conn sshConnection, bindAddr string, bindPort uint32, clientIP string, limits config.Limits, accountID string) *tunnel.Tunnel {
	s.mu.Lock()
	defer s.mu.Unlock()

	if owner, held := s.owners[sub]; !held || owner.conn != conn {
		return nil
	}
	t := tunnel.New(sub, conn, bindAddr, bindPort, clientIP)
	t.Limits = limits
	t.AccountID = accountID
	t.AwaitOptions()
	s.tunnels[sub] = t
	return t
}

// RemoveTunnel removes and closes conn's tunnel and releases its subdomain. It
// does nothing if another connection has since taken the subdomain over.
func (s *Server) RemoveTunnel(sub string, conn sshConnection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if owner, held := s.owners[sub]; !held || owner.conn != conn {
		return
	}
	delete(s.owners, sub)
	if t, ok := s.tunnels[sub]; ok {
		t.Close()
		delete(s.tunnels, sub)
	}
}

// TunnelInfo describes an open tunnel.
type TunnelInfo struct {
	Subdomain string
	ClientIP  string // grouped by /64 for IPv6, like the per-IP limits
	AccountID string // "" for anonymous clients
	CreatedAt time.Time
}

// Tunnels lists the open tunnels, for example for abuse scanning.
func (s *Server) Tunnels() []TunnelInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]TunnelInfo, 0, len(s.tunnels))
	for _, t := range s.tunnels {
		list = append(list, TunnelInfo{Subdomain: t.Subdomain, ClientIP: t.ClientIP, AccountID: t.AccountID, CreatedAt: t.CreatedAt})
	}
	return list
}

// BanIP refuses SSH connections from ip until the given time and closes its
// open ones, for abuse. IPv6 addresses are banned by /64, like the per-IP
// limits. A ban only ever gets longer; UnbanIP lifts it.
func (s *Server) BanIP(ip string, until time.Time) {
	s.abuseTracker.BlockIPUntil(visitorKey(ip), until)
}

// UnbanIP lifts a ban, or an automatic block, on ip.
func (s *Server) UnbanIP(ip string) {
	s.abuseTracker.Unblock(visitorKey(ip))
}

// GetTunnel retrieves a tunnel by subdomain
func (s *Server) GetTunnel(sub string) *tunnel.Tunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tunnels[sub]
}

// RegisterSSHConn registers an SSH connection for an IP (for forced closure on block)
func (s *Server) RegisterSSHConn(clientIP string, conn *ssh.ServerConn) {
	s.addConn(s.sshConns, clientIP, conn)
}

// UnregisterSSHConn removes an SSH connection from tracking
func (s *Server) UnregisterSSHConn(clientIP string, conn *ssh.ServerConn) {
	s.removeConn(s.sshConns, clientIP, conn)
}

// CloseAllForIP closes all SSH connections for a specific IP
// Closing SSH connections triggers cleanup which removes tunnels via defers
// Returns the number of connections closed
func (s *Server) CloseAllForIP(ip string) int {
	return closeConns(s.takeConns(s.sshConns, ip))
}

// addConn adds conn to the connections tracked under key in conns.
func (s *Server) addConn(conns map[string][]*ssh.ServerConn, key string, conn *ssh.ServerConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	conns[key] = append(conns[key], conn)
}

// removeConn stops tracking conn under key in conns.
func (s *Server) removeConn(conns map[string][]*ssh.ServerConn, key string, conn *ssh.ServerConn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Build new slice without the target connection
	kept := make([]*ssh.ServerConn, 0, len(conns[key]))
	for _, c := range conns[key] {
		if c != conn {
			kept = append(kept, c)
		}
	}

	if len(kept) == 0 {
		delete(conns, key)
	} else {
		conns[key] = kept
	}
}

// takeConns stops tracking the connections under key in conns and returns
// them. Removing them now prevents double-close attempts; their cleanup
// handlers' removeConn calls become no-ops.
func (s *Server) takeConns(conns map[string][]*ssh.ServerConn, key string) []*ssh.ServerConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	taken := conns[key]
	delete(conns, key)
	return taken
}

// closeConns closes conns, which triggers their cleanup, and returns how
// many there were. Callers must not hold s.mu, since cleanup takes it.
func closeConns(conns []*ssh.ServerConn) int {
	for _, conn := range conns {
		conn.Close()
	}
	return len(conns)
}

// Stop gracefully stops the server's background goroutines
func (s *Server) Stop() {
	s.abuseTracker.Stop()
}
