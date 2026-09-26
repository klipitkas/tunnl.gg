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

	"tunnl.gg/internal/clientip"
	"tunnl.gg/internal/config"
	"tunnl.gg/internal/subdomain"
	"tunnl.gg/internal/tunnel"
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
	keyFP string // client key fingerprint for a stable subdomain, "" for a random one
}

// Server manages SSH tunnels and HTTP proxying
type Server struct {
	tunnels         map[string]*tunnel.Tunnel
	owners          map[string]subdomainOwner // every reserved or registered subdomain
	ipConnections   map[string]int            // reserved connection slots per IP
	totalReserved   int                       // reserved connection slots server-wide
	newSubdomain    func() (string, error)
	sshConns        map[string][]*ssh.ServerConn // SSH connections per IP for forced closure
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
		ipConnections: make(map[string]int),
		sshConns:      make(map[string][]*ssh.ServerConn),
		abuseTracker:  NewAbuseTracker(),
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

// claimSubdomain reserves sub for conn, whose client key has fingerprint
// keyFP, if sub is free. If it is held by a connection with the same key,
// that connection is returned so the caller can replace it. Otherwise sub is
// held by someone else and neither is returned.
func (s *Server) claimSubdomain(sub string, conn sshConnection, keyFP string) (holder sshConnection, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	owner, held := s.owners[sub]
	if !held {
		s.owners[sub] = subdomainOwner{conn: conn, keyFP: keyFP}
		return nil, true
	}
	if keyFP != "" && owner.keyFP == keyFP {
		return owner.conn, false
	}
	return nil, false
}

// CheckAndReserveConnection checks if a new connection from the given IP is allowed
// and atomically reserves a slot if allowed. Returns true if reservation was made.
// Caller MUST call DecrementIPConnection when done if this returns nil.
func (s *Server) CheckAndReserveConnection(clientIP string) error {
	// Check if IP is blocked
	if expiry := s.abuseTracker.GetBlockExpiry(clientIP); !expiry.IsZero() {
		remaining := time.Until(expiry).Round(time.Minute)
		return fmt.Errorf("IP %s is temporarily blocked. Try again in %v", clientIP, remaining)
	}

	// Check connection rate limit
	if !s.abuseTracker.CheckConnectionRate(clientIP) {
		return fmt.Errorf("connection rate limit exceeded: max %d connections per minute. Repeated violations will result in a temporary block", config.MaxConnectionsPerMinute)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ipConnections[clientIP] >= config.MaxTunnelsPerIP {
		return fmt.Errorf("rate limit exceeded: max %d tunnels per IP", config.MaxTunnelsPerIP)
	}
	// Count reservations rather than registered tunnels, since tunnels are
	// registered later and concurrent connections could otherwise overshoot
	if s.totalReserved >= config.MaxTotalTunnels {
		return fmt.Errorf("server capacity reached: max %d total tunnels", config.MaxTotalTunnels)
	}

	// Atomically reserve the connection slot
	s.ipConnections[clientIP]++
	s.totalReserved++
	return nil
}

// DecrementIPConnection decrements the connection count for an IP
func (s *Server) DecrementIPConnection(clientIP string) {
	s.mu.Lock()
	s.ipConnections[clientIP]--
	s.totalReserved--
	if s.ipConnections[clientIP] <= 0 {
		delete(s.ipConnections, clientIP)
	}
	s.mu.Unlock()
}

// RegisterTunnel registers a tunnel for conn under a subdomain it reserved. It
// returns nil if conn no longer holds sub, so a late registration can't outlive
// its connection's cleanup or take over another connection's subdomain.
func (s *Server) RegisterTunnel(sub string, conn sshConnection, bindAddr string, bindPort uint32, clientIP string) *tunnel.Tunnel {
	s.mu.Lock()
	defer s.mu.Unlock()

	if owner, held := s.owners[sub]; !held || owner.conn != conn {
		return nil
	}
	t := tunnel.New(sub, conn, bindAddr, bindPort, clientIP)
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

// GetTunnel retrieves a tunnel by subdomain
func (s *Server) GetTunnel(sub string) *tunnel.Tunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tunnels[sub]
}

// RegisterSSHConn registers an SSH connection for an IP (for forced closure on block)
func (s *Server) RegisterSSHConn(clientIP string, conn *ssh.ServerConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sshConns[clientIP] = append(s.sshConns[clientIP], conn)
}

// UnregisterSSHConn removes an SSH connection from tracking
func (s *Server) UnregisterSSHConn(clientIP string, conn *ssh.ServerConn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	conns := s.sshConns[clientIP]
	// Build new slice without the target connection
	newConns := make([]*ssh.ServerConn, 0, len(conns))
	for _, c := range conns {
		if c != conn {
			newConns = append(newConns, c)
		}
	}

	if len(newConns) == 0 {
		delete(s.sshConns, clientIP)
	} else {
		s.sshConns[clientIP] = newConns
	}
}

// CloseAllForIP closes all SSH connections for a specific IP
// Closing SSH connections triggers cleanup which removes tunnels via defers
// Returns the number of connections closed
func (s *Server) CloseAllForIP(ip string) int {
	// Collect connections while holding the lock
	s.mu.Lock()
	sshConns := s.sshConns[ip]
	// Make a copy of the slice since we'll modify the map after releasing lock
	connsCopy := make([]*ssh.ServerConn, len(sshConns))
	copy(connsCopy, sshConns)
	// Remove from map now to prevent double-close attempts
	delete(s.sshConns, ip)
	s.mu.Unlock()

	// Close connections outside the lock to avoid deadlock
	// The cleanup handlers (UnregisterSSHConn) will be no-ops since we already removed from map
	for _, conn := range connsCopy {
		conn.Close()
	}

	return len(connsCopy)
}

// Stop gracefully stops the server's background goroutines
func (s *Server) Stop() {
	s.abuseTracker.Stop()
}
