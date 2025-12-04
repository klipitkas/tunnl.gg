package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"

	"tunnl.gg/internal/config"
	"tunnl.gg/internal/subdomain"
	"tunnl.gg/internal/tunnel"
)

// Server manages SSH tunnels and HTTP proxying
type Server struct {
	tunnels       map[string]*tunnel.Tunnel
	ipConnections map[string]int
	sshConns      map[string][]*ssh.ServerConn // SSH connections per IP for forced closure
	mu            sync.RWMutex
	sshConfig     *ssh.ServerConfig

	// Stats
	totalConnections uint64
	totalRequests    uint64

	// Abuse protection
	abuseTracker *AbuseTracker
}

// New creates a new server instance
func New(hostKeyPath string) (*Server, error) {
	s := &Server{
		tunnels:       make(map[string]*tunnel.Tunnel),
		ipConnections: make(map[string]int),
		sshConns:      make(map[string][]*ssh.ServerConn),
		abuseTracker:  NewAbuseTracker(),
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
		NoClientAuth: true,
	}

	hostKey, err := loadOrGenerateHostKey(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load host key: %w", err)
	}
	s.sshConfig.AddHostKey(hostKey)

	return s, nil
}

// SSHConfig returns the SSH server configuration
func (s *Server) SSHConfig() *ssh.ServerConfig {
	return s.sshConfig
}

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("Generating new host key at %s", path)

		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		pemBlock := &pem.Block{
			Type:  "OPENSSH PRIVATE KEY",
			Bytes: edkey.MarshalED25519PrivateKey(priv),
		}

		if err := os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0600); err != nil {
			return nil, err
		}
	}

	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ssh.ParsePrivateKey(keyBytes)
}

// GenerateUniqueSubdomain generates a subdomain that doesn't collide with existing ones
func (s *Server) GenerateUniqueSubdomain() (string, error) {
	const maxAttempts = 10
	for i := 0; i < maxAttempts; i++ {
		sub, err := subdomain.Generate()
		if err != nil {
			return "", err
		}

		s.mu.RLock()
		_, exists := s.tunnels[sub]
		s.mu.RUnlock()

		if !exists {
			return sub, nil
		}
	}
	return "", fmt.Errorf("failed to generate unique subdomain after %d attempts", maxAttempts)
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
	if len(s.tunnels) >= config.MaxTotalTunnels {
		return fmt.Errorf("server capacity reached: max %d total tunnels", config.MaxTotalTunnels)
	}

	// Atomically reserve the connection slot
	s.ipConnections[clientIP]++
	return nil
}

// BlockIP blocks an IP address
func (s *Server) BlockIP(ip string) {
	s.abuseTracker.BlockIP(ip)
}

// DecrementIPConnection decrements the connection count for an IP
func (s *Server) DecrementIPConnection(clientIP string) {
	s.mu.Lock()
	s.ipConnections[clientIP]--
	if s.ipConnections[clientIP] <= 0 {
		delete(s.ipConnections, clientIP)
	}
	s.mu.Unlock()
}

// RegisterTunnel registers a new tunnel
func (s *Server) RegisterTunnel(sub string, listener net.Listener, bindAddr string, bindPort uint32, clientIP string) *tunnel.Tunnel {
	s.mu.Lock()
	defer s.mu.Unlock()

	t := tunnel.New(sub, listener, bindAddr, bindPort, clientIP)
	s.tunnels[sub] = t
	return t
}

// RemoveTunnel removes and closes a tunnel
func (s *Server) RemoveTunnel(sub string) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()

	// Close SSH connections - this triggers cleanup via defer in HandleSSHConnection
	// which will remove tunnels, decrement ipConnections, etc.
	sshConns := s.sshConns[ip]
	for _, conn := range sshConns {
		conn.Close()
	}
	connCount := len(sshConns)
	delete(s.sshConns, ip)

	return connCount
}

// Stop gracefully stops the server's background goroutines
func (s *Server) Stop() {
	s.abuseTracker.Stop()
}
