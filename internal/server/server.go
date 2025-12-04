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
	mu            sync.RWMutex
	sshConfig     *ssh.ServerConfig

	// Stats
	totalConnections uint64
	totalRequests    uint64
}

// New creates a new server instance
func New(hostKeyPath string) (*Server, error) {
	s := &Server{
		tunnels:       make(map[string]*tunnel.Tunnel),
		ipConnections: make(map[string]int),
	}

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

// CheckRateLimits checks if a new connection from the given IP is allowed
func (s *Server) CheckRateLimits(clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ipConnections[clientIP] >= config.MaxTunnelsPerIP {
		return fmt.Errorf("rate limit exceeded: max %d tunnels per IP", config.MaxTunnelsPerIP)
	}
	if len(s.tunnels) >= config.MaxTotalTunnels {
		return fmt.Errorf("server capacity reached: max %d total tunnels", config.MaxTotalTunnels)
	}
	return nil
}

// IncrementIPConnection increments the connection count for an IP
func (s *Server) IncrementIPConnection(clientIP string) {
	s.mu.Lock()
	s.ipConnections[clientIP]++
	s.mu.Unlock()
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
func (s *Server) RegisterTunnel(sub string, listener net.Listener, bindAddr string, bindPort uint32) *tunnel.Tunnel {
	s.mu.Lock()
	defer s.mu.Unlock()

	t := tunnel.New(sub, listener, bindAddr, bindPort)
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
