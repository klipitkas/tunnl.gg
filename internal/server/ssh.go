package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"tunnl.gg/internal/config"
	"tunnl.gg/internal/subdomain"
	"tunnl.gg/internal/tunnel"
)

// ANSI color codes for SSH terminal output.
const (
	ansiReset     = "\033[0m"
	ansiGray      = "\033[38;5;245m"
	ansiBoldGreen = "\033[1;32m"
	ansiPurple    = "\033[38;5;141m"
)

type tcpipForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

// tunnelEntry groups a tunnel with its listener and subdomain.
type tunnelEntry struct {
	sub      string
	listener net.Listener
	tun      *tunnel.Tunnel
}

// HandleSSHConnection handles a new SSH connection
func (s *Server) HandleSSHConnection(conn net.Conn) {
	clientIP := "unknown"
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if tcpAddr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
			clientIP = tcpAddr.IP.String()
		}
		// Set TCP_NODELAY to prevent SSH library from logging errors
		tcpConn.SetNoDelay(true)
	}

	// Do SSH handshake first so we can send error messages to the client
	conn.SetDeadline(time.Now().Add(config.SSHHandshakeTimeout))
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		log.Printf("SSH handshake failed: %v", err)
		return
	}
	conn.SetDeadline(time.Time{}) // clear deadline after successful handshake
	defer sshConn.Close()

	// Check rate limits and reservations after handshake
	if err := s.CheckAndReserveConnection(clientIP); err != nil {
		log.Printf("Connection rejected from %s: %v", clientIP, err)
		// Discard global requests to avoid goroutine leak
		go ssh.DiscardRequests(reqs)
		// Try to send error message to client via session channel
		s.sendErrorAndClose(sshConn, chans, err.Error())
		return
	}
	// Connection slot reserved - must decrement on exit
	defer s.DecrementIPConnection(clientIP)

	// Track SSH connection for forced closure on IP block
	s.RegisterSSHConn(clientIP, sshConn)
	defer s.UnregisterSSHConn(clientIP, sshConn)

	s.IncrementConnections()

	baseSub, err := s.GenerateUniqueSubdomain()
	if err != nil {
		log.Printf("Failed to generate subdomain: %v", err)
		return
	}
	log.Printf("New SSH connection from %s, assigned base subdomain: %s", sshConn.RemoteAddr(), baseSub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Collect all tunnel entries via request handler goroutine.
	// The goroutine owns the entries slice exclusively until it finishes.
	entriesCh := make(chan []*tunnelEntry, 1)
	firstTunnelRegistered := make(chan struct{})

	// Handle global requests (port forwarding) — one per tcpip-forward
	go func() {
		var entries []*tunnelEntry
		defer func() { entriesCh <- entries }()

		// After the first tunnel, wait briefly for additional -R forwards
		// (SSH clients send them serially in quick succession), then return
		// to hand the final entries slice to the main goroutine.
		var batchTimer <-chan time.Time

		for {
			select {
			case req, ok := <-reqs:
				if !ok {
					return
				}
				switch req.Type {
				case "tcpip-forward":
					var fwdReq tcpipForwardRequest
					if err := ssh.Unmarshal(req.Payload, &fwdReq); err != nil {
						req.Reply(false, nil)
						continue
					}

					// Enforce per-connection port limit
					if len(entries) >= config.MaxPortsPerConnection {
						log.Printf("Port limit reached for %s (max %d)", baseSub, config.MaxPortsPerConnection)
						req.Reply(false, nil)
						continue
					}

					// Determine subdomain: first gets base, rest get base-port
					sub := baseSub
					if len(entries) > 0 {
						sub = subdomain.WithPort(baseSub, fwdReq.BindPort)
					}

					// Create listener for this port
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						log.Printf("Failed to create tunnel listener: %v", err)
						req.Reply(false, nil)
						continue
					}

					// Register tunnel atomically (checks capacity + duplicates)
					tun, err := s.RegisterTunnel(sub, listener, fwdReq.BindAddr, fwdReq.BindPort, clientIP)
					if err != nil {
						log.Printf("Failed to register tunnel %s: %v", sub, err)
						listener.Close()
						req.Reply(false, nil)
						continue
					}
					tun.SetSSHConn(sshConn)

					entries = append(entries, &tunnelEntry{
						sub:      sub,
						listener: listener,
						tun:      tun,
					})

					// Signal that the first tunnel is ready and start batch timer
					if len(entries) == 1 {
						close(firstTunnelRegistered)
					}
					// Reset batch timer on every new port to collect them all
					batchTimer = time.After(100 * time.Millisecond)

					req.Reply(true, nil)
				case "cancel-tcpip-forward":
					req.Reply(true, nil)
				default:
					req.Reply(false, nil)
				}
			case <-batchTimer:
				// All ports collected — hand entries to main goroutine
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// entries is set once by drainEntries and read by the cleanup defer and normal flow.
	var entries []*tunnelEntry
	drainEntries := func() {
		if entries == nil {
			cancel() // ensure request handler goroutine exits
			entries = <-entriesCh
		}
	}

	// Cleanup any registered tunnels when the request handler finishes.
	// This defer must be registered before the early-return timeout below
	// so that tunnels are cleaned up even if no tcpip-forward arrives in time.
	defer func() {
		drainEntries()
		for _, entry := range entries {
			s.RemoveTunnel(entry.sub)
		}
	}()

	// Wait for at least one tunnel to be registered
	select {
	case <-firstTunnelRegistered:
	case <-time.After(30 * time.Second):
		log.Printf("Timeout waiting for tcpip-forward request from %s", sshConn.RemoteAddr())
		return
	}

	// Wait for request handler to finish collecting all ports
	drainEntries()

	banner := s.buildBanner(entries)

	// Inactivity checker: close connection when all tunnels have expired
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if allTunnelsExpired(entries) {
					log.Printf("All tunnels for %s expired due to inactivity", baseSub)
					sshConn.Close()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for a session channel with timeout
	sessionReceived := make(chan ssh.NewChannel, 1)
	go func() {
		for {
			select {
			case newChannel, ok := <-chans:
				if !ok {
					return
				}
				if newChannel.ChannelType() == "session" {
					sessionReceived <- newChannel
					return
				}
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			case <-ctx.Done():
				return
			}
		}
	}()

	var sessionChannel ssh.NewChannel
	select {
	case sessionChannel = <-sessionReceived:
	case <-time.After(5 * time.Second):
		log.Printf("Connection from %s rejected: no session channel (use ssh -t)", sshConn.RemoteAddr())
		return
	}

	channel, requests, err := sessionChannel.Accept()
	if err != nil {
		log.Printf("Failed to accept session channel: %v", err)
		return
	}

	fmt.Fprint(channel, banner)

	// Shared request logger for all tunnels
	logger := tunnel.NewRequestLogger(channel, config.LogBufferSize)
	for _, entry := range entries {
		entry.tun.SetLogger(logger)
	}
	defer logger.Close()

	// Start an accept loop for each tunnel's listener
	for _, entry := range entries {
		go func() {
			for {
				tcpConn, err := entry.listener.Accept()
				if err != nil {
					return
				}
				entry.tun.Touch()
				go s.forwardToSSH(sshConn, tcpConn, entry.tun)
			}
		}()
	}

	// Handle session requests
	go func(ch ssh.Channel, reqs <-chan *ssh.Request) {
		for req := range reqs {
			switch req.Type {
			case "pty-req", "shell":
				if req.WantReply {
					req.Reply(true, nil)
				}
			case "signal":
				if req.WantReply {
					req.Reply(true, nil)
				}
				sshConn.Close()
				return
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}(channel, requests)

	// Read from channel to detect disconnect or Ctrl+C
	buf := make([]byte, 1)
	for {
		_, err := channel.Read(buf)
		if err != nil {
			break
		}
		if buf[0] == 0x03 { // Ctrl+C
			sshConn.Close()
			break
		}
	}

	log.Printf("SSH connection closed for subdomain: %s", baseSub)
}

// buildBanner constructs the SSH terminal banner showing tunnel URL(s) and expiry.
func (s *Server) buildBanner(entries []*tunnelEntry) string {
	firstTun := entries[0].tun
	expiresAt := firstTun.CreatedAt.Add(config.MaxTunnelLifetime).Format("Jan 02, 2006 at 15:04 MST")
	expiresLine := fmt.Sprintf("%s (or %s idle)", expiresAt, formatDuration(config.InactivityTimeout))

	heading := "Tunnel is live!"
	if len(entries) > 1 {
		heading = "Tunnels are live!"
	}

	msg := "\r\n" +
		ansiGray + "Connected to " + s.domain + "." + ansiReset + "\r\n" +
		ansiBoldGreen + heading + ansiReset + "\r\n"

	if len(entries) == 1 {
		url := fmt.Sprintf("https://%s.%s", entries[0].sub, s.domain)
		msg += ansiGray + "Public URL: " + ansiPurple + url + ansiReset + "\r\n"
	} else {
		for _, entry := range entries {
			url := fmt.Sprintf("https://%s.%s", entry.sub, s.domain)
			portLabel := fmt.Sprintf(":%-5d", entry.tun.BindPort)
			msg += ansiGray + "  " + portLabel + " \u2192 " + ansiPurple + url + ansiReset + "\r\n"
		}
	}

	msg += ansiGray + "Expires:    " + expiresLine + ansiReset + "\r\n\r\n"
	return msg
}

// sendErrorAndClose sends an error message to the client and closes the connection.
// This is used when the connection is rejected after SSH handshake (e.g., IP blocked).
func (s *Server) sendErrorAndClose(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel, errMsg string) {
	// Wait for session channel with short timeout
	select {
	case newChannel, ok := <-chans:
		if !ok {
			return
		}
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			return
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		// Handle pty-req and shell requests so the message displays properly
		go func() {
			for req := range requests {
				if req.Type == "pty-req" || req.Type == "shell" {
					if req.WantReply {
						req.Reply(true, nil)
					}
				} else if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}()
		// Send error message
		fmt.Fprintf(channel, "\r\n  ERROR: %s\r\n\r\n", errMsg)
		channel.Close()
	case <-time.After(3 * time.Second):
		// Client didn't send session channel in time
		return
	}
}

func (s *Server) forwardToSSH(sshConn *ssh.ServerConn, tcpConn net.Conn, tun *tunnel.Tunnel) {
	defer tcpConn.Close()

	originAddr := "0.0.0.0"
	var originPort uint32
	if tcpAddr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
		originAddr = tcpAddr.IP.String()
		originPort = uint32(tcpAddr.Port)
	}

	channel, reqs, err := sshConn.OpenChannel("forwarded-tcpip", ssh.Marshal(&forwardedTCPPayload{
		Addr:       tun.BindAddr,
		Port:       tun.BindPort,
		OriginAddr: originAddr,
		OriginPort: originPort,
	}))
	if err != nil {
		log.Printf("Failed to open forwarded-tcpip channel: %v", err)
		return
	}
	defer channel.Close()

	go ssh.DiscardRequests(reqs)

	// Copy data bidirectionally. When one direction completes (or errors),
	// close the write side to signal the other goroutine to finish.
	done := make(chan struct{})
	go func() {
		io.Copy(channel, tcpConn)
		// Signal SSH channel we're done sending
		channel.CloseWrite()
	}()
	go func() {
		defer close(done)
		io.Copy(tcpConn, channel)
	}()
	<-done
}

func allTunnelsExpired(entries []*tunnelEntry) bool {
	for _, entry := range entries {
		if !entry.tun.IsExpired() {
			return false
		}
	}
	return true
}

// formatDuration formats a duration as a human-readable string (e.g., "2h", "45m").
func formatDuration(d time.Duration) string {
	if d >= time.Hour {
		h := int(d.Hours())
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}
