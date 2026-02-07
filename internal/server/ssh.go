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
	"tunnl.gg/internal/tunnel"
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

	sub, err := s.GenerateUniqueSubdomain()
	if err != nil {
		log.Printf("Failed to generate subdomain: %v", err)
		return
	}
	log.Printf("New SSH connection from %s, assigned subdomain: %s", sshConn.RemoteAddr(), sub)

	tunnelListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Printf("Failed to create tunnel listener: %v", err)
		return
	}
	// Ensure listener is closed on early return (before tunnel registration)
	// This is safe even after tunnel registration since net.Listener.Close() is idempotent
	defer tunnelListener.Close()

	var bindAddr string
	var bindPort uint32
	tunnelRegistered := make(chan struct{})
	var tun *tunnel.Tunnel

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle global requests (port forwarding)
	go func() {
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
					bindAddr = fwdReq.BindAddr
					bindPort = fwdReq.BindPort
					tun = s.RegisterTunnel(sub, tunnelListener, bindAddr, bindPort, clientIP)
					tun.SetSSHConn(sshConn)
					close(tunnelRegistered)
					req.Reply(true, nil)
				case "cancel-tcpip-forward":
					req.Reply(true, nil)
				default:
					req.Reply(false, nil)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	select {
	case <-tunnelRegistered:
	case <-time.After(30 * time.Second):
		log.Printf("Timeout waiting for tcpip-forward request from %s", sshConn.RemoteAddr())
		return
	}

	defer s.RemoveTunnel(sub)

	url := fmt.Sprintf("https://%s.%s", sub, s.domain)
	expiresAt := tun.CreatedAt.Add(config.MaxTunnelLifetime).Format("Jan 02, 2006 at 15:04 MST")

	expiresLine := fmt.Sprintf("%s (or %s idle)", expiresAt, formatDuration(config.InactivityTimeout))

	urlMessage := fmt.Sprintf("\r\n"+
		"  +-------------------------------------------------------------+\r\n"+
		"  |                         tunnl.gg                            |\r\n"+
		"  +-------------------------------------------------------------+\r\n"+
		"  |  URL: %-53s |\r\n"+
		"  |  Expires: %-49s |\r\n"+
		"  +-------------------------------------------------------------+\r\n"+
		"  |  Press Ctrl+C to close the tunnel                           |\r\n"+
		"  +-------------------------------------------------------------+\r\n\r\n",
		url, expiresLine)

	// Inactivity checker
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if tun.IsExpired() {
					log.Printf("Tunnel %s expired due to inactivity", sub)
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

	fmt.Fprint(channel, urlMessage)

	logger := tunnel.NewRequestLogger(channel, config.LogBufferSize)
	tun.SetLogger(logger)
	defer logger.Close()

	// Accept connections on the tunnel listener
	go func() {
		for {
			tcpConn, err := tunnelListener.Accept()
			if err != nil {
				return
			}
			tun.Touch()
			go s.forwardToSSH(sshConn, tcpConn, tun)
		}
	}()

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

	log.Printf("SSH connection closed for subdomain: %s", sub)
}

// sendErrorAndClose sends an error message to the client and closes the connection
// This is used when the connection is rejected after SSH handshake (e.g., IP blocked)
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

	var originAddr string
	var originPort uint32
	if tcpAddr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
		originAddr = tcpAddr.IP.String()
		originPort = uint32(tcpAddr.Port)
	} else {
		originAddr = "0.0.0.0"
		originPort = 0
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

// formatDuration formats a duration as a human-readable string (e.g., "2h", "45m")
func formatDuration(d time.Duration) string {
	if d >= time.Hour {
		h := int(d.Hours())
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}
