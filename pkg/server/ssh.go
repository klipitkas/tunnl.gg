package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

type tcpipForwardRequest struct {
	BindAddr string
	BindPort uint32
}

// HandleSSHConnection handles a new SSH connection
func (s *Server) HandleSSHConnection(conn net.Conn) {
	clientIP := "unknown"
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if tcpAddr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
			// Group IPv6 by /64 like HTTP rate limiting, so rotating addresses
			// within one network doesn't get around the per-IP limits
			clientIP = visitorKey(tcpAddr.String())
		}
		// Set TCP_NODELAY to prevent SSH library from logging errors
		tcpConn.SetNoDelay(true)
	}

	// Reject before the handshake where possible, since each handshake costs
	// key exchange work and holds a connection for up to SSHHandshakeTimeout
	if !s.beginHandshake(clientIP) {
		conn.Close()
		return
	}

	// Do SSH handshake first so we can send error messages to the client
	conn.SetDeadline(time.Now().Add(config.SSHHandshakeTimeout))
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	s.endHandshake(clientIP)
	if err != nil {
		log.Printf("SSH handshake failed: %v", err)
		return
	}
	conn.SetDeadline(time.Time{}) // clear deadline after successful handshake
	defer sshConn.Close()

	// Check rate limits and reservations after handshake
	acct := connAccount(sshConn)
	slot, err := s.CheckAndReserveConnection(clientIP, acct)
	if err != nil {
		log.Printf("Connection rejected from %s: %v", clientIP, err)
		// Discard global requests to avoid goroutine leak
		go ssh.DiscardRequests(reqs)
		// Try to send error message to client via session channel
		s.sendErrorAndClose(sshConn, chans, err.Error())
		return
	}
	// Connection slot reserved - must release on exit
	defer s.ReleaseConnection(slot)

	// Track SSH connection for forced closure on IP block, or when its
	// account is closed
	s.RegisterSSHConn(clientIP, sshConn)
	defer s.UnregisterSSHConn(clientIP, sshConn)
	limits, accountID := config.FreeLimits(), ""
	if acct != nil {
		limits, accountID = acct.Limits, acct.ID
		s.addConn(s.accountConns, acct.ID, sshConn)
		defer s.removeConn(s.accountConns, acct.ID, sshConn)
	}
	if perms := sshConn.Permissions; perms != nil && perms.Extensions[permKeyFingerprint] != "" {
		fp := perms.Extensions[permKeyFingerprint]
		s.addConn(s.keyConns, fp, sshConn)
		defer s.removeConn(s.keyConns, fp, sshConn)
	}

	s.IncrementConnections()

	// Clients that connected as the stable user with a key get the key's
	// subdomain, and accounts their reserved one or the key's; everyone else,
	// or a client whose subdomain is held by someone else, gets a random one
	sub, stable := "", false
	if perms := sshConn.Permissions; perms != nil && perms.Extensions[permStableSubdomain] != "" {
		sub = perms.Extensions[permStableSubdomain]
		stable = s.claimStableSubdomain(sub, sshConn, perms.Extensions[permOwner])
	}
	if !stable {
		var err error
		if sub, err = s.ReserveSubdomain(sshConn); err != nil {
			log.Printf("Failed to generate subdomain: %v", err)
			return
		}
	}
	defer s.RemoveTunnel(sub, sshConn)
	if acct != nil {
		log.Printf("New SSH connection from %s, assigned subdomain: %s (stable: %v, account: %s)", sshConn.RemoteAddr(), sub, stable, acct.ID)
	} else {
		log.Printf("New SSH connection from %s, assigned subdomain: %s (stable: %v)", sshConn.RemoteAddr(), sub, stable)
	}

	var bindAddr string
	var bindPort uint32
	tunnelRegistered := make(chan struct{})
	var tun *tunnel.Tunnel

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle global requests (port forwarding)
	go func() {
		registered := false
		for {
			select {
			case req, ok := <-reqs:
				if !ok {
					return
				}
				switch req.Type {
				case "tcpip-forward":
					if registered {
						req.Reply(false, nil)
						continue
					}
					var fwdReq tcpipForwardRequest
					if err := ssh.Unmarshal(req.Payload, &fwdReq); err != nil {
						req.Reply(false, nil)
						continue
					}
					bindAddr = fwdReq.BindAddr
					bindPort = fwdReq.BindPort
					t := s.RegisterTunnel(sub, sshConn, bindAddr, bindPort, clientIP, limits, accountID)
					if t == nil {
						// The connection is already being cleaned up
						req.Reply(false, nil)
						return
					}
					tun = t
					registered = true
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

	url := fmt.Sprintf("https://%s.%s", sub, s.domain)
	urlMessage := sessionBanner(url, s.domain, urlNote(stable, acct), limits)

	// endSession tells the user why the session is ending, with a summary of
	// its traffic, then closes the connection
	endSession := func(reason string) {
		if logger := tun.Logger(); logger != nil {
			logger.Notice(reason + ". " + logger.Summary() + ".")
			// Flush before the connection closes, but don't wait on a client
			// that stopped reading: closing the connection unblocks the write
			logger.CloseWithin(logFlushTimeout)
		}
		sshConn.Close()
	}
	reconnectHint := "Reconnecting gives you a new URL; connect as " + config.StableSSHUser + "@ to keep one."
	if stable {
		reconnectHint = "Reconnect to keep using the same URL."
	}

	// Expiry checker: warns before the lifetime limit and closes the tunnel
	// once it expires
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		warned := false
		for {
			select {
			case <-ticker.C:
				// A zero MaxLifetime means no lifetime limit
				remaining := time.Until(tun.CreatedAt.Add(limits.MaxLifetime))
				hasLifetime := limits.MaxLifetime > 0
				if hasLifetime && !warned && remaining > 0 && remaining <= lifetimeWarning {
					warned = true
					if logger := tun.Logger(); logger != nil {
						logger.Notice(fmt.Sprintf("This tunnel closes in %s (%s limit). %s",
							formatDuration(remaining.Round(time.Minute)), formatDuration(limits.MaxLifetime), reconnectHint))
					}
				}
				if tun.IsExpired() {
					reason := "Tunnel closed after " + formatDuration(limits.InactivityTimeout) + " without traffic"
					if hasLifetime && remaining <= 0 {
						reason = "Tunnel closed: reached the " + formatDuration(limits.MaxLifetime) + " limit"
					}
					log.Printf("Tunnel %s expired: %s", sub, reason)
					endSession(reason)
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for a session channel with timeout. Channel opens must be answered
	// for as long as the connection is open: unread ones fill the SSH
	// library's queue and then stall the whole connection, tunnel included.
	sessionReceived := make(chan ssh.NewChannel, 1)
	go func() {
		gotSession := false
		for newChannel := range chans {
			switch {
			case newChannel.ChannelType() != "session":
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			case gotSession:
				newChannel.Reject(ssh.Prohibited, "only one session per connection")
			default:
				gotSession = true
				sessionReceived <- newChannel
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
	defer logger.CloseWithin(logFlushTimeout)

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
				endSession("Stopped")
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
			endSession("Stopped")
			break
		}
	}

	log.Printf("SSH connection closed for subdomain: %s", sub)
}

// lifetimeWarning is how long before the lifetime limit the user is warned.
const lifetimeWarning = 10 * time.Minute

// logFlushTimeout bounds how long a closing session waits for its request log
// to reach the client.
const logFlushTimeout = 2 * time.Second

// Session banner colors.
const (
	bannerReset  = "\033[0m"
	bannerGray   = "\033[38;5;245m"
	bannerGreen  = "\033[1;32m"
	bannerPurple = "\033[38;5;141m"
)

// sessionBanner is shown when a tunnel goes live: its URL, expiry, a QR code
// of the URL, and the header of the request log that follows.
func sessionBanner(url, domain, urlNote string, limits config.Limits) string {
	label := func(name string) string {
		return bannerGray + fmt.Sprintf("  %-9s", name) + bannerReset
	}

	banner := "\r\n" +
		bannerGreen + "  ● Tunnel is live" + bannerReset + bannerGray + " on " + domain + bannerReset + "\r\n\r\n" +
		label("URL") + bannerPurple + url + bannerReset + "\r\n" +
		label("") + bannerGray + urlNote + bannerReset + "\r\n" +
		label("Expires") + expiryText(limits) + "\r\n\r\n"

	// QR code of the URL, for opening the tunnel on a phone
	if code, err := renderQR(url, "  "); err == nil {
		banner += code + "\r\n"
	}
	return banner + bannerGray + "  Requests appear below. Press Ctrl+C to stop." + bannerReset + "\r\n\r\n" + tunnel.Header()
}

// urlNote explains in the session banner whether the URL stays the same.
func urlNote(stable bool, acct *Account) string {
	switch {
	case stable && acct != nil && acct.Subdomain != "":
		return "reserved for your account"
	case stable:
		return "stays the same for your SSH key"
	default:
		return "random: connect as " + config.StableSSHUser + "@ to keep the same URL"
	}
}

// expiryText describes when a tunnel with these limits closes.
func expiryText(limits config.Limits) string {
	idle := "after " + formatDuration(limits.InactivityTimeout) + " without traffic"
	switch {
	case limits.MaxLifetime > 0 && limits.InactivityTimeout > 0:
		return "in " + formatDuration(limits.MaxLifetime) + ", or " + idle
	case limits.MaxLifetime > 0:
		return "in " + formatDuration(limits.MaxLifetime)
	case limits.InactivityTimeout > 0:
		return idle
	default:
		return "never"
	}
}

// stableTakeoverTimeout bounds how long a new connection waits for an older
// connection with the same key to release its subdomain.
const stableTakeoverTimeout = 5 * time.Second

// claimStableSubdomain claims sub for conn. If a connection with the same key
// holds it, for example one left over from before a laptop slept, that
// connection is closed and conn takes the subdomain over once its cleanup
// releases it. It returns false if sub is held by a different key.
func (s *Server) claimStableSubdomain(sub string, conn sshConnection, keyFP string) bool {
	deadline := time.Now().Add(stableTakeoverTimeout)
	var replaced sshConnection
	for {
		holder, ok := s.claimSubdomain(sub, conn, keyFP)
		if ok {
			return true
		}
		if holder == nil || time.Now().After(deadline) {
			return false
		}
		if holder != replaced {
			log.Printf("Replacing the previous connection for stable subdomain %s", sub)
			_ = holder.Close() // its cleanup releases sub
			replaced = holder
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// beginHandshake reports whether an SSH handshake from clientIP may start,
// reserving a handshake slot if so. Blocked IPs are dropped without a message.
func (s *Server) beginHandshake(clientIP string) bool {
	if !s.abuseTracker.GetBlockExpiry(clientIP).IsZero() {
		return false
	}
	if !s.allHandshakes.acquire("") {
		return false
	}
	if !s.handshakes.acquire(clientIP) {
		s.allHandshakes.release("")
		return false
	}
	return true
}

// endHandshake releases a slot reserved by beginHandshake.
func (s *Server) endHandshake(clientIP string) {
	s.handshakes.release(clientIP)
	s.allHandshakes.release("")
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

// formatDuration formats a duration as a human-readable string (e.g., "2h", "45m")
func formatDuration(d time.Duration) string {
	if d >= time.Hour {
		h := int(d.Hours())
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}
