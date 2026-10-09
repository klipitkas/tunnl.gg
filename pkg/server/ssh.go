package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
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
	limits, accountID := s.FreeLimits(), ""
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

	// The subdomain is picked when the client asks for its forward, whose
	// bind address can name one of an account's subdomains. claimMu keeps a
	// late forward from claiming one after the connection gave up waiting.
	var (
		claimMu    sync.Mutex
		done       bool
		sub        string
		stable     bool
		nameNote   string // why a requested name wasn't used
		forwardErr error  // why the forward was refused
	)
	defer func() {
		claimMu.Lock()
		done = true
		claimed := sub
		claimMu.Unlock()
		if claimed != "" {
			s.RemoveTunnel(claimed, sshConn)
		}
	}()

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
					claimMu.Lock()
					if done {
						claimMu.Unlock()
						req.Reply(false, nil)
						return
					}
					var opts tunnel.Options
					var err error
					sub, stable, opts, nameNote, err = s.claimForward(sshConn, acct, fwdReq.BindAddr)
					claimMu.Unlock()
					registered = true
					if err != nil {
						forwardErr = err
						close(tunnelRegistered)
						req.Reply(false, nil)
						continue
					}
					if acct != nil {
						log.Printf("New SSH connection from %s, assigned subdomain: %s (stable: %v, account: %s)", sshConn.RemoteAddr(), sub, stable, acct.ID)
					} else {
						log.Printf("New SSH connection from %s, assigned subdomain: %s (stable: %v)", sshConn.RemoteAddr(), sub, stable)
					}
					bindAddr = fwdReq.BindAddr
					bindPort = fwdReq.BindPort
					t := s.RegisterTunnel(sub, sshConn, bindAddr, bindPort, clientIP, limits, accountID)
					if t == nil {
						// The connection is already being cleaned up
						req.Reply(false, nil)
						return
					}
					t.SetBaseOptions(opts)
					tun = t
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
	if forwardErr != nil {
		log.Printf("Forward refused for %s: %v", sshConn.RemoteAddr(), forwardErr)
		s.sendErrorAndClose(sshConn, chans, forwardErr.Error())
		return
	}

	url := fmt.Sprintf("https://%s.%s", sub, s.domain)

	// endSession tells the user why the session is ending, with a summary of
	// its traffic, then closes the connection
	endSession := func(reason, note string) {
		if logger := tun.Logger(); logger != nil {
			msg := reason + ". " + logger.Summary() + "."
			if note != "" {
				msg += " " + note
			}
			logger.Notice(msg)
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
						logger.Notice(strings.TrimSpace(fmt.Sprintf("This tunnel closes in %s (%s limit). %s %s",
							formatDuration(remaining.Round(time.Minute)), formatDuration(limits.MaxLifetime), reconnectHint, limits.UpgradeNote)))
					}
				}
				if tun.IsExpired() {
					reason := "Tunnel closed after " + formatDuration(limits.InactivityTimeout) + " without traffic"
					if hasLifetime && remaining <= 0 {
						reason = "Tunnel closed: reached the " + formatDuration(limits.MaxLifetime) + " limit"
					}
					log.Printf("Tunnel %s expired: %s", sub, reason)
					endSession(reason, limits.UpgradeNote)
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

	// Options come in the session's exec request, before which requests to
	// the tunnel wait: they may restrict who gets in
	opts, err := readOptions(requests, limits)
	if err != nil {
		msg := "\r\n  ERROR: " + err.Error() + "\r\n\r\n" + strings.ReplaceAll(tunnel.OptionsUsage, "\n", "\r\n") + "\r\n\r\n"
		status := uint32(1)
		if errors.Is(err, tunnel.ErrHelp) {
			msg, status = "\r\n"+strings.ReplaceAll(tunnel.OptionsUsage, "\n", "\r\n")+"\r\n\r\n", 0
		}
		fmt.Fprint(channel, msg)
		channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
		channel.Close()
		return
	}
	tun.SetOptions(opts)

	shown := opts
	if acct != nil {
		shown = acct.Subdomains[sub].With(opts)
	}
	var logger *tunnel.RequestLogger
	if opts.JSON {
		fmt.Fprint(channel, sessionJSON(url, sub, stable, strings.Trim(nameNote, " ()"), limits, shown))
		logger = tunnel.NewJSONRequestLogger(channel, config.LogBufferSize)
	} else {
		fmt.Fprint(channel, sessionBanner(url, s.domain, urlNote(stable, acct, sub)+nameNote, limits, shown))
		logger = tunnel.NewRequestLogger(channel, config.LogBufferSize)
	}
	tun.SetLogger(logger)
	defer logger.CloseWithin(logFlushTimeout)

	// Handle session requests
	go func(ch ssh.Channel, reqs <-chan *ssh.Request) {
		for req := range reqs {
			switch req.Type {
			case "pty-req", "shell", "env", "window-change":
				if req.WantReply {
					req.Reply(true, nil)
				}
			case "signal":
				if req.WantReply {
					req.Reply(true, nil)
				}
				endSession("Stopped", "")
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
			// ssh without a terminal, as run by a service or with
			// < /dev/null, closes its input at once. That isn't a
			// disconnect: keep the tunnel until the connection ends.
			if errors.Is(err, io.EOF) {
				_ = sshConn.Wait() // its error is only why the connection ended
			}
			break
		}
		if buf[0] == 0x03 { // Ctrl+C
			endSession("Stopped", "")
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

// sessionBanner is shown when a tunnel goes live: its URL, expiry and
// options, a QR code of the URL, and the header of the request log that
// follows.
func sessionBanner(url, domain, urlNote string, limits config.Limits, opts tunnel.Options) string {
	label := func(name string) string {
		return bannerGray + fmt.Sprintf("  %-9s", name) + bannerReset
	}

	banner := "\r\n" +
		bannerGreen + "  ● Tunnel is live" + bannerReset + bannerGray + " on " + domain + bannerReset + "\r\n\r\n" +
		label("URL") + bannerPurple + url + bannerReset + "\r\n" +
		label("") + bannerGray + urlNote + bannerReset + "\r\n" +
		label("Expires") + expiryText(limits) + "\r\n"
	if limits.UpgradeNote != "" {
		banner += label("") + bannerGray + limits.UpgradeNote + bannerReset + "\r\n"
	}
	if opts.Host != "" {
		banner += label("Host") + opts.Host + bannerGray + " is sent to your app" + bannerReset + "\r\n"
	}
	if opts.Auth != nil {
		banner += label("Password") + bannerGray + "visitors sign in as " + bannerReset + opts.Auth.User + "\r\n"
	}
	if len(opts.Allow) > 0 {
		nets := make([]string, len(opts.Allow))
		for i, p := range opts.Allow {
			nets[i] = p.String()
			if p.IsSingleIP() {
				nets[i] = p.Addr().String()
			}
		}
		banner += label("Allowed") + strings.Join(nets, ", ") + bannerGray + " only" + bannerReset + "\r\n"
	}
	if len(opts.CORS) > 0 {
		sites := strings.Join(opts.CORS, ", ")
		if opts.CORS[0] == "*" {
			sites = "any site"
		}
		banner += label("CORS") + sites + bannerGray + " can call it from a browser" + bannerReset + "\r\n"
	}
	banner += "\r\n"

	// QR code of the URL, for opening the tunnel on a phone
	if code, err := renderQR(url, "  "); err == nil {
		banner += code + "\r\n"
	}
	return banner + bannerGray + "  Requests appear below. Press Ctrl+C to stop." + bannerReset + "\r\n\r\n" + tunnel.Header()
}

// commandTimeout bounds how long a session waits for the client's shell or
// exec request. Clients that send neither get no options.
const commandTimeout = 5 * time.Second

// readOptions reads session requests up to the client's shell or exec
// request and returns the options in its command. It answers the requests
// before it, like pty-req, and returns an error for invalid options and for
// options limits don't allow.
func readOptions(reqs <-chan *ssh.Request, limits config.Limits) (tunnel.Options, error) {
	timeout := time.After(commandTimeout)
	for {
		select {
		case req, ok := <-reqs:
			if !ok {
				return tunnel.Options{}, nil
			}
			switch req.Type {
			case "shell":
				if req.WantReply {
					req.Reply(true, nil)
				}
				return tunnel.Options{}, nil
			case "exec":
				var cmd struct{ Command string }
				if err := ssh.Unmarshal(req.Payload, &cmd); err != nil {
					if req.WantReply {
						req.Reply(false, nil)
					}
					return tunnel.Options{}, errors.New("couldn't read the command")
				}
				if req.WantReply {
					req.Reply(true, nil)
				}
				opts, err := tunnel.ParseOptions(cmd.Command)
				if err != nil {
					return tunnel.Options{}, err
				}
				for _, name := range opts.Names() {
					if !limits.AllowsOption(name) {
						msg := name + "= isn't available for this tunnel."
						if limits.OptionsNote != "" {
							msg += " " + limits.OptionsNote
						}
						return tunnel.Options{}, errors.New(msg)
					}
				}
				return opts, nil
			case "pty-req", "env", "window-change":
				if req.WantReply {
					req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		case <-timeout:
			return tunnel.Options{}, nil
		}
	}
}

// urlNote explains in the session banner whether the URL stays the same.
// sessionJSON is the banner for output=json: one line describing the tunnel,
// for scripts and AI agents. Requests and notices follow as lines of their own.
func sessionJSON(url, sub string, stable bool, warning string, limits config.Limits, opts tunnel.Options) string {
	return tunnel.JSONLine(struct {
		Event              string   `json:"event"` // "tunnel"
		URL                string   `json:"url"`
		Subdomain          string   `json:"subdomain"`
		Stable             bool     `json:"stable"` // the same URL on every reconnect
		IdleTimeoutSeconds int64    `json:"idle_timeout_seconds"`
		MaxLifetimeSeconds int64    `json:"max_lifetime_seconds"` // 0: no limit
		Options            []string `json:"options,omitempty"`
		Warning            string   `json:"warning,omitempty"`
		Upgrade            string   `json:"upgrade,omitempty"`
	}{
		Event:              "tunnel",
		URL:                url,
		Subdomain:          sub,
		Stable:             stable,
		IdleTimeoutSeconds: int64(limits.InactivityTimeout / time.Second),
		MaxLifetimeSeconds: int64(limits.MaxLifetime / time.Second),
		Options:            opts.Names(),
		Warning:            warning,
		Upgrade:            limits.UpgradeNote,
	})
}

func urlNote(stable bool, acct *Account, sub string) string {
	_, reserved := acct.reserved(sub)
	switch {
	case stable && reserved:
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
