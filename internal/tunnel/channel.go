package tunnel

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ChannelOpener opens SSH channels to the tunnel client. It is implemented by
// *ssh.ServerConn.
type ChannelOpener interface {
	OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error)
}

// forwardedTCPPayload is the payload of a "forwarded-tcpip" channel open
// request (RFC 4254, section 7.2).
type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

// dialTimeout bounds how long opening a channel to the client may take.
const dialTimeout = 10 * time.Second

type originKey struct{}

// WithOrigin returns a context that makes Dial report addr ("host:port", the
// visitor's address) as the origin of the channel it opens.
func WithOrigin(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, originKey{}, addr)
}

// origin returns the origin address and port to report for a channel. Clients
// reject port 0, so a missing or invalid origin falls back to 127.0.0.1:1.
func origin(ctx context.Context) (string, uint32) {
	addr, _ := ctx.Value(originKey{}).(string)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "127.0.0.1", 1
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 || net.ParseIP(host) == nil {
		return "127.0.0.1", 1
	}
	return host, uint32(port)
}

// Dial opens a connection to the client's forwarded service over a new SSH
// "forwarded-tcpip" channel. Use WithOrigin to report the visitor as the
// channel's origin; pooled HTTP connections report the visitor whose request
// opened them.
func (t *Tunnel) Dial(ctx context.Context) (net.Conn, error) {
	originAddr, originPort := origin(ctx)
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	payload := ssh.Marshal(&forwardedTCPPayload{
		Addr:       t.BindAddr,
		Port:       t.BindPort,
		OriginAddr: originAddr,
		OriginPort: originPort,
	})

	type result struct {
		ch   ssh.Channel
		reqs <-chan *ssh.Request
		err  error
	}
	done := make(chan result, 1)
	go func() {
		ch, reqs, err := t.opener.OpenChannel("forwarded-tcpip", payload)
		done <- result{ch, reqs, err}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			return nil, res.err
		}
		go ssh.DiscardRequests(res.reqs)
		return newChannelConn(res.ch, t.Subdomain), nil
	case <-ctx.Done():
		// Close the channel if the client accepts it after we gave up
		go func() {
			if res := <-done; res.err == nil {
				go ssh.DiscardRequests(res.reqs)
				res.ch.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// channelConn adapts an SSH channel to net.Conn.
//
// SSH channels have no deadlines, so a deadline that expires closes the
// channel instead of failing just the pending operation. The connection is
// not usable after that, which matches how deadlines are used here: as idle
// timeouts that end the connection.
type channelConn struct {
	ssh.Channel
	addr tunnelAddr

	mu         sync.Mutex
	readTimer  *time.Timer
	writeTimer *time.Timer
}

func newChannelConn(ch ssh.Channel, sub string) *channelConn {
	return &channelConn{Channel: ch, addr: tunnelAddr(sub)}
}

func (c *channelConn) LocalAddr() net.Addr  { return c.addr }
func (c *channelConn) RemoteAddr() net.Addr { return c.addr }

func (c *channelConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *channelConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readTimer = c.resetTimer(c.readTimer, t)
	return nil
}

func (c *channelConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeTimer = c.resetTimer(c.writeTimer, t)
	return nil
}

// resetTimer arms timer to close the channel at t, or disarms it if t is zero.
func (c *channelConn) resetTimer(timer *time.Timer, t time.Time) *time.Timer {
	if t.IsZero() {
		if timer != nil {
			timer.Stop()
		}
		return timer
	}
	d := time.Until(t)
	if timer == nil {
		return time.AfterFunc(d, func() { c.Channel.Close() })
	}
	timer.Reset(d)
	return timer
}

func (c *channelConn) Close() error {
	c.mu.Lock()
	for _, timer := range []*time.Timer{c.readTimer, c.writeTimer} {
		if timer != nil {
			timer.Stop()
		}
	}
	c.mu.Unlock()
	return c.Channel.Close()
}

// tunnelAddr is the address of a connection through a tunnel.
type tunnelAddr string

func (a tunnelAddr) Network() string { return "ssh-tunnel" }
func (a tunnelAddr) String() string  { return string(a) }
