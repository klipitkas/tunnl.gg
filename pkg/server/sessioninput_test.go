package server

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countedConn counts the bytes the server reads from and writes to a client.
type countedConn struct {
	net.Conn
	read, written *atomic.Int64
}

func (c countedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

func (c countedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, err
}

// TestE2E_InputFloodNotAmplified covers a client streaming into the session's
// input, like "yes | ssh -R ..." or a service piping its output. Reading that
// a byte at a time sent a window adjustment per byte: about 36 bytes out for
// each byte in.
func TestE2E_InputFloodNotAmplified(t *testing.T) {
	srv := newTestServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	var read, written atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.HandleSSHConnection(countedConn{conn, &read, &written})
		}
	}()
	tt := openTunnel(t, srv, ln.Addr().String(), anonymousClient(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "still here")
	}))

	// Twice the session's window, so half of it has been read, not just
	// buffered, by the time all of it has arrived
	const flood = 4 << 20
	read0, written0 := read.Load(), written.Load()
	if _, err := tt.stdin.Write(make([]byte, flood)); err != nil {
		t.Fatalf("writing to the session: %v", err)
	}
	waitFor(t, "the server to receive the flood", func() bool { return read.Load()-read0 >= flood })
	// Against the input itself, not the bytes received: a client held to a
	// byte of window at a time sends a packet per byte too
	out := written.Load() - written0
	t.Logf("server sent %d B for %d B of session input (%d B received): %.4f out per byte in", out, flood, read.Load()-read0, float64(out)/flood)
	if out > flood/10 {
		t.Errorf("server sent %d B in answer to %d B of session input, want under 10%%", out, flood)
	}

	resp := tt.get(t, "/")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "still here" {
		t.Fatalf("after the flood: %d %q, want 200 %q", resp.StatusCode, body, "still here")
	}
}

// TestE2E_CtrlCAmongOtherInput covers a Ctrl+C that arrives in one read with
// other keys.
func TestE2E_CtrlCAmongOtherInput(t *testing.T) {
	tt := startTestTunnel(t, http.NotFoundHandler())
	if _, err := tt.stdin.Write([]byte("abc\x03def")); err != nil {
		t.Fatalf("writing to the session: %v", err)
	}
	waitFor(t, "the session to stop", func() bool { return strings.Contains(tt.sessionText(), "Stopped.") })
	if err := tt.client.Wait(); err == nil {
		t.Error("client.Wait() = nil, want the connection closed by the server")
	}
}

// TestE2E_PipedCtrlCByteKeepsTunnel covers ssh without a terminal, where the
// input is piped data: a 0x03 in it isn't the user pressing Ctrl+C.
func TestE2E_PipedCtrlCByteKeepsTunnel(t *testing.T) {
	_, addr := startSSHServer(t)
	client, err := dialSSH(addr)
	if err != nil {
		t.Fatalf("ssh.Dial() error: %v", err)
	}
	defer client.Close()
	if _, err := client.Listen("tcp", "0.0.0.0:80"); err != nil {
		t.Fatalf("client.Listen() error: %v", err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	if err := session.Shell(); err != nil { // no RequestPty: like ssh -T
		t.Fatalf("Shell() error: %v", err)
	}
	output := &syncBuffer{}
	go io.Copy(output, stdout)
	waitFor(t, "tunnel banner", func() bool { return publicURLPattern.MatchString(output.String()) })

	if _, err := stdin.Write([]byte("data\x03data")); err != nil {
		t.Fatalf("writing to the session: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
		t.Fatalf("connection closed after a piped 0x03: %v", err)
	}
	if strings.Contains(output.String(), "Stopped") {
		t.Errorf("session stopped by a piped 0x03:\n%s", output.String())
	}
}
