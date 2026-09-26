package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// pipeChannel is an ssh.Channel backed by one end of a net.Pipe.
type pipeChannel struct {
	net.Conn
}

func (c *pipeChannel) CloseWrite() error                              { return nil }
func (c *pipeChannel) SendRequest(string, bool, []byte) (bool, error) { return false, nil }
func (c *pipeChannel) Stderr() io.ReadWriter                          { return nil }

// fakeOpener records channel open requests and answers them with pipes.
type fakeOpener struct {
	mu      sync.Mutex
	name    string
	payload []byte
	remote  net.Conn      // client end of the last opened channel
	release chan struct{} // if set, OpenChannel waits for it
}

func (o *fakeOpener) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	if o.release != nil {
		<-o.release
	}
	local, remote := net.Pipe()
	o.mu.Lock()
	o.name, o.payload, o.remote = name, data, remote
	o.mu.Unlock()
	reqs := make(chan *ssh.Request)
	close(reqs)
	return &pipeChannel{Conn: local}, reqs, nil
}

func TestDial_OpensForwardedChannel(t *testing.T) {
	opener := &fakeOpener{}
	tun := New("happy-tiger-00000001", opener, "localhost", 8080, "192.0.2.1")

	conn, err := tun.Dial(WithOrigin(context.Background(), "198.51.100.7:4321"))
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()

	if opener.name != "forwarded-tcpip" {
		t.Errorf("channel type = %q, want forwarded-tcpip", opener.name)
	}
	var payload forwardedTCPPayload
	if err := ssh.Unmarshal(opener.payload, &payload); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	if payload.Addr != "localhost" || payload.Port != 8080 {
		t.Errorf("forwarded to %s:%d, want the client's bind address localhost:8080", payload.Addr, payload.Port)
	}
	if payload.OriginAddr != "198.51.100.7" || payload.OriginPort != 4321 {
		t.Errorf("origin = %s:%d, want the visitor 198.51.100.7:4321", payload.OriginAddr, payload.OriginPort)
	}

	go opener.remote.Write([]byte("hi"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hi" {
		t.Errorf("read through channel = %q, %v; want %q", buf, err, "hi")
	}
}

func TestDial_GivesUpWhenContextDone(t *testing.T) {
	opener := &fakeOpener{release: make(chan struct{})}
	tun := New("happy-tiger-00000001", opener, "localhost", 8080, "192.0.2.1")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := tun.Dial(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial() error = %v, want context deadline exceeded", err)
	}

	// The client accepts the channel after we gave up; it must be closed
	close(opener.release)
	waitForRemote := time.Now().Add(2 * time.Second)
	for {
		opener.mu.Lock()
		remote := opener.remote
		opener.mu.Unlock()
		if remote != nil {
			remote.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := remote.Read(make([]byte, 1)); err != io.EOF {
				t.Errorf("late channel read error = %v, want EOF (channel closed)", err)
			}
			return
		}
		if time.Now().After(waitForRemote) {
			t.Fatal("OpenChannel was never called")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestChannelConn_ReadDeadlineClosesChannel(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	conn := newChannelConn(&pipeChannel{Conn: local}, "happy-tiger-00000001")

	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Read() should fail once the deadline closes the channel")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read() blocked past its deadline")
	}
}

func TestChannelConn_ClearedDeadlineDoesNotClose(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	conn := newChannelConn(&pipeChannel{Conn: local}, "happy-tiger-00000001")
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(50 * time.Millisecond))
	conn.SetDeadline(time.Time{})
	time.Sleep(100 * time.Millisecond)

	go remote.Write([]byte("x"))
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		t.Errorf("Read() after clearing the deadline: %v", err)
	}
}

func TestOrigin(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		wantAddr string
		wantPort uint32
	}{
		{"ipv4", "198.51.100.7:4321", "198.51.100.7", 4321},
		{"ipv6", "[2001:db8::1]:443", "2001:db8::1", 443},
		{"port 0 is rejected by clients", "198.51.100.7:0", "127.0.0.1", 1},
		{"not host:port", "garbage", "127.0.0.1", 1},
		{"missing", "", "127.0.0.1", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.addr != "" {
				ctx = WithOrigin(ctx, tt.addr)
			}
			addr, port := origin(ctx)
			if addr != tt.wantAddr || port != tt.wantPort {
				t.Errorf("origin(%q) = %s:%d, want %s:%d", tt.addr, addr, port, tt.wantAddr, tt.wantPort)
			}
		})
	}
}
