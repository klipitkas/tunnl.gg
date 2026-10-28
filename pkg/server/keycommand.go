package server

import (
	"log"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/config"
)

// KeyCommand answers a client that connects as the command's SSH user with a
// key, instead of opening a tunnel. Connecting proves the client holds the
// private key, so a hosted deployment can use it, for example, to link the
// key to an account without asking for a signature. It gets the key and
// returns the text to show the client; it runs during the connection, so it
// should be quick.
type KeyCommand func(key ssh.PublicKey) (string, error)

// keyCommandKey is the ssh.Permissions.ExtraData key holding the key that a
// command's client authenticated with.
type keyCommandKey struct{}

// SetKeyCommand makes clients that connect as user, with a key, run cmd
// instead of opening a tunnel. Clients without a key are refused, so theirs
// fall back to offering their keys. Call it before serving. The user can't be
// the stable or account user.
func (s *Server) SetKeyCommand(user string, cmd KeyCommand) {
	if user == "" || user == config.StableSSHUser || user == config.AccountSSHUser {
		panic("server: SetKeyCommand needs a user of its own, not " + strconv.Quote(user))
	}
	if s.keyCommands == nil {
		s.keyCommands = make(map[string]KeyCommand)
	}
	s.keyCommands[user] = cmd
}

// authKeyCommand accepts any key offered by a command's user, keeping it for
// the command. x/crypto/ssh only grants these permissions once the client has
// proven it holds the private key.
func authKeyCommand(key ssh.PublicKey) *ssh.Permissions {
	return &ssh.Permissions{ExtraData: map[any]any{keyCommandKey{}: key}}
}

// commandKey returns the key conn authenticated with if it connected as a
// command's user, or nil.
func commandKey(conn *ssh.ServerConn) ssh.PublicKey {
	if conn.Permissions == nil {
		return nil
	}
	key, _ := conn.Permissions.ExtraData[keyCommandKey{}].(ssh.PublicKey)
	return key
}

// runKeyCommand runs the command of conn's user with key and shows the client
// what it returns. Each run counts against the IP's connection rate, like a
// tunnel, so the command can't be used to flood whatever it calls.
func (s *Server) runKeyCommand(conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, clientIP string, key ssh.PublicKey) {
	go ssh.DiscardRequests(reqs) // including any port forwarding asked for
	user := conn.User()
	if !s.abuseTracker.CheckConnectionRate(clientIP) {
		log.Printf("Connection rejected from %s: %v (%s user)", clientIP, errConnectionRate, user)
		s.sendErrorAndClose(conn, chans, errConnectionRate.Error())
		return
	}
	text, err := s.keyCommands[user](key)
	if err != nil {
		log.Printf("The %s command failed for %s: %v", user, clientIP, err)
		s.sendErrorAndClose(conn, chans, "something went wrong on our side. Try again in a moment")
		return
	}
	log.Printf("Ran the %s command for %s with key %s", user, clientIP, ssh.FingerprintSHA256(key))
	s.sendAndClose(conn, chans, "\r\n"+strings.ReplaceAll(strings.TrimRight(text, "\n"), "\n", "\r\n")+"\r\n\r\n", 0)
}
