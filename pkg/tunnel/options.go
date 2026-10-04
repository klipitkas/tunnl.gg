package tunnel

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/klipitkas/tunnl.gg/pkg/config"
)

// Options are what a client asks for in the ssh command, after the host:
//
//	ssh -t -R 80:localhost:8080 proxy.tunnl.gg host=localhost auth=me:secret
type Options struct {
	Host  string         // sent to the app as the Host header instead of the public host, if set
	Auth  *BasicAuth     // visitors must sign in with these credentials, if set
	Allow []netip.Prefix // only visitors from these networks get through, if set
}

// BasicAuth is a user name and password visitors must send with HTTP basic
// authentication. Only a hash of them is kept.
type BasicAuth struct {
	User   string
	hash   [sha256.Size]byte
	verify func(password string) bool // checks the password instead of hash, if set
}

// NewBasicAuth returns credentials whose password verify checks, for
// passwords stored hashed elsewhere. verify runs for every request that
// sends user, so it should cache what it can.
func NewBasicAuth(user string, verify func(password string) bool) *BasicAuth {
	return &BasicAuth{User: user, verify: verify}
}

// Limits on option values, so a client can't make the server hold much.
const (
	maxAuthLength   = 128
	maxAllowEntries = 64
	maxHostLength   = 253 + 6 // a host name and a port
)

var hostPattern = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?$`)

// OptionsUsage describes the options, for errors and "help".
const OptionsUsage = `Options go after the host, as name=value:
  host=localhost:3000    send this Host header to your app instead of the public one
                         (for dev servers that block unknown hosts, like Vite)
  auth=user:password     visitors must sign in with this user name and password
  allow=203.0.113.7,198.51.100.0/24
                         only visitors from these IPs or networks get through
For example: ssh -t -R 80:localhost:8080 proxy.tunnl.gg host=localhost auth=me:secret`

// ErrHelp is returned by ParseOptions for "help".
var ErrHelp = errors.New("help")

// ParseOptions parses the command of an ssh exec request: options separated
// by spaces, each name=value. Repeating allow= adds to the list.
func ParseOptions(command string) (Options, error) {
	var opts Options
	seen := map[string]bool{}
	for _, field := range strings.Fields(command) {
		if field == "help" || field == "--help" || field == "-h" {
			return Options{}, ErrHelp
		}
		name, value, ok := strings.Cut(field, "=")
		if !ok || value == "" {
			return Options{}, fmt.Errorf("%q isn't an option: options are name=value", field)
		}
		name = strings.ToLower(name)
		if seen[name] && name != config.OptionAllow {
			return Options{}, fmt.Errorf("%s= is given twice", name)
		}
		seen[name] = true
		switch name {
		case config.OptionHost:
			if len(value) > maxHostLength || !hostPattern.MatchString(value) {
				return Options{}, fmt.Errorf("host=%s isn't a host name, like localhost or localhost:3000", value)
			}
			opts.Host = value
		case config.OptionAuth:
			user, pass, ok := strings.Cut(value, ":")
			if !ok || user == "" || pass == "" {
				return Options{}, errors.New("auth= needs a user name and a password, like auth=me:secret")
			}
			if len(value) > maxAuthLength {
				return Options{}, fmt.Errorf("auth= is too long: at most %d characters", maxAuthLength)
			}
			opts.Auth = &BasicAuth{User: user, hash: sha256.Sum256([]byte(value))}
		case config.OptionAllow:
			for _, entry := range strings.Split(value, ",") {
				prefix, err := parseAllowEntry(entry)
				if err != nil {
					return Options{}, err
				}
				opts.Allow = append(opts.Allow, prefix)
			}
			if len(opts.Allow) > maxAllowEntries {
				return Options{}, fmt.Errorf("allow= takes at most %d entries", maxAllowEntries)
			}
		default:
			return Options{}, fmt.Errorf("there's no %s= option", name)
		}
	}
	return opts, nil
}

func parseAllowEntry(entry string) (netip.Prefix, error) {
	if entry == "" {
		return netip.Prefix{}, errors.New("allow= has an empty entry: separate IPs with single commas")
	}
	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("allow=%s isn't a network, like 198.51.100.0/24", entry)
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("allow=%s isn't an IP address", entry)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// With returns o with the options set in override replacing its own.
func (o Options) With(override Options) Options {
	if override.Host != "" {
		o.Host = override.Host
	}
	if override.Auth != nil {
		o.Auth = override.Auth
	}
	if len(override.Allow) > 0 {
		o.Allow = override.Allow
	}
	return o
}

// Names returns the names of the options that are set.
func (o Options) Names() []string {
	var names []string
	if o.Host != "" {
		names = append(names, config.OptionHost)
	}
	if o.Auth != nil {
		names = append(names, config.OptionAuth)
	}
	if len(o.Allow) > 0 {
		names = append(names, config.OptionAllow)
	}
	return names
}

// Allows reports whether a visitor from addr may reach the tunnel.
func (o Options) Allows(addr netip.Addr) bool {
	if len(o.Allow) == 0 {
		return true
	}
	addr = addr.Unmap()
	for _, p := range o.Allow {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Check reports whether r carries the credentials.
func (a *BasicAuth) Check(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	if a.verify != nil {
		return subtle.ConstantTimeCompare([]byte(user), []byte(a.User)) == 1 && a.verify(pass)
	}
	sum := sha256.Sum256([]byte(user + ":" + pass))
	return subtle.ConstantTimeCompare(sum[:], a.hash[:]) == 1
}
