package tunnel

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseOptions(t *testing.T) {
	opts, err := ParseOptions("  host=localhost:5173 auth=me:pa:ss allow=203.0.113.7,198.51.100.0/24 allow=2001:db8::/32 ")
	if err != nil {
		t.Fatal(err)
	}
	if opts.Host != "localhost:5173" || opts.Auth == nil || opts.Auth.User != "me" || len(opts.Allow) != 3 {
		t.Fatalf("opts = %+v", opts)
	}
	if got := strings.Join(opts.Names(), ","); got != "host,auth,allow" {
		t.Errorf("Names() = %s", got)
	}
	if opts, err := ParseOptions(""); err != nil || len(opts.Names()) != 0 {
		t.Errorf("no options: %+v, %v", opts, err)
	}
	if _, err := ParseOptions("auth=x:y help"); !errors.Is(err, ErrHelp) {
		t.Errorf("help: %v", err)
	}

	for _, bad := range []string{
		"bogus",
		"color=red",
		"host=",
		"host=evil.com/path",
		"host=a b",
		"host=-x",
		"host=x host=y",
		"auth=nopassword",
		"auth=:pass",
		"auth=me:",
		"auth=me:" + strings.Repeat("x", 200),
		"allow=1.2.3",
		"allow=1.2.3.4,,5.6.7.8",
		"allow=10.0.0.0/33",
		"allow=" + strings.Repeat("10.0.0.1,", 64) + "10.0.0.2",
	} {
		if _, err := ParseOptions(bad); err == nil {
			t.Errorf("ParseOptions(%q) should fail", bad)
		}
	}
	for _, ok := range []string{"host=localhost", "host=127.0.0.1:8080", "host=[::1]:3000", "host=my-app.test", "HOST=x"} {
		if _, err := ParseOptions(ok); err != nil {
			t.Errorf("ParseOptions(%q): %v", ok, err)
		}
	}
}

func TestOptionsAllows(t *testing.T) {
	opts, _ := ParseOptions("allow=203.0.113.7,198.51.100.0/24,2001:db8::/32")
	for addr, want := range map[string]bool{
		"203.0.113.7":        true,
		"203.0.113.8":        false,
		"198.51.100.200":     true,
		"::ffff:203.0.113.7": true, // IPv4 seen as IPv6
		"2001:db8:1::1":      true,
		"2001:db9::1":        false,
	} {
		if got := opts.Allows(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Allows(%s) = %v, want %v", addr, got, want)
		}
	}
	if !(Options{}).Allows(netip.MustParseAddr("192.0.2.1")) {
		t.Error("without allow=, everyone gets through")
	}
}

func TestBasicAuthCheck(t *testing.T) {
	opts, _ := ParseOptions("auth=me:pa:ss")
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	if opts.Auth.Check(r) {
		t.Error("no credentials accepted")
	}
	r.SetBasicAuth("me", "wrong")
	if opts.Auth.Check(r) {
		t.Error("wrong password accepted")
	}
	r.SetBasicAuth("you", "pa:ss")
	if opts.Auth.Check(r) {
		t.Error("wrong user accepted")
	}
	r.SetBasicAuth("me", "pa:ss")
	if !opts.Auth.Check(r) {
		t.Error("right credentials refused")
	}
}

func TestRequestsWaitForOptions(t *testing.T) {
	// Without AwaitOptions, nothing waits
	if _, ok := New("a", nil, "", 80, "").Options(context.Background()); !ok {
		t.Error("a tunnel that doesn't await options should serve")
	}

	tun := New("b", nil, "", 80, "")
	tun.AwaitOptions()
	got := make(chan Options)
	go func() {
		opts, ok := tun.Options(context.Background())
		if ok {
			got <- opts
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("a request went through before the options were set")
	case <-time.After(50 * time.Millisecond):
	}
	opts, _ := ParseOptions("host=localhost")
	tun.SetOptions(opts)
	if o := <-got; o.Host != "localhost" {
		t.Errorf("options = %+v", o)
	}

	// Closing without options refuses waiting requests
	tun = New("c", nil, "", 80, "")
	tun.AwaitOptions()
	go func() { time.Sleep(20 * time.Millisecond); tun.Close() }()
	if _, ok := tun.Options(context.Background()); ok {
		t.Error("a request went through a tunnel that closed without options")
	}

	// So does a timeout
	tun = New("d", nil, "", 80, "")
	tun.AwaitOptions()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, ok := tun.Options(ctx); ok {
		t.Error("a request went through after its wait timed out")
	}
}

func TestOptionsWith(t *testing.T) {
	base, _ := ParseOptions("host=base.test auth=me:base allow=192.0.2.1")
	cmd, _ := ParseOptions("host=cmd.test")
	got := base.With(cmd)
	if got.Host != "cmd.test" || got.Auth != base.Auth || len(got.Allow) != 1 {
		t.Errorf("With() = %+v", got)
	}
	if got := (Options{}).With(Options{}); len(got.Names()) != 0 {
		t.Errorf("empty With() = %+v", got)
	}
}

func TestNewBasicAuth(t *testing.T) {
	a := NewBasicAuth("me", func(p string) bool { return p == "right" })
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	for user, pass := range map[string]string{"me": "wrong", "you": "right"} {
		r.SetBasicAuth(user, pass)
		if a.Check(r) {
			t.Errorf("%s:%s accepted", user, pass)
		}
	}
	r.SetBasicAuth("me", "right")
	if !a.Check(r) {
		t.Error("the right password was refused")
	}
}

func TestParseCORS(t *testing.T) {
	opts, err := ParseOptions("cors=https://App.example.com,http://localhost:5173/ cors=https://app.example.com")
	if err != nil || strings.Join(opts.CORS, " ") != "https://app.example.com http://localhost:5173" {
		t.Fatalf("CORS = %v, %v", opts.CORS, err)
	}
	if allow, creds := opts.CORSOrigin("https://app.example.com"); allow != "https://app.example.com" || !creds {
		t.Errorf("listed origin: %q %v", allow, creds)
	}
	if allow, _ := opts.CORSOrigin("https://evil.example"); allow != "" {
		t.Errorf("unlisted origin allowed: %q", allow)
	}
	any, _ := ParseOptions("cors=*")
	if allow, creds := any.CORSOrigin("https://anything.example"); allow != "*" || creds {
		t.Errorf("cors=*: %q %v; credentials must never come with *", allow, creds)
	}
	if allow, _ := any.CORSOrigin(""); allow != "" {
		t.Error("requests without an Origin get no CORS headers")
	}
	for _, bad := range []string{"cors=example.com", "cors=ftp://x.example", "cors=https://x.example/path", "cors=https://u:p@x.example", "cors=*,https://x.example"} {
		if _, err := ParseOptions(bad); err == nil {
			t.Errorf("ParseOptions(%q) should fail", bad)
		}
	}
}
