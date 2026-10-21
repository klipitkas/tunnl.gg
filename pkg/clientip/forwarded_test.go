package clientip

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

// Keep the original split-and-flatten walk as a compatibility oracle.
func referenceForwardedFor(r *Resolver, peer netip.Addr, h http.Header) netip.Addr {
	var hops []string
	for _, value := range h.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(value, ",")...)
	}
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		addr := parseAddr(strings.TrimSpace(hops[i]))
		if !addr.IsValid() {
			return client
		}
		client = addr
		if !contains(r.proxies, addr) && !contains(r.cloudflare, addr) {
			return addr
		}
	}
	return client
}

func FuzzForwardedForCompatibility(f *testing.F) {
	for _, seed := range []string{
		"", ",", "198.51.100.9,", ",10.0.0.7", "junk,10.0.0.7",
		"junk,198.51.100.9,10.0.0.7", "198.51.100.9\n10.0.0.7",
		"198.51.100.9\n\n10.0.0.7", "198.51.100.9\n10.0.0.7,10.0.0.8",
		"10.0.0.6,10.0.0.7", "[2001:db8::1]:443,173.245.48.10",
		"\t::ffff:198.51.100.9\u2003, 10.0.0.7", "fe80::1%eth0,10.0.0.7",
	} {
		f.Add(seed)
	}
	r, err := Parse("10.0.0.0/8,cloudflare")
	if err != nil {
		f.Fatal(err)
	}
	peer := netip.MustParseAddr("10.0.0.5")
	f.Fuzz(func(t *testing.T, input string) {
		h := http.Header{"X-Forwarded-For": strings.Split(input, "\n")}
		if got, want := r.fromForwardedFor(peer, h), referenceForwardedFor(r, peer, h); got != want {
			t.Fatalf("headers %q: got %v, want %v", h.Values("X-Forwarded-For"), got, want)
		}
	})
}

var resolvedVisitorSink Result

func BenchmarkForwardedFor(b *testing.B) {
	r, err := Parse("10.0.0.0/8,cloudflare")
	if err != nil {
		b.Fatal(err)
	}
	for _, tc := range []struct {
		name, peer, want string
		values           []string
	}{
		{"Single", "10.0.0.5:443", "198.51.100.9", []string{"198.51.100.9"}},
		{"Chain", "10.0.0.5:443", "198.51.100.9", []string{"198.51.100.9, 10.0.0.7, 10.0.0.8"}},
		{"MultipleHeaders", "10.0.0.5:443", "198.51.100.9", []string{"spoofed", "198.51.100.9, 10.0.0.7", "10.0.0.8"}},
		{"UnusedPrefix1024", "10.0.0.5:443", "198.51.100.9", []string{strings.Repeat("1.2.3.4,", 1024) + "198.51.100.9, 10.0.0.7"}},
		{"AllTrusted32", "10.0.0.5:443", "10.0.0.7", []string{strings.Repeat("10.0.0.7,", 31) + "10.0.0.7"}},
		{"Malformed", "10.0.0.5:443", "10.0.0.7", []string{"198.51.100.9, junk, 10.0.0.7"}},
		{"UntrustedPeer", "203.0.113.1:443", "203.0.113.1", []string{"198.51.100.9, 10.0.0.7"}},
		{"Cloudflare", "173.245.48.10:443", "198.51.100.9", []string{"198.51.100.9, 10.0.0.7"}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			h := http.Header{"X-Forwarded-For": tc.values, "Cf-Connecting-Ip": {"198.51.100.9"}}
			want := netip.MustParseAddr(tc.want)
			if got := r.Resolve(tc.peer, h); got.Addr != want {
				b.Fatalf("got %v, want %v", got.Addr, want)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				resolvedVisitorSink = r.Resolve(tc.peer, h)
			}
		})
	}
}
