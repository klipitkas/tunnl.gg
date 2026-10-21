package clientip

import (
	"net/netip"
	"testing"
)

func referenceParseAddr(s string) netip.Addr {
	if addrPort, err := netip.ParseAddrPort(s); err == nil {
		return addrPort.Addr().Unmap()
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func FuzzParseAddrCompatibility(f *testing.F) {
	for _, seed := range []string{
		"", "junk", "192.0.2.1", "192.0.2.1:0", "192.0.2.1:65535",
		"192.0.2.1:65536", "192.0.2.1:-1", "192.0.2.1:+1", "192.0.2.1:",
		"192.0.2.1:01", "192.0.2.01", "[192.0.2.1]:80", "192.0.2.1%eth0",
		"::", "::1", "2001:db8::1234", "[2001:db8::1]:443", "[::1]",
		"[::1]:invalid", "::ffff:192.0.2.1", "[::ffff:192.0.2.1]:443",
		"fe80::1%eth0", "fe80::1%eth0:443", "fe80::1%eth[0]:443",
		"[fe80::1%eth0]:443", "fe80::1%", "fe80::1%eth0\x00", "::1:65536",
		"a:b", ":1", "[", " 192.0.2.1", "192.0.2.1\n", "[::1]:+443",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if got, want := parseAddr(input), referenceParseAddr(input); got != want {
			t.Fatalf("%q: got %v, want %v", input, got, want)
		}
	})
}

var parsedAddrSink netip.Addr

func BenchmarkParseAddr(b *testing.B) {
	for _, tc := range []struct{ name, input string }{
		{"IPv4", "198.51.100.9"},
		{"IPv6", "2001:db8::9"},
		{"MappedIPv4", "::ffff:198.51.100.9"},
		{"ZonedIPv6", "fe80::1%eth0"},
		{"IPv4Port", "198.51.100.9:443"},
		{"IPv6Port", "[2001:db8::9]:443"},
		{"Malformed", "not-an-ip"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			if got, want := parseAddr(tc.input), referenceParseAddr(tc.input); got != want {
				b.Fatalf("got %v, want %v", got, want)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				parsedAddrSink = parseAddr(tc.input)
			}
		})
	}
}
