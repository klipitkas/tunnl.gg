package server

import (
	"math/rand/v2"
	"net/netip"
	"testing"
)

func TestVisitorKeyFormattingCompatibility(t *testing.T) {
	check := func(addr netip.Addr) {
		t.Helper()
		unmapped := addr.Unmap()
		want := unmapped.String()
		if unmapped.Is6() && unmapped.Zone() == "" {
			want = netip.PrefixFrom(unmapped, 64).Masked().String()
		}
		if got := visitorKeyAddr(addr); got != want {
			t.Fatalf("%v: key %q, want %q", addr, got, want)
		}
	}
	check(netip.Addr{})
	for _, input := range []string{"0.0.0.0", "255.255.255.255", "::", "::1", "::ffff:192.0.2.1", "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe80::1%eth0"} {
		check(netip.MustParseAddr(input))
	}
	rng := rand.New(rand.NewPCG(123, 456))
	for range 1000 {
		var raw [16]byte
		for i := range raw {
			raw[i] = byte(rng.Uint32())
		}
		addr := netip.AddrFrom16(raw)
		check(addr)
		check(addr.WithZone("eth0"))
		check(netip.AddrFrom4([4]byte(raw[:4])))
		key := visitorKeyAddr(addr)
		// Rotating the host bits must not create another rate-limit bucket.
		for i := 8; i < len(raw); i++ {
			raw[i] ^= 0xff
		}
		if visitorKeyAddr(netip.AddrFrom16(raw)) != key {
			t.Fatal("host bits changed the /64 key")
		}
		// Crossing the /64 boundary must create a different bucket.
		raw[7] ^= 1
		if visitorKeyAddr(netip.AddrFrom16(raw)) == key {
			t.Fatal("different /64 prefixes shared a key")
		}
	}
}

var visitorKeySink string

func BenchmarkVisitorKeyFormatting(b *testing.B) {
	for _, tc := range []struct{ name, input string }{
		{"IPv6", "2001:db8:1234:5678::1"},
		{"IPv6Zero", "::1"},
		{"IPv4", "198.51.100.1"},
		{"MappedIPv4", "::ffff:198.51.100.1"},
		{"ZonedIPv6", "fe80::1%eth0"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			addr := netip.MustParseAddr(tc.input)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				visitorKeySink = visitorKeyAddr(addr)
			}
		})
	}
}
