package clientip

import (
	"net/http"
	"net/netip"
	"testing"
)

func TestResolve(t *testing.T) {
	const (
		cfEdge  = "173.245.48.10:443" // inside Cloudflare's ranges
		cfEdge6 = "[2606:4700::1]:443"
		nginx   = "10.0.0.5:51000"
		visitor = "203.0.113.7:4321"
	)

	tests := []struct {
		name       string
		spec       string
		remoteAddr string
		headers    map[string]string
		want       string
		wantCF     bool
	}{
		// Direct deployments (on-prem, no proxy): headers are never trusted
		{"direct", "", visitor, nil, "203.0.113.7", false},
		{"direct ignores spoofed CF header", "", visitor, map[string]string{"CF-Connecting-IP": "1.2.3.4"}, "203.0.113.7", false},
		{"direct ignores spoofed XFF", "", visitor, map[string]string{"X-Forwarded-For": "1.2.3.4"}, "203.0.113.7", false},
		{"ipv4-mapped peer", "", "[::ffff:203.0.113.7]:4321", nil, "203.0.113.7", false},

		// Cloudflare
		{"cloudflare edge", "cloudflare", cfEdge, map[string]string{"CF-Connecting-IP": "198.51.100.9"}, "198.51.100.9", true},
		{"cloudflare ipv6 edge", "cloudflare", cfEdge6, map[string]string{"CF-Connecting-IP": "2001:db8::9"}, "2001:db8::9", true},
		{"cloudflare edge without header", "cloudflare", cfEdge, nil, "173.245.48.10", false},
		{"cloudflare edge with garbage header", "cloudflare", cfEdge, map[string]string{"CF-Connecting-IP": "not-an-ip"}, "173.245.48.10", false},
		{"direct to origin bypassing cloudflare", "cloudflare", visitor, map[string]string{"CF-Connecting-IP": "1.2.3.4"}, "203.0.113.7", false},
		{"cloudflare does not trust XFF", "cloudflare", cfEdge, map[string]string{"X-Forwarded-For": "1.2.3.4"}, "173.245.48.10", false},

		// On-prem reverse proxies setting X-Forwarded-For
		{"trusted proxy", "10.0.0.0/8", nginx, map[string]string{"X-Forwarded-For": "198.51.100.9"}, "198.51.100.9", false},
		{"trusted proxy single IP", "10.0.0.5", nginx, map[string]string{"X-Forwarded-For": "198.51.100.9"}, "198.51.100.9", false},
		{"spoofed entries left of the real client", "10.0.0.0/8", nginx, map[string]string{"X-Forwarded-For": "1.2.3.4, 198.51.100.9"}, "198.51.100.9", false},
		{"chain of trusted proxies", "10.0.0.0/8", nginx, map[string]string{"X-Forwarded-For": "198.51.100.9, 10.0.0.7"}, "198.51.100.9", false},
		{"proxy behind cloudflare", "cloudflare,10.0.0.0/8", nginx, map[string]string{"X-Forwarded-For": "198.51.100.9, 173.245.48.10"}, "198.51.100.9", false},
		{"trusted proxy without header", "10.0.0.0/8", nginx, nil, "10.0.0.5", false},
		{"malformed entry stops the walk", "10.0.0.0/8", nginx, map[string]string{"X-Forwarded-For": "198.51.100.9, junk"}, "10.0.0.5", false},
		{"untrusted peer ignores XFF", "10.0.0.0/8", visitor, map[string]string{"X-Forwarded-For": "1.2.3.4"}, "203.0.113.7", false},
		{"proxy does not trust CF header", "10.0.0.0/8", nginx, map[string]string{"CF-Connecting-IP": "1.2.3.4"}, "10.0.0.5", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Parse(tt.spec)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.spec, err)
			}
			h := http.Header{}
			for k, v := range tt.headers {
				h.Set(k, v)
			}
			got := r.Resolve(tt.remoteAddr, h)
			if got.Addr != netip.MustParseAddr(tt.want) || got.ViaCloudflare != tt.wantCF {
				t.Errorf("Resolve() = %v (cloudflare=%v), want %s (cloudflare=%v)", got.Addr, got.ViaCloudflare, tt.want, tt.wantCF)
			}
		})
	}
}

func TestResolve_MultipleForwardedForHeaders(t *testing.T) {
	r, _ := Parse("10.0.0.0/8")
	h := http.Header{}
	h.Add("X-Forwarded-For", "1.2.3.4")
	h.Add("X-Forwarded-For", "198.51.100.9")

	if got := r.Resolve("10.0.0.5:1", h).Addr; got != netip.MustParseAddr("198.51.100.9") {
		t.Errorf("Resolve() = %v, want the rightmost untrusted entry across headers", got)
	}
}

func TestResolve_NilResolverTrustsNobody(t *testing.T) {
	var r *Resolver
	h := http.Header{}
	h.Set("CF-Connecting-IP", "1.2.3.4")

	if got := r.Resolve("203.0.113.7:1", h).Addr; got != netip.MustParseAddr("203.0.113.7") {
		t.Errorf("Resolve() = %v, want the peer", got)
	}
}

func TestParse_Invalid(t *testing.T) {
	for _, spec := range []string{"not-a-cidr", "10.0.0.0/33", "cloudflare,bogus"} {
		if _, err := Parse(spec); err == nil {
			t.Errorf("Parse(%q) should fail", spec)
		}
	}
}
