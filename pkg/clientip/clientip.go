// Package clientip resolves the address of the visitor behind a request,
// trusting forwarding headers only when they come from configured proxies.
package clientip

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// Cloudflare is the keyword that trusts Cloudflare's edge ranges.
const Cloudflare = "cloudflare"

// CloudflareRanges are Cloudflare's published edge IP ranges, from
// https://www.cloudflare.com/ips/ (retrieved 2026-09-26). Cloudflare rarely
// changes them; list current ranges explicitly in TRUSTED_PROXIES if it does.
var CloudflareRanges = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// Resolver finds the visitor's address for a request. The zero value, and a
// nil *Resolver, trust no proxies: the visitor is always the TCP peer.
type Resolver struct {
	cloudflare []netip.Prefix // peers whose CF-Connecting-IP header is trusted
	proxies    []netip.Prefix // peers whose X-Forwarded-For header is trusted
}

// Parse builds a Resolver from a comma-separated list of trusted proxies:
// CIDRs or IPs of reverse proxies that set X-Forwarded-For, and the keyword
// "cloudflare" for Cloudflare's edge, which sets CF-Connecting-IP. An empty
// spec trusts no proxies, for servers that face the internet directly.
func Parse(spec string) (*Resolver, error) {
	r := &Resolver{}
	for item := range strings.SplitSeq(spec, ",") {
		item = strings.TrimSpace(item)
		switch {
		case item == "":
			continue
		case strings.EqualFold(item, Cloudflare):
			for _, cidr := range CloudflareRanges {
				r.cloudflare = append(r.cloudflare, netip.MustParsePrefix(cidr))
			}
		default:
			prefix, err := parsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy %q: %w", item, err)
			}
			r.proxies = append(r.proxies, prefix)
		}
	}
	return r, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		return prefix.Masked(), err
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// Result is the resolved visitor for a request.
type Result struct {
	// Addr is the visitor's IP address. It is invalid only if the peer address
	// could not be parsed, which does not happen for real network connections.
	Addr netip.Addr
	// ViaCloudflare reports whether Addr came from a trusted CF-Connecting-IP
	// header, meaning the request arrived directly from Cloudflare.
	ViaCloudflare bool
}

// Resolve returns the visitor for a request from peer remoteAddr ("ip:port")
// with headers h. Forwarding headers are only used when the peer is trusted.
func (r *Resolver) Resolve(remoteAddr string, h http.Header) Result {
	peer := parseAddr(remoteAddr)
	if r == nil || !peer.IsValid() {
		return Result{Addr: peer}
	}

	if contains(r.cloudflare, peer) {
		if addr := parseAddr(h.Get("CF-Connecting-IP")); addr.IsValid() {
			return Result{Addr: addr, ViaCloudflare: true}
		}
		return Result{Addr: peer}
	}

	if contains(r.proxies, peer) {
		return Result{Addr: r.fromForwardedFor(peer, h)}
	}
	return Result{Addr: peer}
}

// fromForwardedFor walks X-Forwarded-For from the right, skipping trusted
// proxies, and returns the first untrusted address: entries further left were
// written by the visitor and can't be trusted.
func (r *Resolver) fromForwardedFor(peer netip.Addr, h http.Header) netip.Addr {
	var hops []string
	for _, value := range h.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(value, ",")...)
	}

	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		addr := parseAddr(strings.TrimSpace(hops[i]))
		if !addr.IsValid() {
			// Malformed entry: nothing to its left can be trusted either
			return client
		}
		client = addr
		if !contains(r.proxies, addr) && !contains(r.cloudflare, addr) {
			return addr
		}
	}
	return client
}

// parseAddr parses "ip", "ip:port", or "[ipv6]:port", unmapping IPv4-in-IPv6.
func parseAddr(s string) netip.Addr {
	if addrPort, err := netip.ParseAddrPort(s); err == nil {
		return addrPort.Addr().Unmap()
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
