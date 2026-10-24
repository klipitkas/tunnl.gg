package server

import (
	"log"
	"sync"
	"time"

	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

// transferMeter counts the bytes each tunnel owner sends through its tunnels
// in the current UTC day, for Limits.DailyTransfer. Counts live in memory,
// so a restart starts the day over.
type transferMeter struct {
	mu    sync.Mutex
	day   int64 // days since the epoch, UTC
	bytes map[string]int64
	now   func() time.Time // for tests
}

func newTransferMeter() *transferMeter {
	return &transferMeter{bytes: map[string]int64{}, now: time.Now}
}

// today starts the counts over when the day changes. Call it with mu held.
func (m *transferMeter) today() {
	day := m.now().Unix() / 86400
	if day != m.day {
		m.day = day
		clear(m.bytes)
	}
}

// over reports whether owner used up limit today; a zero limit never is.
func (m *transferMeter) over(owner string, limit int64) bool {
	if limit <= 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.today()
	return m.bytes[owner] >= limit
}

// add counts n bytes for owner, and reports whether they took it to limit.
func (m *transferMeter) add(owner string, n, limit int64) (reached bool) {
	if n <= 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.today()
	before := m.bytes[owner]
	m.bytes[owner] = before + n
	return limit > 0 && before < limit && before+n >= limit
}

// untilReset is how long until the counts start over, at midnight UTC.
func (m *transferMeter) untilReset() time.Duration {
	now := m.now().UTC()
	return now.Truncate(24 * time.Hour).Add(24 * time.Hour).Sub(now)
}

// stableIPShare is how many keys' daily transfer one IP's stable tunnels may
// use together: people sharing an address (an office, a mobile carrier) each
// get their key's limit, but making new keys can't stretch an IP's further.
const stableIPShare = 3

// transferQuota is a count a tunnel's transfer goes to, and its daily limit.
type transferQuota struct {
	owner string
	limit int64
}

// transferQuotas are who a tunnel's transfer counts against: its account; or
// for the stable user, its key and its client IP; or else its client IP. IPv6
// counts by /64, which one client can rotate through.
func transferQuotas(tun *tunnel.Tunnel) (first, second transferQuota) {
	limit := tun.Limits.DailyTransfer
	switch {
	case tun.AccountID != "":
		return transferQuota{"account:" + tun.AccountID, limit}, transferQuota{}
	case tun.Owner != "":
		return transferQuota{"key:" + tun.Owner, limit}, transferQuota{visitorKey(tun.ClientIP), limit * stableIPShare}
	}
	return transferQuota{visitorKey(tun.ClientIP), limit}, transferQuota{}
}

// overTransfer reports whether the tunnel's owner used up a daily limit.
func (s *Server) overTransfer(tun *tunnel.Tunnel) bool {
	first, second := transferQuotas(tun)
	return s.transfer.over(first.owner, first.limit) || second.owner != "" && s.transfer.over(second.owner, second.limit)
}

// countTransfer counts a request's bytes against the tunnel's owner, and
// tells the owner when that reaches a daily limit.
func (s *Server) countTransfer(tun *tunnel.Tunnel, in, out int64) {
	n := max(in, 0) + max(out, 0)
	first, second := transferQuotas(tun)
	reached, what := int64(0), "your tunnels"
	if s.transfer.add(first.owner, n, first.limit) {
		reached = first.limit
	}
	if second.owner != "" && s.transfer.add(second.owner, n, second.limit) && reached == 0 {
		reached, what = second.limit, "stable tunnels from your IP address"
	}
	if reached == 0 {
		return
	}
	log.Printf("Tunnel %s: its owner reached a daily transfer limit (%s)", tun.Subdomain, tunnel.FormatBytes(reached))
	if logger := tun.Logger(); logger != nil {
		msg := "Reached the daily transfer limit of " + tunnel.FormatBytes(reached) + " for " + what +
			": visitors get HTTP 429 until it resets at 00:00 UTC."
		if note := tun.Limits.TransferNote; note != "" {
			msg += " " + note
		}
		logger.Notice(msg)
	}
}
