package server

import (
	"log"
	"strconv"
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

// over reports whether any of keys used up limit today; a zero limit never
// is.
func (m *transferMeter) over(keys []string, limit int64) bool {
	if limit <= 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.today()
	for _, k := range keys {
		if m.bytes[k] >= limit {
			return true
		}
	}
	return false
}

// add counts n bytes for each of keys, and reports whether they took any to
// limit. Without a limit nothing is counted.
func (m *transferMeter) add(keys []string, n, limit int64) (reached bool) {
	if n <= 0 || limit <= 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.today()
	for _, k := range keys {
		before := m.bytes[k]
		m.bytes[k] = before + n
		reached = reached || before < limit && before+n >= limit
	}
	return reached
}

// used is the most any of keys sent today.
func (m *transferMeter) used(keys []string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.today()
	var most int64
	for _, k := range keys {
		most = max(most, m.bytes[k])
	}
	return most
}

// untilReset is how long until the counts start over, at midnight UTC.
func (m *transferMeter) untilReset() time.Duration {
	now := m.now().UTC()
	return now.Truncate(24 * time.Hour).Add(24 * time.Hour).Sub(now)
}

// transferKeys are who a tunnel's transfer counts against: its account; or
// for the stable user (owner is its key), both the key and the client IP, so
// neither a new key nor a new address gets a fresh limit; or else its client
// IP. IPv6 counts by /64, which one client can rotate through.
func transferKeys(accountID, owner, clientIP string) []string {
	switch {
	case accountID != "":
		return []string{"account:" + accountID}
	case owner != "":
		return []string{"key:" + owner, visitorKey(clientIP)}
	}
	return []string{visitorKey(clientIP)}
}

// countTransfer counts a request's bytes against the tunnel's owner, and
// tells the owner when that reaches the daily limit.
func (s *Server) countTransfer(tun *tunnel.Tunnel, in, out int64) {
	limit := tun.Limits.DailyTransfer
	if !s.transfer.add(tun.TransferKeys, max(in, 0)+max(out, 0), limit) {
		return
	}
	log.Printf("Tunnel %s: its owner reached the daily transfer limit (%s)", tun.Subdomain, formatLimit(limit))
	if logger := tun.Logger(); logger != nil {
		msg := "Reached the daily transfer limit of " + formatLimit(limit) +
			" for your tunnels: visitors get HTTP 429 until it resets at 00:00 UTC."
		if note := tun.Limits.TransferNote; note != "" {
			msg += " " + note
		}
		logger.Notice(msg)
	}
}

// formatLimit writes whole gigabytes as "5 GB", like the documented limits.
func formatLimit(b int64) string {
	if b > 0 && b%(1<<30) == 0 {
		return strconv.FormatInt(b>>30, 10) + " GB"
	}
	return tunnel.FormatBytes(b)
}
