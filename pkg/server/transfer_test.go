package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

func TestTransferMeter(t *testing.T) {
	now := time.Date(2026, 10, 24, 23, 0, 0, 0, time.UTC)
	m := newTransferMeter()
	m.now = func() time.Time { return now }

	if m.add("a", 60, 100) || m.over("a", 100) {
		t.Fatal("60 of 100 bytes counts as the limit")
	}
	if !m.add("a", 40, 100) {
		t.Error("reaching the limit isn't reported")
	}
	if m.add("a", 10, 100) {
		t.Error("going further past the limit is reported again")
	}
	if !m.over("a", 100) || m.over("b", 100) || m.over("a", 0) {
		t.Error("over() is wrong after the limit")
	}
	if got := m.untilReset(); got != time.Hour {
		t.Errorf("untilReset() = %v, want 1h", got)
	}

	now = now.Add(time.Hour) // midnight UTC
	if m.over("a", 100) {
		t.Error("the limit holds past midnight")
	}
}

func TestTransferQuotas(t *testing.T) {
	limits := config.Limits{DailyTransfer: 100}
	for _, tc := range []struct {
		ip, account, owner string
		want               [2]transferQuota
	}{
		{"192.0.2.1", "", "", [2]transferQuota{{"192.0.2.1", 100}, {}}},
		{"2001:db8:1:2:3:4:5:6", "", "", [2]transferQuota{{"2001:db8:1:2::/64", 100}, {}}},
		{"192.0.2.1", "", "SHA256:abc", [2]transferQuota{{"key:SHA256:abc", 100}, {"192.0.2.1", 300}}},
		{"192.0.2.1", "acct_1", "acct_1", [2]transferQuota{{"account:acct_1", 100}, {}}},
	} {
		first, second := transferQuotas(&tunnel.Tunnel{ClientIP: tc.ip, AccountID: tc.account, Owner: tc.owner, Limits: limits})
		if got := [2]transferQuota{first, second}; got != tc.want {
			t.Errorf("transferQuotas(%q, %q, %q) = %v, want %v", tc.ip, tc.account, tc.owner, got, tc.want)
		}
	}
}

func TestE2E_DailyTransferLimit(t *testing.T) {
	srv, addr := startSSHServer(t)
	free := config.FreeLimits()
	free.BrowserWarning = false
	free.DailyTransfer = 1000
	free.TransferNote = "Pro doubles it."
	srv.SetFreeLimits(free)

	tt := openTunnel(t, srv, addr, anonymousClient(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("x", 600))
	}))
	for i, want := range []int{http.StatusOK, http.StatusOK, http.StatusTooManyRequests} {
		resp := tt.get(t, "/")
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("request %d: status %d, want %d", i+1, resp.StatusCode, want)
		}
		if want == http.StatusTooManyRequests && resp.Header.Get("Retry-After") == "" {
			t.Error("the refusal has no Retry-After")
		}
	}
	waitFor(t, "the notice", func() bool {
		return strings.Contains(tt.output.String(), "Reached the daily transfer limit of 1000 B") &&
			strings.Contains(tt.output.String(), "Pro doubles it.")
	})

	// Another tunnel from the same IP shares the limit
	other := openTunnel(t, srv, addr, anonymousClient(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	resp := other.get(t, "/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("the same IP's other tunnel: status %d", resp.StatusCode)
	}
}

func TestE2E_DailyTransferLimitStable(t *testing.T) {
	srv, addr := startSSHServer(t)
	free := config.FreeLimits()
	free.BrowserWarning = false
	free.DailyTransfer = 1000 // per key; 3000 for the IP's stable tunnels
	srv.SetFreeLimits(free)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("x", 600))
	})
	statuses := func(tt *testTunnel, n int) []int {
		var out []int
		for range n {
			resp := tt.get(t, "/")
			io.ReadAll(resp.Body)
			resp.Body.Close()
			out = append(out, resp.StatusCode)
		}
		return out
	}

	// Each key gets its own limit from the same IP...
	for _, name := range []string{"first", "second"} {
		tt := openTunnel(t, srv, addr, stableClient(newTestKey(t)), app)
		if got := statuses(tt, 3); got[0] != 200 || got[1] != 200 || got[2] != 429 {
			t.Errorf("%s key: statuses %v, want 200 200 429", name, got)
		}
	}
	// ...until the IP's stable tunnels reach three keys' worth
	tt := openTunnel(t, srv, addr, stableClient(newTestKey(t)), app)
	if got := statuses(tt, 2); got[0] != 200 || got[1] != 429 {
		t.Errorf("third key: statuses %v, want 200 429", got)
	}
	waitFor(t, "the notice", func() bool {
		return strings.Contains(tt.output.String(), "for stable tunnels from your IP address")
	})
}
