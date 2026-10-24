package server

import (
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/klipitkas/tunnl.gg/pkg/config"
)

func TestTransferMeter(t *testing.T) {
	now := time.Date(2026, 10, 24, 23, 0, 0, 0, time.UTC)
	m := newTransferMeter()
	m.now = func() time.Time { return now }
	a, ab := []string{"a"}, []string{"a", "b"}

	if m.add(a, 60, 100) || m.over(a, 100) {
		t.Fatal("60 of 100 bytes counts as the limit")
	}
	if !m.add(ab, 40, 100) {
		t.Error("reaching the limit isn't reported")
	}
	if m.add(ab, 10, 100) {
		t.Error("going further past the limit is reported again")
	}
	if !m.over(a, 100) || m.over([]string{"b"}, 100) || !m.over(ab, 100) || m.over(a, 0) {
		t.Error("over() is wrong after the limit")
	}
	if m.add([]string{"c"}, 10, 0); m.bytes["c"] != 0 {
		t.Error("counted without a limit")
	}
	if got := m.untilReset(); got != time.Hour {
		t.Errorf("untilReset() = %v, want 1h", got)
	}

	now = now.Add(time.Hour) // midnight UTC
	if m.over(a, 100) {
		t.Error("the limit holds past midnight")
	}
}

func TestTransferKeys(t *testing.T) {
	for _, tc := range []struct {
		account, owner, ip string
		want               []string
	}{
		{"", "", "192.0.2.1", []string{"192.0.2.1"}},
		{"", "", "2001:db8:1:2:3:4:5:6", []string{"2001:db8:1:2::/64"}},
		{"", "SHA256:abc", "192.0.2.1", []string{"key:SHA256:abc", "192.0.2.1"}},
		{"acct_1", "acct_1", "192.0.2.1", []string{"account:acct_1"}},
	} {
		if got := transferKeys(tc.account, tc.owner, tc.ip); !slices.Equal(got, tc.want) {
			t.Errorf("transferKeys(%q, %q, %q) = %q, want %q", tc.account, tc.owner, tc.ip, got, tc.want)
		}
	}
}

// getStatus requests / through the tunnel and returns the status.
func getStatus(t *testing.T, tt *testTunnel) *http.Response {
	t.Helper()
	resp := tt.get(t, "/")
	io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp
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
		resp := getStatus(t, tt)
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
	if resp := getStatus(t, other); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("the same IP's other tunnel: status %d", resp.StatusCode)
	}
}

func TestE2E_DailyTransferLimitStable(t *testing.T) {
	srv, addr := startSSHServer(t)
	free := config.FreeLimits()
	free.BrowserWarning = false
	free.DailyTransfer = 1000
	srv.SetFreeLimits(free)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("x", 600))
	})
	status := func(tt *testTunnel) int { return getStatus(t, tt).StatusCode }

	// A stable key and an anonymous tunnel from the same IP share its limit
	stable := openTunnel(t, srv, addr, stableClient(newTestKey(t)), app)
	anonymous := openTunnel(t, srv, addr, anonymousClient(), app)
	if a, b := status(stable), status(anonymous); a != 200 || b != 200 {
		t.Fatalf("under the limit: statuses %d %d", a, b)
	}
	// A new key doesn't get a fresh limit from the same IP
	fresh := openTunnel(t, srv, addr, stableClient(newTestKey(t)), app)
	if got := status(fresh); got != 429 {
		t.Errorf("a new key from the same IP: status %d, want 429", got)
	}
	if got := status(stable); got != 429 {
		t.Errorf("the first key: status %d, want 429", got)
	}
}
