package tunnel

import (
	"sync"
	"testing"
	"time"

	"github.com/klipitkas/tunnl.gg/pkg/config"
)

func TestRequestActivityConcurrentEnd(t *testing.T) {
	tun := &Tunnel{Limits: config.Limits{InactivityTimeout: time.Hour}}
	first, second := tun.BeginRequest(), tun.BeginRequest()
	beforeEnd := time.Now()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			<-start
			first.End()
			tun.mu.Lock()
			defer tun.mu.Unlock()
			if tun.inFlight != 1 || tun.LastActive.Before(beforeEnd) {
				t.Errorf("completion returned with inFlight=%d, LastActive=%s", tun.inFlight, tun.LastActive)
			}
		})
	}
	close(start)
	wg.Wait()

	// A repeated completion must not count twice or refresh idle time. Another
	// stream remains active even when the last activity timestamp is old.
	old := time.Now().Add(-2 * time.Hour)
	tun.LastActive = old
	first.End()
	if tun.LastActive != old || tun.inFlight != 1 {
		t.Fatal("repeated completion changed tunnel activity")
	}
	if tun.IsExpired() {
		t.Fatal("the remaining stream no longer keeps the tunnel active")
	}
	second.End()
	if tun.inFlight != 0 || tun.IsExpired() {
		t.Fatal("final completion did not reset inactivity")
	}
	tun.LastActive = old
	first.End()
	second.End()
	if !tun.IsExpired() || tun.inFlight != 0 {
		t.Fatal("completed activities prevented idle expiry")
	}
}

func TestRequestActivityDeferredEndOnPanic(t *testing.T) {
	tun := &Tunnel{}
	func() {
		defer func() {
			if got := recover(); got != "handler panic" {
				t.Fatalf("unexpected panic: %v", got)
			}
		}()
		defer tun.BeginRequest().End()
		if tun.inFlight != 1 {
			t.Fatal("deferred completion did not begin activity immediately")
		}
		panic("handler panic")
	}()
	if tun.inFlight != 0 {
		t.Fatal("panic leaked an active request")
	}
}
