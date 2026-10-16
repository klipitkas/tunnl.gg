package server

import (
	"fmt"
	"sync"
	"testing"

	"github.com/klipitkas/tunnl.gg/pkg/config"
)

func TestConfiguredCapacityConcurrentReservations(t *testing.T) {
	s := newTestServer(t)
	if err := s.SetMaxTotalTunnels(17); err != nil {
		t.Fatal(err)
	}
	if got := s.GetStats(false).MaxTotalTunnels; got != 17 {
		t.Fatalf("reported cap %d, want 17", got)
	}
	var wg sync.WaitGroup
	slots := make(chan string, 100)
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if slot, err := s.CheckAndReserveConnection(fmt.Sprintf("192.0.2.%d", i), nil); err == nil {
				slots <- slot
			}
		}()
	}
	wg.Wait()
	close(slots)
	if len(slots) != 17 {
		t.Fatalf("admitted %d reservations, want 17", len(slots))
	}
	if err := s.SetMaxTotalTunnels(0); err == nil {
		t.Fatal("zero cap accepted")
	}
	if err := s.SetMaxTotalTunnels(-1); err == nil {
		t.Fatal("negative cap accepted")
	}
	if err := s.SetMaxTotalTunnels(1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckAndReserveConnection("198.51.100.1", nil); err == nil {
		t.Fatal("lowered cap admitted a reservation while full")
	}
	for slot := range slots {
		s.ReleaseConnection(slot)
	}
	if _, err := s.CheckAndReserveConnection("198.51.100.1", nil); err != nil {
		t.Fatalf("released slots were not reusable: %v", err)
	}
}

func TestCheckAndReserveConnection_CapacityCountsReservations(t *testing.T) {
	s := newTestServer(t)

	// Reserve every slot from distinct IPs without registering any tunnels
	for i := 0; i < config.MaxTotalTunnels; i++ {
		if _, err := s.CheckAndReserveConnection(fmt.Sprintf("10.0.%d.%d", i/256, i%256), nil); err != nil {
			t.Fatalf("reservation %d: %v", i+1, err)
		}
	}
	if _, err := s.CheckAndReserveConnection("192.0.2.1", nil); err == nil {
		t.Fatal("reservation over capacity should fail even before tunnels are registered")
	}

	s.ReleaseConnection("10.0.0.0")
	if _, err := s.CheckAndReserveConnection("192.0.2.1", nil); err != nil {
		t.Errorf("reservation after releasing a slot: %v", err)
	}
}

func TestReserveSubdomain_SkipsReservedSubdomains(t *testing.T) {
	s := newTestServer(t)
	candidates := []string{"happy-tiger-00000001", "happy-tiger-00000001", "happy-tiger-00000002"}
	s.newSubdomain = func() (string, error) {
		sub := candidates[0]
		candidates = candidates[1:]
		return sub, nil
	}

	first, err := s.ReserveSubdomain(nil)
	if err != nil {
		t.Fatalf("ReserveSubdomain() error: %v", err)
	}
	second, err := s.ReserveSubdomain(nil)
	if err != nil {
		t.Fatalf("ReserveSubdomain() error: %v", err)
	}
	if first == second {
		t.Errorf("ReserveSubdomain() returned %q twice", first)
	}
}

func TestRegisterTunnel_RequiresReservation(t *testing.T) {
	s := newTestServer(t)

	sub, err := s.ReserveSubdomain(nil)
	if err != nil {
		t.Fatalf("ReserveSubdomain() error: %v", err)
	}
	// The connection gave up waiting and cleaned up before registering
	s.RemoveTunnel(sub, nil)

	if tun := s.RegisterTunnel(sub, nil, "localhost", 80, "192.0.2.1", config.FreeLimits(), ""); tun != nil {
		t.Error("RegisterTunnel() should refuse a subdomain whose reservation was released")
	}
	if s.GetTunnel(sub) != nil {
		t.Error("released subdomain should not be registered")
	}
}
