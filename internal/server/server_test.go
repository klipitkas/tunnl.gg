package server

import (
	"fmt"
	"testing"

	"tunnl.gg/internal/config"
)

func TestCheckAndReserveConnection_CapacityCountsReservations(t *testing.T) {
	s := newTestServer(t)

	// Reserve every slot from distinct IPs without registering any tunnels
	for i := 0; i < config.MaxTotalTunnels; i++ {
		if err := s.CheckAndReserveConnection(fmt.Sprintf("10.0.%d.%d", i/256, i%256)); err != nil {
			t.Fatalf("reservation %d: %v", i+1, err)
		}
	}
	if err := s.CheckAndReserveConnection("192.0.2.1"); err == nil {
		t.Fatal("reservation over capacity should fail even before tunnels are registered")
	}

	s.DecrementIPConnection("10.0.0.0")
	if err := s.CheckAndReserveConnection("192.0.2.1"); err != nil {
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

	first, err := s.ReserveSubdomain()
	if err != nil {
		t.Fatalf("ReserveSubdomain() error: %v", err)
	}
	second, err := s.ReserveSubdomain()
	if err != nil {
		t.Fatalf("ReserveSubdomain() error: %v", err)
	}
	if first == second {
		t.Errorf("ReserveSubdomain() returned %q twice", first)
	}
}

func TestRegisterTunnel_RequiresReservation(t *testing.T) {
	s := newTestServer(t)

	sub, err := s.ReserveSubdomain()
	if err != nil {
		t.Fatalf("ReserveSubdomain() error: %v", err)
	}
	// The connection gave up waiting and cleaned up before registering
	s.RemoveTunnel(sub)

	if tun := s.RegisterTunnel(sub, nil, "localhost", 80, "192.0.2.1"); tun != nil {
		t.Error("RegisterTunnel() should refuse a subdomain whose reservation was released")
	}
	if s.GetTunnel(sub) != nil {
		t.Error("released subdomain should not be registered")
	}
}
