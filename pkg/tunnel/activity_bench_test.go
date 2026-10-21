package tunnel

import "testing"

// Match the handler's deferred completion, including both activity timestamps.
func benchmarkRequestActivity(tun *Tunnel) {
	defer tun.BeginRequest().End()
}

func BenchmarkRequestActivity(b *testing.B) {
	tun := &Tunnel{}
	b.ReportAllocs()
	for range b.N {
		benchmarkRequestActivity(tun)
	}
	if tun.inFlight != 0 {
		b.Fatalf("activity leaked: %d requests", tun.inFlight)
	}
}
