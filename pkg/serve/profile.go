package serve

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime"
	"runtime/trace"
	"strconv"
	"sync"
	"time"
)

// Profiling is opt-in and uses a dedicated mux on a numeric loopback address.
// Never attach these handlers to the public HTTP or statistics listener.
//
// With a flight recorder, GET /debug/pprof/trace-window writes an execution
// trace of about the recorder's window, for looking into a stall just seen.
func newProfileServer(addr string, recorder *trace.FlightRecorder) (*http.Server, error) {
	if addr == "" {
		return nil, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return nil, fmt.Errorf("expected a loopback IP and port, such as 127.0.0.1:9092")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	for _, name := range []string{"heap", "allocs", "goroutine", "mutex", "block"} {
		mux.Handle("GET /debug/pprof/"+name, pprof.Handler(name))
	}
	if recorder != nil {
		var mu sync.Mutex // the recorder writes one snapshot at a time
		mux.HandleFunc("GET /debug/pprof/trace-window", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", `attachment; filename="trace.out"`)
			if _, err := recorder.WriteTo(w); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		})
	}
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}, nil
}

// Mutex and block profiles stay empty unless the runtime samples them. These
// rates record one in mutexProfileFraction contended lock waits, and blocking
// events in proportion to their length: every one of blockProfileRate or
// more. Both cost little enough to leave on while profiling is.
const (
	mutexProfileFraction = 100
	blockProfileRate     = 100 * time.Microsecond
)

func enableContentionProfiles() {
	runtime.SetMutexProfileFraction(mutexProfileFraction)
	runtime.SetBlockProfileRate(int(blockProfileRate))
}

// flightRecorderMaxBytes caps the flight recorder's window, whatever its age.
const flightRecorderMaxBytes = 32 << 20

// newFlightRecorder starts a flight recorder that keeps about window of
// execution trace in memory, or returns nil if window is empty. Tracing
// costs a few percent of CPU while it's on.
func newFlightRecorder(window string) (*trace.FlightRecorder, error) {
	if window == "" {
		return nil, nil
	}
	d, err := time.ParseDuration(window)
	if err != nil || d <= 0 {
		return nil, fmt.Errorf("expected a positive duration, such as 10s")
	}
	recorder := trace.NewFlightRecorder(trace.FlightRecorderConfig{MinAge: d, MaxBytes: flightRecorderMaxBytes})
	if err := recorder.Start(); err != nil {
		return nil, err
	}
	return recorder, nil
}
