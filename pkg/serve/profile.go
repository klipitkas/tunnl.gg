package serve

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"
	"time"
)

// Profiling is opt-in and uses a dedicated mux on a numeric loopback address.
// Never attach these handlers to the public HTTP or statistics listener.
func newProfileServer(addr string) (*http.Server, error) {
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
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}, nil
}
