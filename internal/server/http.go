package server

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"tunnl.gg/internal/config"
	"tunnl.gg/internal/subdomain"
	"tunnl.gg/internal/tunnel"
)

var errResponseTooLarge = errors.New("response body too large")

// ServeHTTP implements http.Handler for HTTPS requests
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)

	// Enforce request body size limit
	if r.ContentLength > config.MaxRequestBodySize {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, config.MaxRequestBodySize)

	host := strings.ToLower(stripPort(r.Host))
	domain := strings.ToLower(s.domain)

	if !strings.HasSuffix(host, "."+domain) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	sub := strings.TrimSuffix(host, "."+domain)

	if !subdomain.IsValid(sub) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	tun := s.GetTunnel(sub)
	if tun == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Throttle only the visitor: the tunnel owner doesn't control who sends
	// traffic to their URL, so exceeding the limit must not affect the tunnel.
	visitor := visitorKey(r.RemoteAddr)
	if !tun.AllowRequest(visitor) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	defer tun.BeginRequest()()
	s.IncrementRequests()

	// Show interstitial warning for browser requests
	if isBrowserRequest(r) &&
		r.Header.Get("tunnl-skip-browser-warning") == "" &&
		!hasWarningCookie(r, sub) {
		s.redirectToWarningPage(w, r, sub)
		return
	}

	if isWebSocketRequest(r) {
		// Upgraded connections are long-lived, so cap how many are open at once
		if !s.wsPerVisitor.acquire(visitor) {
			http.Error(w, "Too Many WebSocket Connections", http.StatusTooManyRequests)
			return
		}
		defer s.wsPerVisitor.release(visitor)
		if !s.wsPerTunnel.acquire(sub) {
			http.Error(w, "Too Many WebSocket Connections", http.StatusTooManyRequests)
			return
		}
		defer s.wsPerTunnel.release(sub)

		s.handleWebSocket(w, r, tun, sub)
		return
	}

	requestStart := time.Now()
	r = r.WithContext(tunnel.WithOrigin(r.Context(), r.RemoteAddr))
	dw, r, stopDeadlines := newProxyDeadlines(w, r, config.ProxyIdleTimeout)
	defer stopDeadlines()
	sw := &statusCaptureWriter{ResponseWriter: dw}

	// The tunneled app decides its own response headers
	for name := range securityHeaders {
		w.Header().Del(name)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// The tunnel's transport sends every request over SSH, so the
			// URL host only needs to be valid
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = pr.In.Host
			pr.Out.Host = pr.In.Host
			// Replaces any X-Forwarded-* headers sent by the visitor
			pr.SetXForwarded()
		},
		Transport: tun.Transport(),
		ModifyResponse: func(resp *http.Response) error {
			for name, value := range proxiedDefaultHeaders {
				if resp.Header.Get(name) == "" {
					resp.Header.Set(name, value)
				}
			}

			// Enforce response body size limit
			if resp.ContentLength > config.MaxResponseBodySize {
				return fmt.Errorf("%w: %d bytes (max %d)", errResponseTooLarge, resp.ContentLength, config.MaxResponseBodySize)
			}
			// Wrap body with size limiter for chunked/unknown-length responses
			resp.Body = &limitedReadCloser{
				rc:    resp.Body,
				limit: config.MaxResponseBodySize,
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error for %s: %v", sub, err)
			setSecurityHeaders(w)
			if errors.Is(err, errResponseTooLarge) {
				http.Error(w, "Response Too Large", http.StatusBadGateway)
				return
			}
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	proxy.ServeHTTP(sw, r)

	if logger := tun.Logger(); logger != nil {
		logger.LogRequest(r.Method, r.URL.Path, sw.status, time.Since(requestStart))
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request, tun *tunnel.Tunnel, sub string) {
	backendConn, err := tun.Dial(tunnel.WithOrigin(r.Context(), r.RemoteAddr))
	if err != nil {
		log.Printf("WebSocket backend dial error for %s: %v", sub, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("WebSocket hijack not supported for %s", sub)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	hijacked, brw, err := hijacker.Hijack()
	if err != nil {
		// After Hijack() is called (even on failure), ResponseWriter may be invalid
		// Just log the error and return - the connection will be closed
		log.Printf("WebSocket hijack error for %s: %v", sub, err)
		return
	}
	defer hijacked.Close()
	// Read through the hijack buffer: it may already hold data the client
	// sent right after the upgrade request.
	clientConn := &bufferedConn{Conn: hijacked, r: brw.Reader}

	if err := r.Write(backendConn); err != nil {
		log.Printf("WebSocket request write error for %s: %v", sub, err)
		return
	}

	logger := tun.Logger()
	wsPath := r.URL.Path
	wsStart := time.Now()
	if logger != nil {
		logger.LogWebSocketOpen(wsPath)
	}

	// Copy data bidirectionally with limits
	var backendBytes, clientBytes int64
	clientDone := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(clientDone)
		backendBytes, _ = copyWithLimits(backendConn, clientConn, config.MaxWebSocketTransfer, config.WebSocketIdleTimeout)
		// Signal backend we're done sending
		if cw, ok := backendConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer close(done)
		clientBytes, _ = copyWithLimits(clientConn, backendConn, config.MaxWebSocketTransfer, config.WebSocketIdleTimeout)
	}()
	<-done
	// Once the backend is done, close both sides to stop the client copy, and
	// wait for it so its byte count is complete before logging
	hijacked.Close()
	backendConn.Close()
	<-clientDone

	if logger != nil {
		logger.LogWebSocketClose(wsPath, time.Since(wsStart), backendBytes+clientBytes)
	}
}

// bufferedConn is a net.Conn whose reads are served from r first.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// copyWithLimits copies from src to dst with a byte transfer limit and idle timeout.
// It resets the read deadline on src after each successful read.
// Returns the number of bytes written and any error.
func copyWithLimits(dst, src net.Conn, maxBytes int64, idleTimeout time.Duration) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, readErr := src.Read(buf)
		if n > 0 {
			written += int64(n)
			if written > maxBytes {
				return written, fmt.Errorf("transfer limit exceeded")
			}
			dst.SetWriteDeadline(time.Now().Add(idleTimeout))
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return written, writeErr
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return written, nil
			}
			return written, readErr
		}
	}
}

// securityHeaders are set on responses the server generates itself, such as
// errors and redirects.
var securityHeaders = map[string]string{
	"X-Content-Type-Options": "nosniff",
	"X-Frame-Options":        "DENY",
	"Referrer-Policy":        "strict-origin-when-cross-origin",
}

// proxiedDefaultHeaders are added to proxied responses only when the tunneled
// app doesn't set them. Framing is left to the app, so it can be embedded.
var proxiedDefaultHeaders = map[string]string{
	"X-Content-Type-Options": "nosniff",
	"Referrer-Policy":        "strict-origin-when-cross-origin",
}

func setSecurityHeaders(w http.ResponseWriter) {
	for name, value := range securityHeaders {
		w.Header().Set(name, value)
	}
}

func isBrowserRequest(r *http.Request) bool {
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	browserKeywords := []string{"mozilla", "chrome", "safari", "firefox", "edge", "opera"}
	for _, kw := range browserKeywords {
		if strings.Contains(ua, kw) {
			return true
		}
	}
	return false
}

func hasWarningCookie(r *http.Request, sub string) bool {
	cookie, err := r.Cookie(config.WarningCookieName + "_" + sub)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte("1")) == 1
}

func (s *Server) redirectToWarningPage(w http.ResponseWriter, r *http.Request, sub string) {
	originalURL := "https://" + r.Host + r.URL.RequestURI()
	fullSubdomain := sub + "." + s.domain
	warningURL := fmt.Sprintf("https://%s/#/warning?redirect=%s&subdomain=%s",
		s.domain,
		url.QueryEscape(originalURL),
		url.QueryEscape(fullSubdomain))
	http.Redirect(w, r, warningURL, http.StatusTemporaryRedirect)
}

func isWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// visitorKey returns the rate-limit key for a request's remote address. IPv6
// addresses are grouped by /64, since a single client typically controls a
// whole /64 and could otherwise rotate addresses to evade the limit.
func visitorKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// stripPort removes the port from a host string (e.g., "example.com:443" -> "example.com")
func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	if strings.Count(host, ":") == 1 {
		idx := strings.LastIndex(host, ":")
		return host[:idx]
	}
	return host
}

// limitedReadCloser wraps an io.ReadCloser and limits the number of bytes read
type limitedReadCloser struct {
	rc    io.ReadCloser
	limit int64
	read  int64
}

func (l *limitedReadCloser) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if l.read >= l.limit {
		var probe [1]byte
		n, err := l.rc.Read(probe[:])
		if n > 0 {
			l.read += int64(n)
			return 0, fmt.Errorf("%w (exceeded %d bytes)", errResponseTooLarge, l.limit)
		}
		return 0, err
	}
	remaining := l.limit - l.read
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err = l.rc.Read(p)
	l.read += int64(n)
	return n, err
}

func (l *limitedReadCloser) Close() error {
	return l.rc.Close()
}

// statusCaptureWriter wraps http.ResponseWriter to capture the status code.
type statusCaptureWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusCaptureWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.status = code
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusCaptureWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap returns the underlying ResponseWriter for interface passthrough (e.g., http.Flusher).
func (w *statusCaptureWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// HTTPRedirectHandler returns an http.Handler that redirects HTTP to HTTPS
func (s *Server) HTTPRedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(stripPort(r.Host))
		domain := strings.ToLower(s.domain)
		if !strings.HasSuffix(host, "."+domain) && host != domain {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		target := "https://" + r.Host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}
