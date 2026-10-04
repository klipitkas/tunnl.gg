package server

import (
	"bufio"
	"context"
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

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/clientip"
	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/subdomain"
	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

var errResponseTooLarge = errors.New("response body too large")

// optionsWaitTimeout bounds how long a request to a new tunnel waits for
// the client's options. The SSH side waits at most 5 seconds for the session
// and 5 more for its command.
const optionsWaitTimeout = 15 * time.Second

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

	if !subdomain.IsLabel(sub) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	tun := s.GetTunnel(sub)
	if tun == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// The client sends its options just after the tunnel opens; until then
	// it's unknown who may get in
	waitCtx, cancelWait := context.WithTimeout(r.Context(), optionsWaitTimeout)
	opts, ok := tun.Options(waitCtx)
	cancelWait()
	if !ok {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	client := s.clientIPs.Resolve(r.RemoteAddr, r.Header)
	// Before rate limiting, so visitors who aren't allowed can't use up the
	// tunnel's budget
	if !opts.Allows(client.Addr) {
		logTunnlEvent(tun, r, client, http.StatusForbidden, "not on the tunnel's allowlist")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Throttle only the visitor: the tunnel owner doesn't control who sends
	// traffic to their URL, so exceeding the limit must not affect the tunnel.
	visitor := visitorKey(client.Addr.String())
	if !tun.AllowRequest(visitor) {
		logTunnlEvent(tun, r, client, http.StatusTooManyRequests, "rate limited by tunnl")
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	defer tun.BeginRequest()()
	s.IncrementRequests()

	// After rate limiting, which slows down password guessing
	if opts.Auth != nil {
		if !tun.PasswordTriesLeft(visitor) {
			logTunnlEvent(tun, r, client, http.StatusTooManyRequests, "too many wrong passwords (tunnl limit)")
			w.Header().Set("Retry-After", "10")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		if !opts.Auth.Check(r) {
			// Browsers ask without credentials first: only guesses count
			if _, _, sent := r.BasicAuth(); sent {
				tun.PasswordFailed(visitor)
			}
			logTunnlEvent(tun, r, client, http.StatusUnauthorized, "no or wrong password")
			w.Header().Set("WWW-Authenticate", `Basic realm="`+sub+"."+s.domain+`", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// The tunnel's password is not for the app
		r.Header.Del("Authorization")
	}

	// Show interstitial warning for browser requests
	if tun.Limits.BrowserWarning && isBrowserRequest(r) &&
		r.Header.Get("tunnl-skip-browser-warning") == "" &&
		!hasWarningCookie(r, sub) {
		logTunnlEvent(tun, r, client, http.StatusTemporaryRedirect, "browser sent to the warning page")
		s.redirectToWarningPage(w, r, sub)
		return
	}

	if isWebSocketRequest(r) {
		// Upgraded connections are long-lived, so cap how many are open at once
		if !s.wsPerVisitor.acquire(visitor) {
			logTunnlEvent(tun, r, client, http.StatusTooManyRequests, "too many open WebSockets from this visitor (tunnl limit)")
			http.Error(w, "Too Many WebSocket Connections", http.StatusTooManyRequests)
			return
		}
		defer s.wsPerVisitor.release(visitor)
		if !s.wsPerTunnel.acquire(sub) {
			logTunnlEvent(tun, r, client, http.StatusTooManyRequests, "too many open WebSockets on this tunnel (tunnl limit)")
			http.Error(w, "Too Many WebSocket Connections", http.StatusTooManyRequests)
			return
		}
		defer s.wsPerTunnel.release(sub)

		s.handleWebSocket(w, r, tun, sub, client, opts)
		return
	}

	// Proxied requests can stay open for minutes, for example when a tunnel's
	// app never responds, so cap how many are in flight
	if !s.reqPerVisitor.acquire(visitor) {
		logTunnlEvent(tun, r, client, http.StatusTooManyRequests, "too many open requests from this visitor (tunnl limit)")
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}
	defer s.reqPerVisitor.release(visitor)
	if !s.reqPerTunnel.acquire(sub) {
		logTunnlEvent(tun, r, client, http.StatusServiceUnavailable, "too many open requests on this tunnel (tunnl limit)")
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	defer s.reqPerTunnel.release(sub)

	requestStart := time.Now()
	target := r.URL.RequestURI()
	// The inspector keeps what the app was sent and what it answered
	insp := tun.Inspector()
	var reqBody, respBody *tunnel.Capture
	var outHost string
	var outHeader, respHeader http.Header
	if insp != nil && r.Body != nil && r.Body != http.NoBody {
		reqBody = tunnel.NewCapture(r.Body)
		r.Body = reqBody
	}
	var proxyErr error
	var body *limitedReadCloser // the response body, once the app responds
	r = r.WithContext(tunnel.WithOrigin(r.Context(), originAddr(client, r.RemoteAddr)))
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
			if opts.Host != "" {
				pr.Out.Host = opts.Host
			}
			setForwardedHeaders(pr.Out.Header, pr.In, client)
			if insp != nil {
				outHost, outHeader = pr.Out.Host, pr.Out.Header.Clone()
			}
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
			body = &limitedReadCloser{
				rc:    resp.Body,
				limit: config.MaxResponseBodySize,
			}
			resp.Body = body
			if insp != nil {
				respHeader = resp.Header.Clone()
				respBody = tunnel.NewCapture(resp.Body)
				resp.Body = respBody
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error for %s: %v", sub, err)
			proxyErr = err
			setSecurityHeaders(w)
			if errors.Is(err, errResponseTooLarge) {
				http.Error(w, "Response Too Large", http.StatusBadGateway)
				return
			}
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	// ReverseProxy panics with http.ErrAbortHandler when the response body
	// can't be copied, so log from a deferred call that sees the panic
	defer func() {
		p := recover()
		detail := describeProxyError(proxyErr)
		if p != nil {
			detail = describeCutOff(body)
		}
		logEntry(tun, tunnel.Entry{
			Time:    requestStart,
			Method:  r.Method,
			Target:  target,
			Status:  sw.status,
			Bytes:   sw.bytes,
			Latency: time.Since(requestStart),
			Visitor: client.Addr.String(),
			Detail:  detail,
		})
		if insp != nil {
			insp.Add(tunnel.Exchange{
				Time:           requestStart,
				Method:         r.Method,
				Target:         target,
				Host:           outHost,
				Visitor:        client.Addr.String(),
				RequestHeader:  outHeader,
				RequestBody:    reqBody.Body(),
				Status:         sw.status,
				ResponseHeader: respHeader,
				ResponseBody:   respBody.Body(),
				Duration:       time.Since(requestStart),
				Note:           detail,
			})
		}
		if p != nil {
			panic(p)
		}
	}()

	proxy.ServeHTTP(sw, r)
}

// logEntry writes e to the tunnel's request log, if its SSH session has one.
func logEntry(tun *tunnel.Tunnel, e tunnel.Entry) {
	if logger := tun.Logger(); logger != nil {
		logger.Log(e)
	}
}

// logTunnlEvent logs a request that tunnl answered itself, without the app.
func logTunnlEvent(tun *tunnel.Tunnel, r *http.Request, client clientip.Result, status int, note string) {
	if insp := tun.Inspector(); insp != nil {
		header := r.Header.Clone()
		// A wrong tunnel password isn't for the inspector to show
		header.Del("Authorization")
		insp.Add(tunnel.Exchange{
			Time:          time.Now(),
			Method:        r.Method,
			Target:        r.URL.RequestURI(),
			Host:          r.Host,
			Visitor:       client.Addr.String(),
			RequestHeader: header,
			Status:        status,
			Note:          "answered by tunnl: " + note,
		})
	}
	logEntry(tun, tunnel.Entry{
		Time:      time.Now(),
		Method:    r.Method,
		Target:    r.URL.RequestURI(),
		Status:    status,
		Bytes:     -1,
		Visitor:   client.Addr.String(),
		Note:      note,
		FromTunnl: true,
	})
}

// describeProxyError explains in plain words why a request couldn't be
// completed by the tunneled app, for the tunnel owner's request log.
func describeProxyError(err error) string {
	var openErr *ssh.OpenChannelError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &openErr):
		// The SSH client couldn't connect to the local app, e.g. nothing is
		// listening on the forwarded port
		reason := openErr.Message
		if reason == "" {
			reason = openErr.Reason.String()
		}
		return "your local app didn't accept the connection: " + strings.ToLower(reason)
	case errors.Is(err, errResponseTooLarge):
		return fmt.Sprintf("response larger than %s, not sent", tunnel.FormatBytes(config.MaxResponseBodySize))
	case errors.Is(err, context.DeadlineExceeded):
		return "your SSH client didn't connect to your local app in time"
	case errors.Is(err, context.Canceled):
		return "canceled: the visitor left, or no data for " + tunnel.FormatDuration(config.ProxyIdleTimeout)
	default:
		return "couldn't get a response from your local app: " + err.Error()
	}
}

// describeCutOff explains why a response stopped partway through, given its
// body, for the tunnel owner's request log.
func describeCutOff(body *limitedReadCloser) string {
	var err error
	if body != nil {
		err = body.err
	}
	switch {
	case errors.Is(err, errResponseTooLarge):
		return fmt.Sprintf("response larger than %s, cut off", tunnel.FormatBytes(config.MaxResponseBodySize))
	case err == nil, errors.Is(err, context.Canceled):
		// Reading from the app didn't fail on its own, so sending to the
		// visitor failed or the request was canceled
		return "response cut off: the visitor left, or no data for " + tunnel.FormatDuration(config.ProxyIdleTimeout)
	default:
		return "response cut off: your local app stopped sending: " + err.Error()
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request, tun *tunnel.Tunnel, sub string, client clientip.Result, opts tunnel.Options) {
	wsEntry := tunnel.Entry{
		Time:    time.Now(),
		Method:  "WS",
		Target:  r.URL.RequestURI(),
		Bytes:   -1,
		Visitor: client.Addr.String(),
	}

	backendConn, err := tun.Dial(tunnel.WithOrigin(r.Context(), originAddr(client, r.RemoteAddr)))
	if err != nil {
		log.Printf("WebSocket backend dial error for %s: %v", sub, err)
		failed := wsEntry
		failed.Status = http.StatusBadGateway
		failed.Detail = describeProxyError(err)
		logEntry(tun, failed)
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

	// The upgrade request is written as-is, so give the app the same
	// forwarding headers as proxied requests
	setForwardedHeaders(r.Header, r, client)
	if opts.Host != "" {
		r.Host = opts.Host
	}
	if err := r.Write(backendConn); err != nil {
		log.Printf("WebSocket request write error for %s: %v", sub, err)
		return
	}

	opened := wsEntry
	opened.Note = "open"
	logEntry(tun, opened)

	// Copy data bidirectionally with limits
	var backendBytes, clientBytes int64
	clientDone := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(clientDone)
		backendBytes, _ = copyWithLimits(backendConn, clientConn, config.MaxWebSocketTransfer, config.WebSocketIdleTimeout)
	}()
	go func() {
		defer close(done)
		clientBytes, _ = copyWithLimits(clientConn, backendConn, config.MaxWebSocketTransfer, config.WebSocketIdleTimeout)
	}()
	// Once either side is done, close both to stop the other copy: an app
	// that ignores the visitor leaving would otherwise hold the WebSocket's
	// slots until the idle timeout. Wait for both copies so the byte count is
	// complete before logging.
	select {
	case <-done:
	case <-clientDone:
	}
	hijacked.Close()
	backendConn.Close()
	<-done
	<-clientDone

	closed := wsEntry
	closed.Time = time.Now()
	closed.Note = fmt.Sprintf("closed after %s, %s",
		tunnel.FormatDuration(time.Since(wsEntry.Time)), tunnel.FormatBytes(backendBytes+clientBytes))
	logEntry(tun, closed)
	if insp := tun.Inspector(); insp != nil {
		insp.Add(tunnel.Exchange{
			Time:          wsEntry.Time,
			Method:        "WS",
			Target:        wsEntry.Target,
			Host:          r.Host,
			Visitor:       wsEntry.Visitor,
			RequestHeader: r.Header.Clone(),
			Status:        http.StatusSwitchingProtocols,
			Duration:      time.Since(wsEntry.Time),
			Note:          closed.Note,
		})
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

// setForwardedHeaders replaces the forwarding headers on a request to the
// tunneled app, so the app only sees values set by this server: the resolved
// visitor, the public host, and the scheme the visitor used. CF-Connecting-IP
// is kept only when it came from Cloudflare; otherwise a visitor could set it.
func setForwardedHeaders(out http.Header, in *http.Request, client clientip.Result) {
	out.Del("Forwarded")
	out.Del("X-Forwarded-For")
	out.Del("X-Forwarded-Host")
	out.Del("X-Forwarded-Proto")
	if !client.ViaCloudflare {
		out.Del("CF-Connecting-IP")
	}

	if client.Addr.IsValid() {
		out.Set("X-Forwarded-For", client.Addr.String())
	}
	out.Set("X-Forwarded-Host", in.Host)
	if in.TLS != nil {
		out.Set("X-Forwarded-Proto", "https")
	} else {
		out.Set("X-Forwarded-Proto", "http")
	}
}

// originAddr returns the "ip:port" to report as a forwarded channel's origin:
// the resolved visitor, with the peer's port since a proxy doesn't forward the
// visitor's port.
func originAddr(client clientip.Result, remoteAddr string) string {
	_, port, err := net.SplitHostPort(remoteAddr)
	if err != nil || !client.Addr.IsValid() {
		return remoteAddr
	}
	return net.JoinHostPort(client.Addr.String(), port)
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
	err   error // the first read error other than io.EOF
}

func (l *limitedReadCloser) Read(p []byte) (n int, err error) {
	n, err = l.read1(p)
	if err != nil && err != io.EOF && l.err == nil {
		l.err = err
	}
	return n, err
}

func (l *limitedReadCloser) read1(p []byte) (n int, err error) {
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

// statusCaptureWriter wraps http.ResponseWriter to capture the status code
// and the number of body bytes written.
type statusCaptureWriter struct {
	http.ResponseWriter
	status      int
	bytes       int64
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
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
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
