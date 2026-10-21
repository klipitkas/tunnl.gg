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
	"net/netip"
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
	s.metrics.countRequest(r)
	// Enforce request body size limit
	if r.ContentLength > config.MaxRequestBodySize {
		s.metrics.answer(answerTooLarge)
		localError(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = http.MaxBytesReader(w, r.Body, config.MaxRequestBodySize)
	}

	host := strings.ToLower(stripPort(r.Host))
	domain := strings.ToLower(s.domain)

	if !strings.HasSuffix(host, "."+domain) {
		s.metrics.answer(answerBadHost)
		localError(w, "Bad Request", http.StatusBadRequest)
		return
	}

	sub := strings.TrimSuffix(host, "."+domain)

	if !subdomain.IsLabel(sub) {
		s.metrics.answer(answerBadHost)
		localError(w, "Bad Request", http.StatusBadRequest)
		return
	}

	tun := s.GetTunnel(sub)
	if tun == nil {
		s.metrics.answer(answerNoTunnel)
		localError(w, "Not Found", http.StatusNotFound)
		return
	}

	// The client sends its options just after the tunnel opens; until then
	// it's unknown who may get in
	opts, ok := tun.OptionsWithin(r.Context(), optionsWaitTimeout)
	if !ok {
		s.metrics.answer(answerNoOptions)
		localError(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	client := s.clientIPs.Resolve(r.RemoteAddr, r.Header)
	// Before rate limiting, so visitors who aren't allowed can't use up the
	// tunnel's budget
	if !opts.Allows(client.Addr) {
		s.logTunnlEvent(tun, r, client, http.StatusForbidden, answerAllowlist, "not on the tunnel's allowlist")
		localError(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Throttle only the visitor: the tunnel owner doesn't control who sends
	// traffic to their URL, so exceeding the limit must not affect the tunnel.
	visitorIP := client.Addr.String()
	visitor := visitorIP
	if client.Addr.Is6() {
		visitor = visitorKeyAddr(client.Addr)
	}
	if !tun.AllowRequest(visitor) {
		s.logTunnlEvent(tun, r, client, http.StatusTooManyRequests, answerRateLimited, "rate limited by tunnl")
		w.Header().Set("Retry-After", "1")
		localError(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	defer tun.BeginRequest().End()
	s.IncrementRequests()

	// CORS preflights carry no credentials, so they're answered before the
	// password check; otherwise a protected tunnel could never be called
	// from another site. The allowlist and rate limits still apply.
	corsAllow, corsCredentials := opts.CORSOrigin(r.Header.Get("Origin"))
	if corsAllow != "" && r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
		h := w.Header()
		setCORS(h, corsAllow, corsCredentials)
		h.Set("Access-Control-Allow-Methods", r.Header.Get("Access-Control-Request-Method"))
		if requested := r.Header.Get("Access-Control-Request-Headers"); requested != "" {
			h.Set("Access-Control-Allow-Headers", requested)
		}
		h.Set("Access-Control-Max-Age", "600")
		s.logTunnlEvent(tun, r, client, http.StatusNoContent, answerPreflight, "CORS preflight answered")
		setSecurityHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// For the answers tunnl gives itself below, so the page can read them
	setCORS(w.Header(), corsAllow, corsCredentials)

	// After rate limiting, which slows down password guessing
	if opts.Auth != nil {
		if !tun.PasswordTriesLeft(visitor) {
			s.logTunnlEvent(tun, r, client, http.StatusTooManyRequests, answerPasswordTries, "too many wrong passwords (tunnl limit)")
			w.Header().Set("Retry-After", "10")
			localError(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		if !opts.Auth.Check(r) {
			// Browsers ask without credentials first: only guesses count
			if _, _, sent := r.BasicAuth(); sent {
				tun.PasswordFailed(visitor)
			}
			s.logTunnlEvent(tun, r, client, http.StatusUnauthorized, answerPassword, "no or wrong password")
			w.Header().Set("WWW-Authenticate", `Basic realm="`+sub+"."+s.domain+`", charset="UTF-8"`)
			localError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// The tunnel's password is not for the app
		r.Header.Del("Authorization")
	}

	// Show interstitial warning for browser requests
	if tun.Limits.BrowserWarning && isBrowserRequest(r) &&
		r.Header.Get("tunnl-skip-browser-warning") == "" &&
		!hasWarningCookie(r, sub) {
		s.logTunnlEvent(tun, r, client, http.StatusTemporaryRedirect, answerWarningPage, "browser sent to the warning page")
		s.redirectToWarningPage(w, r, sub)
		return
	}

	if isWebSocketRequest(r) {
		// Upgraded connections are long-lived, so cap how many are open at once
		if !s.wsPerVisitor.acquire(visitor) {
			s.logTunnlEvent(tun, r, client, http.StatusTooManyRequests, answerVisitorWebSockets, "too many open WebSockets from this visitor (tunnl limit)")
			localError(w, "Too Many WebSocket Connections", http.StatusTooManyRequests)
			return
		}
		defer s.wsPerVisitor.release(visitor)
		if !s.wsPerTunnel.acquire(sub) {
			s.logTunnlEvent(tun, r, client, http.StatusTooManyRequests, answerTunnelWebSockets, "too many open WebSockets on this tunnel (tunnl limit)")
			localError(w, "Too Many WebSocket Connections", http.StatusTooManyRequests)
			return
		}
		defer s.wsPerTunnel.release(sub)

		setSecurityHeaders(w)
		s.handleWebSocket(w, r, tun, sub, client, opts)
		return
	}

	// Proxied requests can stay open for minutes, for example when a tunnel's
	// app never responds, so cap how many are in flight
	if !s.reqPerVisitor.acquire(visitor) {
		s.logTunnlEvent(tun, r, client, http.StatusTooManyRequests, answerVisitorRequests, "too many open requests from this visitor (tunnl limit)")
		w.Header().Set("Retry-After", "1")
		localError(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}
	defer s.reqPerVisitor.release(visitor)
	if !s.reqPerTunnel.acquire(sub) {
		s.logTunnlEvent(tun, r, client, http.StatusServiceUnavailable, answerTunnelRequests, "too many open requests on this tunnel (tunnl limit)")
		w.Header().Set("Retry-After", "1")
		localError(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	defer s.reqPerTunnel.release(sub)

	requestStart := time.Now()
	target := r.URL.RequestURI()
	// The inspector keeps what the app was sent and what it answered
	insp := tun.Inspector()
	var reqBody *tunnel.Capture
	// The proxy callbacks and deferred accounting share a request lifetime.
	// Keep their mutable state in one allocation. None of it is pooled or
	// reused by another request.
	var state struct {
		respBody              *tunnel.Capture
		outHost               string
		outHeader, respHeader http.Header
		proxyErr              error
		body                  *limitedReadCloser // the response body, once the app responds
	}
	if insp != nil && r.Body != nil && r.Body != http.NoBody {
		reqBody = tunnel.NewCapture(r.Body)
		r.Body = reqBody
	}
	var in *countingReader
	if r.Body != nil && r.Body != http.NoBody {
		in = &countingReader{ReadCloser: r.Body}
		r.Body = in
	}
	ctx := tunnel.WithOrigin(r.Context(), originAddr(client.Addr, visitorIP, r.RemoteAddr))
	dw, r := newProxyDeadlines(ctx, w, r, config.ProxyIdleTimeout)
	defer dw.stop()
	sw := &statusCaptureWriter{ResponseWriter: dw}

	// The tunneled app decides its own response headers; CORS ones are added
	// back if it sets none
	for name := range securityHeaders {
		w.Header().Del(name)
	}
	for _, name := range corsHeaders {
		w.Header().Del(name)
	}

	proxy := &httputil.ReverseProxy{
		BufferPool: &responseBuffers,
		Rewrite: func(pr *httputil.ProxyRequest) {
			// The tunnel's transport sends every request over SSH, so the
			// URL host only needs to be valid
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = pr.In.Host
			pr.Out.Host = pr.In.Host
			if opts.Host != "" {
				pr.Out.Host = opts.Host
			}
			setForwardedHeaders(pr.Out.Header, pr.In, client, visitorIP)
			if insp != nil {
				state.outHost, state.outHeader = pr.Out.Host, pr.Out.Header.Clone()
			}
		},
		Transport: tun.Transport(),
		ModifyResponse: func(resp *http.Response) error {
			s.metrics.headersTime.observe(latencyBuckets, int64(time.Since(requestStart)))
			for name, value := range proxiedDefaultHeaders {
				if resp.Header.Get(name) == "" {
					resp.Header.Set(name, value)
				}
			}
			resp.Header.Set(robotsHeader, robotsNoIndex)
			setCORS(resp.Header, corsAllow, corsCredentials)

			// Enforce response body size limit
			if resp.ContentLength > config.MaxResponseBodySize {
				return fmt.Errorf("%w: %d bytes (max %d)", errResponseTooLarge, resp.ContentLength, config.MaxResponseBodySize)
			}
			// Wrap body with size limiter for chunked/unknown-length responses
			state.body = &limitedReadCloser{
				rc:    resp.Body,
				limit: config.MaxResponseBodySize,
			}
			resp.Body = state.body
			if insp != nil {
				state.respHeader = resp.Header.Clone()
				state.respBody = tunnel.NewCapture(resp.Body)
				resp.Body = state.respBody
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error for %s: %v", sub, err)
			state.proxyErr = err
			setSecurityHeaders(w)
			setCORS(w.Header(), corsAllow, corsCredentials)
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
		detail := describeProxyError(state.proxyErr)
		if p != nil {
			detail = describeCutOff(state.body)
		}
		logEntry(tun, tunnel.Entry{
			Time:    requestStart,
			Method:  r.Method,
			Target:  target,
			Status:  sw.status,
			Bytes:   sw.bytes,
			Latency: time.Since(requestStart),
			Visitor: visitorIP,
			Detail:  detail,
		})
		status := sw.status
		if p != nil && status == 0 {
			status = http.StatusBadGateway
		}
		var uploaded int64
		if in != nil {
			uploaded = in.n
		}
		tun.CountRequest(status, uploaded, sw.bytes, time.Since(requestStart))
		s.metrics.requestDone(requestResult(sw.status, state.proxyErr, p != nil), time.Since(requestStart), uploaded, sw.bytes)
		if insp != nil {
			insp.Add(tunnel.Exchange{
				Time:           requestStart,
				Method:         r.Method,
				Target:         target,
				Host:           state.outHost,
				Visitor:        visitorIP,
				RequestHeader:  state.outHeader,
				RequestBody:    reqBody.TakeBody(),
				Status:         sw.status,
				ResponseHeader: state.respHeader,
				ResponseBody:   state.respBody.TakeBody(),
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

// logTunnlEvent logs a request that tunnl answered itself, without the app,
// counting it under why (an answer* constant).
func (s *Server) logTunnlEvent(tun *tunnel.Tunnel, r *http.Request, client clientip.Result, status, why int, note string) {
	s.metrics.answer(why)
	tun.CountRequest(status, -1, -1, 0)
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
			FromTunnl:     true,
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
	if err == nil {
		return ""
	}
	var openErr *ssh.OpenChannelError
	switch {
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
	case errors.Is(err, tunnel.ErrUnresponsive):
		return "your SSH client stopped answering, so requests fail at once until it answers again"
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

	backendConn, err := tun.Dial(tunnel.WithOrigin(r.Context(), originAddr(client.Addr, wsEntry.Visitor, r.RemoteAddr)))
	if err != nil {
		s.metrics.wsDialFailed.Add(1)
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
	setForwardedHeaders(r.Header, r, client, wsEntry.Visitor)
	if opts.Host != "" {
		r.Host = opts.Host
	}
	if err := r.Write(backendConn); err != nil {
		log.Printf("WebSocket request write error for %s: %v", sub, err)
		return
	}

	s.metrics.wsRelayed.Add(1)
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

	tun.CountRequest(http.StatusSwitchingProtocols, backendBytes, clientBytes, time.Since(wsEntry.Time))
	s.metrics.websocketDone(time.Since(wsEntry.Time), backendBytes+clientBytes)
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
	buf := responseBuffers.Get()
	defer responseBuffers.Put(buf)
	var written int64
	for {
		src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, readErr := src.Read(buf)
		if n > 0 {
			if int64(n) > maxBytes-written {
				return written, fmt.Errorf("transfer limit exceeded")
			}
			dst.SetWriteDeadline(time.Now().Add(idleTimeout))
			nw, writeErr := dst.Write(buf[:n])
			written += int64(nw)
			if writeErr != nil {
				return written, writeErr
			}
			if nw != n {
				return written, io.ErrShortWrite
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
	robotsHeader:             robotsNoIndex,
}

// Tunnels are someone's computer for a while, not websites: search engines
// mustn't index them, which would also make phishing pages findable. Every
// response says so, the app's included, whatever the app sends.
const (
	robotsHeader  = "X-Robots-Tag"
	robotsNoIndex = "noindex, nofollow"
)

// proxiedDefaultHeaders are added to proxied responses only when the tunneled
// app doesn't set them. Framing is left to the app, so it can be embedded.
var proxiedDefaultHeaders = map[string]string{
	"X-Content-Type-Options": "nosniff",
	"Referrer-Policy":        "strict-origin-when-cross-origin",
}

// corsHeaders are the headers setCORS sets.
var corsHeaders = []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"}

// setCORS lets the page on an allowed origin read the response, unless the
// app answered with its own CORS headers.
func setCORS(h http.Header, allow string, credentials bool) {
	if allow == "" || h.Get("Access-Control-Allow-Origin") != "" {
		return
	}
	h.Set("Access-Control-Allow-Origin", allow)
	if allow != "*" {
		h.Add("Vary", "Origin")
	}
	if credentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
}

func localError(w http.ResponseWriter, message string, status int) {
	setSecurityHeaders(w)
	http.Error(w, message, status)
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
	setSecurityHeaders(w)
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
func setForwardedHeaders(out http.Header, in *http.Request, client clientip.Result, visitorIP string) {
	out.Del("Forwarded")
	out.Del("X-Forwarded-For")
	out.Del("X-Forwarded-Host")
	out.Del("X-Forwarded-Proto")
	if !client.ViaCloudflare {
		out.Del("Cf-Connecting-Ip")
	}

	if client.Addr.IsValid() {
		out.Set("X-Forwarded-For", visitorIP)
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
func originAddr(addr netip.Addr, visitorIP, remoteAddr string) string {
	_, port, err := net.SplitHostPort(remoteAddr)
	if err != nil || !addr.IsValid() {
		return remoteAddr
	}
	return net.JoinHostPort(visitorIP, port)
}

// visitorKeyAddr avoids reparsing an already resolved visitor address.
func visitorKeyAddr(addr netip.Addr) string {
	addr = addr.Unmap()
	if addr.Is6() && addr.Zone() == "" {
		// Format directly into stack storage to avoid an intermediate IP string.
		// An unzoned IPv6 address plus "/64" fits in 42 bytes.
		var buf [42]byte
		return string(netip.PrefixFrom(addr, 64).Masked().AppendTo(buf[:0]))
	}
	return addr.String()
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
	if !strings.ContainsRune(host, ':') {
		return host
	}
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

// countingReader counts what's read from a request body.
type countingReader struct {
	io.ReadCloser
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n += int64(n)
	return n, err
}
