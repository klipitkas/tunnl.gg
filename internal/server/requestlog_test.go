package server

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

var ansiCodes = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// sessionText is the SSH session output without colors.
func (tt *testTunnel) sessionText() string {
	return ansiCodes.ReplaceAllString(tt.output.String(), "")
}

func TestDescribeProxyError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"none", nil, ""},
		{"app refused", &ssh.OpenChannelError{Reason: ssh.ConnectionFailed, Message: "Connection refused"},
			"your local app didn't accept the connection: connection refused"},
		{"too large", fmt.Errorf("%w: 200 bytes", errResponseTooLarge), "response larger than 128.0 MB, not sent"},
		{"client slow", fmt.Errorf("dial: %w", context.DeadlineExceeded), "your SSH client didn't connect to your local app in time"},
		{"canceled", context.Canceled, "canceled: the visitor left, or no data for 2m"},
		{"other", fmt.Errorf("unexpected EOF"), "couldn't get a response from your local app: unexpected EOF"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeProxyError(tt.err); got != tt.want {
				t.Errorf("describeProxyError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestE2E_SessionBanner(t *testing.T) {
	tt := startTestTunnel(t, http.NotFoundHandler())
	out := tt.sessionText()
	for _, want := range []string{"● Tunnel is live", "URL", "https://" + tt.host(), "Expires", "in 24h, or after 2h without traffic",
		"Press Ctrl+C to stop", "TIME UTC", "METHOD", "PATH", "STATUS"} {
		if !strings.Contains(out, want) {
			t.Errorf("banner missing %q:\n%s", want, out)
		}
	}
}

func TestE2E_RequestLogShowsQueryVisitorAndSize(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	}))
	tt.get(t, "/search?q=tunnel&page=2")

	waitFor(t, "request log line", func() bool { return strings.Contains(tt.sessionText(), "/search?q=tunnel&page=2") })
	line := ""
	for _, l := range strings.Split(tt.sessionText(), "\r\n") {
		if strings.Contains(l, "/search?q=tunnel&page=2") {
			line = l
		}
	}
	for _, want := range []string{"GET", "200", "5 B", "127.0.0.1"} {
		if !strings.Contains(line, want) {
			t.Errorf("log line missing %q: %q", want, line)
		}
	}
}

func TestE2E_RequestLogExplainsFailures(t *testing.T) {
	tt := startTestTunnel(t, http.NotFoundHandler())
	tt.local.Close() // the tunneled app stops

	if resp := tt.get(t, "/down"); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	waitFor(t, "failure explanation", func() bool {
		return strings.Contains(tt.sessionText(), "↳ couldn't get a response from your local app")
	})
}

func TestE2E_RequestLogShowsTunnlEvents(t *testing.T) {
	tt := startTestTunnel(t, http.NotFoundHandler())

	// A browser visit gets the warning page
	req, _ := http.NewRequest(http.MethodGet, tt.public.URL+"/", nil)
	req.Host = tt.host()
	req.Header.Set("User-Agent", "Mozilla/5.0")
	client := tt.public.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	resp.Body.Close()

	// A flooding visitor gets rate limited
	for i := 0; i < 300; i++ {
		if tt.serveDirect("198.51.100.7:4321", nil).Code == http.StatusTooManyRequests {
			break
		}
	}

	waitFor(t, "tunnl events in the request log", func() bool {
		out := tt.sessionText()
		return strings.Contains(out, "browser sent to the warning page") && strings.Contains(out, "rate limited by tunnl")
	})
}

func TestE2E_CtrlCShowsSummary(t *testing.T) {
	tt := startTestTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hi")
	}))
	tt.get(t, "/one")
	tt.get(t, "/two")
	waitFor(t, "both requests logged", func() bool { return strings.Contains(tt.sessionText(), "/two") })

	if _, err := tt.stdin.Write([]byte{0x03}); err != nil { // Ctrl+C
		t.Fatalf("writing Ctrl+C: %v", err)
	}
	waitFor(t, "summary on stop", func() bool {
		return strings.Contains(tt.sessionText(), "Stopped. 2 requests, 4 B served.")
	})
}
