package server

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/klipitkas/tunnl.gg/pkg/config"
	"github.com/klipitkas/tunnl.gg/pkg/tunnel"
)

func TestE2E_Inspector(t *testing.T) {
	srv, addr := startSSHServer(t)
	key := newTestKey(t)
	acct := &Account{ID: "acct_pro", Subdomain: "myapp", Limits: config.Limits{Options: config.AllOptions, Inspect: true}}
	withAccounts(srv, []ssh.Signer{key}, []*Account{acct})
	var hits atomic.Int32
	tt := openTunnelCommand(t, srv, addr, accountClient(key), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-App", "yes")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "got "+string(body))
	}), "auth=me:secret")

	insp := srv.GetTunnel("myapp").Inspector()
	if insp == nil {
		t.Fatal("a tunnel with Inspect should keep its requests")
	}
	events, cancel := insp.Subscribe()
	defer cancel()

	post := func(auth string, body string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, tt.public.URL+"/hook?x=1", strings.NewReader(body))
		req.Host = tt.host()
		if auth != "" {
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
		}
		resp, err := tt.public.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp
	}
	post("me:wrong", "")
	post("me:secret", `{"event":"paid"}`)

	list := insp.List()
	if len(list) != 2 {
		t.Fatalf("kept %d exchanges: %+v", len(list), list)
	}
	refused, e := list[0], list[1]
	if refused.Status != http.StatusUnauthorized || !strings.HasPrefix(refused.Note, "answered by tunnl") || refused.RequestHeader.Get("Authorization") != "" {
		t.Errorf("the refused request: %+v", refused)
	}
	if e.Method != "POST" || e.Target != "/hook?x=1" || e.Status != http.StatusCreated || string(e.RequestBody.Data) != `{"event":"paid"}` ||
		string(e.ResponseBody.Data) != `got {"event":"paid"}` || e.ResponseHeader.Get("X-App") != "yes" ||
		e.RequestHeader.Get("X-Forwarded-Host") != tt.host() || e.RequestHeader.Get("Authorization") != "" {
		t.Errorf("the exchange: %+v", e)
	}
	if got := <-events; got.ID != refused.ID {
		t.Errorf("first event = %d, want %d", got.ID, refused.ID)
	}

	// Replaying sends it to the app again
	again, err := srv.GetTunnel("myapp").Replay(context.Background(), e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Replay || again.Status != http.StatusCreated || string(again.ResponseBody.Data) != `got {"event":"paid"}` || hits.Load() != 2 {
		t.Errorf("replay: %+v, app hit %d times", again, hits.Load())
	}
	if _, err := srv.GetTunnel("myapp").Replay(context.Background(), 999); !errors.Is(err, tunnel.ErrGone) {
		t.Errorf("replaying an unknown request: %v", err)
	}

	// Bodies too large to keep can't be replayed
	post("me:secret", strings.Repeat("x", tunnel.MaxInspectedBody+1))
	last := insp.List()[len(insp.List())-1]
	if !last.RequestBody.Truncated || last.RequestBody.Size != tunnel.MaxInspectedBody+1 {
		t.Errorf("large body: %+v", last.RequestBody)
	}
	if _, err := srv.GetTunnel("myapp").Replay(context.Background(), last.ID); !errors.Is(err, tunnel.ErrBodyTruncated) {
		t.Errorf("replaying a truncated body: %v", err)
	}
}

func TestE2E_InspectorOffByDefault(t *testing.T) {
	tt := startTestTunnel(t, echoBackend("hi"))
	tt.get(t, "/")
	if insp := tt.srv.GetTunnel(tt.sub).Inspector(); insp != nil {
		t.Error("anonymous tunnels should keep no requests")
	}
	if _, err := tt.srv.GetTunnel(tt.sub).Replay(context.Background(), 1); !errors.Is(err, tunnel.ErrNotInspected) {
		t.Errorf("Replay() without an inspector: %v", err)
	}
}
