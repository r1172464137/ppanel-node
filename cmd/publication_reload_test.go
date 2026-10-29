package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
)

func TestHostSecretReloadFencesInflightAndWaitingStatus(t *testing.T) {
	oldArrived, release := make(chan panel.ServerPushStatusRequest, 1), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	oldServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("secret_key") != "old-secret" {
			http.Error(w, "forbidden", 403)
			return
		}
		switch r.URL.Path {
		case "/v2/server/7":
			fmt.Fprint(w, `{"code":200,"data":{"protocols":[],"total":0,"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":1}}}`)
		case "/v1/server/status":
			var v panel.ServerPushStatusRequest
			if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
				t.Error(err)
			}
			oldArrived <- v
			<-release
			fmt.Fprint(w, `{"code":200}`)
		}
	}))
	defer func() { unblock(); oldServer.Close() }()
	newReports := make(chan panel.ServerPushStatusRequest, 1)
	newServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("secret_key") != "new-secret" {
			http.Error(w, "forbidden", 403)
			return
		}
		switch r.URL.Path {
		case "/v2/server/7":
			fmt.Fprint(w, `{"code":200,"data":{"protocols":[],"total":0,"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":2}}}`)
		case "/v1/server/status":
			var v panel.ServerPushStatusRequest
			if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
				t.Error(err)
			}
			newReports <- v
			fmt.Fprint(w, `{"code":200}`)
		}
	}))
	defer newServer.Close()
	cfg := conf.New()
	cfg.LogConfig.Level = "error"
	cfg.ApiConfig = conf.ServerApiConfig{ApiHost: oldServer.URL, SecretKey: "old-secret", ServerId: 7, Timeout: 5}
	old := panel.NewServerClient(&cfg.ApiConfig)
	nodes, x, _, err := startInitial(context.Background(), cfg, old, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { nodes.Close(); x.Close() }()
	oldResult := make(chan error, 1)
	go func() { oldResult <- old.ReportServerStatus(context.Background(), &panel.NodeStatus{}) }()
	var first panel.ServerPushStatusRequest
	select {
	case first = <-oldArrived:
	case <-time.After(time.Second):
		t.Fatal("old status did not arrive")
	}
	waitingStarted, waitingResult := make(chan struct{}), make(chan error, 1)
	go func() {
		close(waitingStarted)
		waitingResult <- old.ReportServerStatus(context.Background(), &panel.NodeStatus{})
	}()
	<-waitingStarted
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("Log:\n  Level: error\nApi:\n  ApiHost: %q\n  ServerID: 7\n  SecretKey: new-secret\n  Timeout: 5\n", newServer.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	h, err := reload(path, &nodes, &x, nil)
	if err != nil {
		unblock()
		t.Fatal(err)
	}
	if h != nil {
		defer h.Close()
	}
	if x.Client == old {
		unblock()
		t.Fatal("host/secret change reused client")
	}
	if err := x.Client.ReportServerStatus(context.Background(), &panel.NodeStatus{}); err != nil {
		unblock()
		t.Fatal(err)
	}
	second := <-newReports
	unblock()
	if err := <-oldResult; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waitingResult:
		if !errors.Is(err, panel.ErrRetiredClient) {
			t.Fatalf("old waiting status was not fenced: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("old waiting status stuck")
	}
	if first.InstanceID != second.InstanceID || first.Sequence == 0 || second.Sequence <= first.Sequence || second.Applied == nil || second.Applied.SourceRevision != 2 {
		t.Fatalf("stale publication order: old=%+v new=%+v", first, second)
	}
	if err := old.ReportServerStatus(context.Background(), &panel.NodeStatus{}); !errors.Is(err, panel.ErrRetiredClient) {
		t.Fatalf("old client reported after reload: %v", err)
	}
}
