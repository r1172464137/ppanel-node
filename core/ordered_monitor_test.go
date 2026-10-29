package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
)

func TestPreparedCoreStartsMonitorOnlyAfterActivation(t *testing.T) {
	cfg := &panel.ServerConfigResponse{Data: &panel.Data{Protocols: &[]panel.Protocol{}, PullInterval: 3600, Routing: emptyTestRouting()}}
	x := New(conf.New(), nil)
	if err := x.StartPrepared(cfg); err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if x.serverConfigMonitorPeriodic != nil {
		t.Fatal("uncommitted core started its monitor")
	}
	if err := x.Activate(cfg); err != nil {
		t.Fatal(err)
	}
	if x.serverConfigMonitorPeriodic == nil {
		t.Fatal("committed core did not start its monitor")
	}
	first := x.serverConfigMonitorPeriodic
	if err := x.Activate(cfg); err != nil {
		t.Fatal(err)
	}
	if x.serverConfigMonitorPeriodic != first {
		t.Fatal("duplicate monitor started")
	}
}

func TestRequiredMonitorFailurePreventsActivation(t *testing.T) {
	cfg := orderedConfig([]panel.RouteRule{}, nil)
	x := New(conf.New(), nil)
	if err := x.StartPrepared(cfg); err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	cfg.Data.PullInterval = 86401
	if err := x.Activate(cfg); err == nil {
		t.Fatal("invalid monitor interval was ignored")
	}
	if x.serverConfigMonitorPeriodic != nil {
		t.Fatal("failed monitor was marked active")
	}
}

func TestMonitorCoalescesUnchangedPendingButNotReplacement(t *testing.T) {
	var mu sync.Mutex
	revision := 1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n := revision
		mu.Unlock()
		etag := fmt.Sprintf(`"%d"`, n)
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(304)
			return
		}
		fmt.Fprintf(w, `{"code":200,"data":{"protocols":[],"total":0,"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":%d}}}`, n)
	}))
	defer server.Close()
	client := panel.NewServerClient(&conf.ServerApiConfig{ApiHost: server.URL, ServerId: 7})
	first, err := panel.GetServerConfig(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	client.Commit(first)
	core := New(conf.New(), client)
	core.ReloadCh = make(chan struct{}, 1)
	mu.Lock()
	revision = 2
	mu.Unlock()
	if err := core.ServerConfigMonitor(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-core.ReloadCh:
	default:
		t.Fatal("new candidate did not signal")
	}
	for i := 0; i < 3; i++ {
		if err := core.ServerConfigMonitor(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-core.ReloadCh:
		t.Fatal("same 304 candidate defeated retry backoff")
	default:
	}
	mu.Lock()
	revision = 3
	mu.Unlock()
	if err := core.ServerConfigMonitor(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-core.ReloadCh:
	default:
		t.Fatal("replacement candidate did not signal")
	}
}
