package node

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core"
)

func TestFailedPartialUserUpdateRestoresAndRetries(t *testing.T) {
	var phase atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/server/alivelist" {
			fmt.Fprint(w, `{"alive":{}}`)
			return
		}
		if phase.Load() == 0 {
			w.Header().Set("ETag", "old")
			fmt.Fprint(w, `{"users":[{"id":1,"uuid":"00000000-0000-0000-0000-000000000001"}]}`)
			return
		}
		if r.Header.Get("If-None-Match") != "old" {
			t.Errorf("failed candidate was committed: %q", r.Header.Get("If-None-Match"))
		}
		w.Header().Set("ETag", "candidate")
		if phase.Load() == 1 {
			fmt.Fprint(w, `{"users":[{"id":2,"uuid":"00000000-0000-0000-0000-000000000002"},{"id":3,"uuid":"zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"}]}`)
		} else {
			fmt.Fprint(w, `{"users":[{"id":2,"uuid":"00000000-0000-0000-0000-000000000002"}]}`)
		}
	}))
	defer server.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	protocols := []panel.Protocol{{Type: "vless", Enable: true, Port: port, Transport: "tcp"}}
	config := &panel.ServerConfigResponse{Data: &panel.Data{Protocols: &protocols, Total: 1, PullInterval: 3600, PushInterval: 3600, Routing: testNodeRouting()}}
	cfg := conf.New()
	cfg.ApiConfig.ApiHost = server.URL
	x := core.New(cfg, panel.NewServerClient(&cfg.ApiConfig))
	if err := x.Start(config); err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	n, err := New(x, cfg, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	c := n.controllers[0]
	phase.Store(1)
	_ = c.userListMonitor(context.Background())
	m, err := x.GetUserManager(c.tag)
	if err != nil {
		t.Fatal(err)
	}
	if m.GetUsersCount(context.Background()) != 1 || m.GetUser(context.Background(), c.tag+"|00000000-0000-0000-0000-000000000001") == nil {
		t.Fatal("old user not restored")
	}
	phase.Store(2)
	_ = c.userListMonitor(context.Background())
	m, err = x.GetUserManager(c.tag)
	if err != nil {
		t.Fatal(err)
	}
	if m.GetUsersCount(context.Background()) != 1 || m.GetUser(context.Background(), c.tag+"|00000000-0000-0000-0000-000000000002") == nil {
		t.Fatal("candidate did not retry")
	}
}
