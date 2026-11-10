package node

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core"
)

func TestV1UserMonitorWaitsForLiveCoreGate(t *testing.T) {
	var fetched atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fetched.Load() {
			w.Header().Set("ETag", "candidate")
			fmt.Fprint(w, `{"code":200,"data":{"users":[{"id":2,"uuid":"00000000-0000-0000-0000-000000000002"}]}}`)
			return
		}
		w.Header().Set("ETag", "initial")
		fmt.Fprint(w, `{"code":200,"data":{"users":[{"id":1,"uuid":"00000000-0000-0000-0000-000000000001"}]}}`)
	}))
	defer server.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
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
	manager, err := x.GetUserManager(c.tag)
	if err != nil {
		t.Fatal(err)
	}

	if err := x.LockLive(context.Background()); err != nil {
		t.Fatal(err)
	}
	fetched.Store(true)
	done := make(chan error, 1)
	go func() { done <- c.userListMonitor(context.Background()) }()
	time.Sleep(100 * time.Millisecond)
	if got := manager.GetUsersCount(context.Background()); got != 1 {
		x.UnlockLive()
		t.Fatalf("user monitor mutated the live core while the reload gate was held: %d users", got)
	}
	select {
	case err := <-done:
		x.UnlockLive()
		t.Fatalf("user monitor returned before the live gate was released: %v", err)
	default:
	}
	x.UnlockLive()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("user monitor did not resume after the gate was released")
	}
	if got := manager.GetUsersCount(context.Background()); got != 1 {
		t.Fatalf("candidate user count = %d", got)
	}
	if manager.GetUser(context.Background(), c.tag+"|00000000-0000-0000-0000-000000000001") != nil {
		t.Fatal("old user survived the serialized update")
	}
	if manager.GetUser(context.Background(), c.tag+"|00000000-0000-0000-0000-000000000002") == nil {
		t.Fatal("candidate user was not applied after the gate was released")
	}
}
