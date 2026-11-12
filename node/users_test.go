package node

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core"
)

func TestUserSyncRevokesLastUserAndAllowsEmptyStartup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":200}`)
	}))
	defer server.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	protocols := []panel.Protocol{{Type: "vless", Enable: true, Port: port, Transport: "tcp"}}
	user := panel.IdentityUser{ID: 1, UUID: "00000000-0000-0000-0000-000000000001", AccountID: 1}
	config := completeV3(&panel.ServerConfigResponse{Data: &panel.Data{Protocols: &protocols, Total: len(protocols), PullInterval: 3600, PushInterval: 3600, Routing: testNodeRouting()}}, map[string][]panel.IdentityUser{"vless": {user}})
	cfg := conf.New()
	cfg.ApiConfig.ApiHost = server.URL
	xcore := core.New(cfg, panel.NewServerClient(&cfg.ApiConfig))
	if err := xcore.Start(config); err != nil {
		t.Fatal(err)
	}
	defer xcore.Close()
	n, err := New(xcore, cfg, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	c := n.controllers[0]
	manager, err := xcore.GetUserManager(c.tag)
	if err != nil {
		t.Fatal(err)
	}
	if manager.GetUsersCount(context.Background()) != 1 {
		t.Fatal("initial user missing")
	}
	// The next candidate's identity snapshot has no user: applying it in
	// place revokes the last user.
	empty := completeV3(&panel.ServerConfigResponse{Data: &panel.Data{Protocols: &protocols, Total: len(protocols), PullInterval: 3600, PushInterval: 3600, Routing: testNodeRouting()}}, nil)
	if err := n.ApplyIdentity(empty.Data); err != nil {
		t.Fatal(err)
	}
	if manager.GetUsersCount(context.Background()) != 0 {
		t.Fatal("last user was not revoked")
	}
	n.Close()
	next, err := New(xcore, cfg, empty)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err := next.Start(); err != nil {
		t.Fatalf("empty startup: %v", err)
	}
}
