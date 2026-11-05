package node

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core"
)

func TestUserRestoreRemoveFailureStopsCore(t *testing.T) {
	panelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"users":[{"id":1,"uuid":"00000000-0000-0000-0000-000000000001"}]}`)
	}))
	defer panelServer.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	protocols := []panel.Protocol{{Type: "vless", Enable: true, Port: port, Transport: "tcp"}}
	config := &panel.ServerConfigResponse{Data: &panel.Data{Protocols: &protocols, Total: 1, PullInterval: 3600, PushInterval: 3600, Routing: testNodeRouting()}}
	cfg := conf.New()
	cfg.ApiConfig.ApiHost = panelServer.URL
	x := core.New(cfg, nil)
	x.ReloadCh = make(chan struct{}, 1)
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
	address := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("positive control: %v", err)
	}
	conn.Close()
	c := n.controllers[0]
	c.removeInbound = func(string) error { return errors.New("injected remove failure") }
	c.restoreUsersAfterFailure()
	if !x.FailedClosed() {
		t.Fatal("core not marked failed")
	}
	if conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("listener still accepting after remove failure")
	}
	select {
	case <-x.ReloadCh:
	default:
		t.Fatal("reload not requested")
	}
	if err := n.Stop(); err != nil {
		t.Fatalf("stop failed closed core: %v", err)
	}
	if err := n.Start(); err == nil {
		t.Fatal("failed closed core restarted")
	}
}
