package node

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core"
)

func TestV2SnapshotDeviceAdmissionAndOfflineCount(t *testing.T) {
	var unexpected, claims atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/server/device":
			var req struct {
				UID int    `json:"uid"`
				IP  string `json:"ip"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UID != 42 || req.IP != "127.0.0.1" {
				t.Errorf("bad claim: %+v %v", req, err)
			}
			claims.Add(1)
			fmt.Fprint(w, `{"allowed":true,"ttl_seconds":300}`)
		case "/v1/server/online":
			fmt.Fprint(w, `{"code":200}`)
		case "/v1/server/user", "/v1/server/alivelist":
			unexpected.Add(1)
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		default:
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
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
	routing := testNodeRouting()
	routing.Version = 2
	routing.Mode = "ordered-v2-inherited"
	routing.UserDefaults = []panel.UserDefault{}
	uuid := "00000000-0000-0000-0000-000000000001"
	snapshot := &panel.IdentitySnapshot{SnapshotID: strings.Repeat("a", 64), Protocols: []panel.ProtocolUserSnapshot{{Protocol: "vless", Users: []panel.UserInfo{{Id: 42, Uuid: uuid, AccountID: 7, DeviceLimit: 1}}}}}
	config := &panel.ServerConfigResponse{Data: &panel.Data{Protocols: &protocols, Total: 1, PullInterval: 3600, PushInterval: 3600, Routing: routing, IdentitySnapshot: snapshot}}
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
	defer n.Close()
	if err = n.Start(); err != nil {
		t.Fatalf("snapshot startup must not depend on count endpoint: %v", err)
	}
	c := n.controllers[0]
	if c.userListMonitorPeriodic != nil || c.onlinePeriodic == nil {
		t.Fatal("v2 tasks do not match snapshot/heartbeat contract")
	}
	_, release, rejected := c.limiter.Acquire(t.Context(), format.UserTag(c.tag, uuid), "127.0.0.1")
	if rejected || claims.Load() != 1 {
		t.Fatalf("snapshot identity was not admitted via device endpoint: rejected=%v claims=%d", rejected, claims.Load())
	}
	release()
	if err = c.reportOnline(t.Context()); err != nil {
		t.Fatal(err)
	}
	if unexpected.Load() != 0 {
		t.Fatalf("startup made %d unexpected user/count requests", unexpected.Load())
	}
}
