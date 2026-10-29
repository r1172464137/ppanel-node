package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"github.com/perfect-panel/ppanel-node/conf"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// Prove that both wire formats keep the previous running instance and receipt
// when an unusable TUIC outbound or SS inbound plugin is observed and retried.
func TestUnsupportedCapabilityNeverAdvancesApplied(t *testing.T) {
	for _, kind := range []string{"tuic", "shadowsocks-plugin"} {
		for _, binary := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/protobuf=%v", kind, binary), func(t *testing.T) {
				var revision atomic.Int32
				revision.Store(1)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/v2/server/7" {
						fmt.Fprint(w, `{"code":200}`)
						return
					}
					rev := revision.Load()
					etag := fmt.Sprintf(`"%d"`, rev)
					w.Header().Set("ETag", etag)
					if r.Header.Get("If-None-Match") == etag {
						w.WriteHeader(304)
						return
					}
					if binary {
						w.Header().Set("Content-Type", "application/protobuf")
						policy := &serverv1.RoutingPolicy{Version: 1, DefaultOutboundId: "direct", Mode: "ordered-v1-inherited", Source: "global", SourceRevision: int64(rev)}
						data := &serverv1.QueryServerProtocolConfigData{Routing: policy, PullInterval: 3600, PushInterval: 3600}
						if rev == 2 && kind == "tuic" {
							policy.Outbounds = []*serverv1.Outbound{{Id: "ob_11111111-1111-4111-8111-111111111111", Name: "tuic", Protocol: "tuic", Address: "127.0.0.1", Port: 443, Uuid: "00000000-0000-0000-0000-000000000001", Password: "password", Settings: `{"address":"127.0.0.1","port":443}`}}
						}
						if rev == 2 && kind == "shadowsocks-plugin" {
							opts, _ := structpb.NewValue(map[string]any{"mode": "http"})
							data.Protocols = []*serverv1.ServerProtocol{{Type: "shadowsocks", Enable: true, Port: 443, Cipher: "aes-128-gcm", Plugin: "obfs", PluginOptions: opts}}
						}
						data.Total = int64(len(data.Protocols))
						body, _ := proto.Marshal(&serverv1.QueryServerProtocolConfigResponse{Code: 200, Data: data})
						w.Write(body)
						return
					}
					outbounds := []any{}
					protocols := []any{}
					if rev == 2 && kind == "tuic" {
						outbounds = append(outbounds, map[string]any{"id": "ob_11111111-1111-4111-8111-111111111111", "name": "tuic", "protocol": "tuic", "address": "127.0.0.1", "port": 443, "uuid": "00000000-0000-0000-0000-000000000001", "password": "password", "settings": `{"address":"127.0.0.1","port":443}`})
					}
					if rev == 2 && kind == "shadowsocks-plugin" {
						protocols = append(protocols, map[string]any{"type": "shadowsocks", "enable": true, "port": 443, "cipher": "aes-128-gcm", "plugin": "obfs", "plugin_opts": map[string]any{"mode": "http"}})
					}
					json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": map[string]any{"protocols": protocols, "total": len(protocols), "pull_interval": 3600, "push_interval": 3600, "routing": map[string]any{"version": 1, "outbounds": outbounds, "rules": []any{}, "default_outbound_id": "direct", "mode": "ordered-v1-inherited", "source": "global", "source_revision": rev}}})
				}))
				defer server.Close()
				cfg := conf.New()
				cfg.LogConfig.Level = "error"
				cfg.ApiConfig = conf.ServerApiConfig{ApiHost: server.URL, ServerId: 7, Timeout: 2}
				path := filepath.Join(t.TempDir(), "config.yml")
				if err := os.WriteFile(path, []byte(fmt.Sprintf("Log:\n  Level: error\nApi:\n  ApiHost: %q\n  ServerID: 7\n  Timeout: 2\n", server.URL)), 0600); err != nil {
					t.Fatal(err)
				}
				client := panel.NewServerClient(&cfg.ApiConfig)
				nodes, x, _, err := startInitial(context.Background(), cfg, client, make(chan struct{}, 1))
				if err != nil {
					t.Fatal(err)
				}
				defer func() { nodes.Close(); x.Close() }()
				oldNodes, oldCore := nodes, x
				revision.Store(2)
				for i := 0; i < 2; i++ {
					_, err := reload(path, &nodes, &x, nil)
					if err == nil {
						t.Fatal("unusable candidate was applied")
					}
					if kind == "tuic" && !strings.Contains(err.Error(), "TUIC") {
						t.Fatalf("wrong error: %v", err)
					}
					if kind == "shadowsocks-plugin" && !strings.Contains(err.Error(), "plugin") {
						t.Fatalf("wrong error: %v", err)
					}
					if nodes != oldNodes || x != oldCore {
						t.Fatal("failed candidate displaced active core")
					}
					state := client.State.Snapshot()
					if state.Applied == nil || state.Applied.SourceRevision != 1 || state.Pending == nil || state.Pending.SourceRevision != 2 || state.Error == nil || state.Error.Stage != "validate" {
						t.Fatalf("bad receipt: %+v", state)
					}
				}
			})
		}
	}
}
