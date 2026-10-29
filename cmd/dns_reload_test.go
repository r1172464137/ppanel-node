package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"github.com/perfect-panel/ppanel-node/conf"
	"google.golang.org/protobuf/proto"
)

func TestInvalidDNSCandidateNeverAdvancesApplied(t *testing.T) {
	cases := []struct {
		name     string
		resolver panel.DNSItem
	}{
		{"tcp", panel.DNSItem{Proto: "tcp", Address: "1.1.1.1"}},
		{"tls", panel.DNSItem{Proto: "tls", Address: "1.1.1.1"}},
		{"https", panel.DNSItem{Proto: "https", Address: "1.1.1.1"}},
		{"quic", panel.DNSItem{Proto: "quic", Address: "1.1.1.1"}},
		{"server-name", panel.DNSItem{Proto: "udp", Address: "1.1.1.1", ServerName: "dns.example"}},
		{"bad-port", panel.DNSItem{Proto: "udp", Address: "127.0.0.1:0"}},
		{"bad-ipv6", panel.DNSItem{Proto: "udp", Address: "[::1]:65536"}},
	}
	for _, tc := range cases {
		for _, binary := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/proto=%v", tc.name, binary), func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				port := listener.Addr().(*net.TCPAddr).Port
				listener.Close()
				var rev atomic.Int32
				rev.Store(1)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/v1/server/user":
						if binary {
							w.Header().Set("Content-Type", "application/protobuf")
							body, _ := proto.Marshal(&serverv1.GetServerUserListResponse{Code: 200, Data: &serverv1.ServerUserListData{}})
							w.Write(body)
						} else {
							fmt.Fprint(w, `{"code":200,"data":{"users":[]}}`)
						}
					case "/v2/server/7":
						n := rev.Load()
						etag := fmt.Sprintf(`"r%d"`, n)
						w.Header().Set("ETag", etag)
						if r.Header.Get("If-None-Match") == etag {
							w.WriteHeader(http.StatusNotModified)
							return
						}
						var resolvers []panel.DNSItem
						if n == 2 {
							resolvers = []panel.DNSItem{tc.resolver}
						} else if n == 3 {
							resolvers = []panel.DNSItem{{Proto: "udp", Address: "127.0.0.1:5353", Domains: []string{"full:example.com"}}}
						}
						if binary {
							w.Header().Set("Content-Type", "application/protobuf")
							dns := make([]*serverv1.DNSResolver, 0, len(resolvers))
							for _, item := range resolvers {
								dns = append(dns, &serverv1.DNSResolver{Proto: item.Proto, Address: item.Address, ServerName: item.ServerName, Domains: item.Domains})
							}
							message := &serverv1.QueryServerProtocolConfigResponse{Code: 200, Data: &serverv1.QueryServerProtocolConfigData{PushInterval: 3600, PullInterval: 3600, Total: 1, Dns: dns, Protocols: []*serverv1.ServerProtocol{{Type: "vless", Enable: true, Port: uint32(port), Transport: "tcp"}}, Routing: &serverv1.RoutingPolicy{Version: 1, DefaultOutboundId: "direct", Mode: "ordered-v1-inherited", Source: "global", SourceRevision: int64(n)}}}
							body, _ := proto.Marshal(message)
							w.Write(body)
							return
						}
						payload := map[string]any{"code": 200, "data": map[string]any{"pull_interval": 3600, "push_interval": 3600, "dns": resolvers, "protocols": []any{map[string]any{"type": "vless", "enable": true, "port": port, "transport": "tcp"}}, "total": 1, "routing": map[string]any{"version": 1, "outbounds": []any{}, "rules": []any{}, "default_outbound_id": "direct", "mode": "ordered-v1-inherited", "source": "global", "source_revision": n}}}
						_ = json.NewEncoder(w).Encode(payload)
					default:
						fmt.Fprint(w, `{"code":200}`)
					}
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
				assertListener := func() {
					t.Helper()
					conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), time.Second)
					if err != nil {
						t.Fatalf("previous listener unavailable: %v", err)
					}
					conn.Close()
				}
				assertListener()
				rev.Store(2)
				for i := 0; i < 2; i++ {
					_, err := reload(path, &nodes, &x, nil)
					if err == nil || !strings.Contains(err.Error(), "DNS resolver") {
						t.Fatalf("bad DNS attempt %d: %v", i, err)
					}
					if nodes != oldNodes || x != oldCore {
						t.Fatal("bad DNS replaced active core")
					}
					status := client.State.Snapshot()
					if status.Applied == nil || status.Applied.SourceRevision != 1 || status.Pending == nil || status.Pending.SourceRevision != 2 || status.Error == nil || status.Error.Stage != "validate" {
						t.Fatalf("bad DNS receipt: %+v", status)
					}
					if client.ServerConfigEtag != `"r1"` {
						t.Fatal("bad DNS advanced applied ETag")
					}
					assertListener()
				}
				rev.Store(3)
				handle, err := reload(path, &nodes, &x, nil)
				if err != nil {
					t.Fatal(err)
				}
				if handle != nil {
					defer handle.Close()
				}
				status := client.State.Snapshot()
				if status.Applied == nil || status.Applied.SourceRevision != 3 || status.Pending != nil {
					t.Fatalf("corrected DNS not applied: %+v", status)
				}
				assertListener()
			})
		}
	}
}
