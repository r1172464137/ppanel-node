package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core/app/dispatcher"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport/internet"
)

const dataPlaneUUID = "00000000-0000-0000-0000-000000000001"
const dataPlaneOutbound = "ob_11111111-1111-4111-8111-111111111111"
const builtinDirectChild = "PPNODE_BUILTIN_DIRECT_TEST_CHILD"

type fixedDirectDialer struct {
	target     string
	receipts   chan string
	unexpected atomic.Int32
}

func (d *fixedDirectDialer) Dial(network, address string) (net.Conn, error) {
	if network != "tcp" || address != "8.8.8.8:443" {
		d.unexpected.Add(1)
		return nil, fmt.Errorf("unexpected outbound dial")
	}
	d.receipts <- address
	return net.DialTimeout("tcp", d.target, time.Second)
}

// A subprocess installs an isolated controlled dialer *after* Freedom's real
// private-IP check, so the built-in direct outbound is exercised unchanged.
func TestBuiltinDirectThroughRealNodeListener(t *testing.T) {
	if os.Getenv(builtinDirectChild) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestBuiltinDirectThroughRealNodeListener$", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), builtinDirectChild+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("builtin direct subprocess: %v\n%s", err, out)
		}
		return
	}
	var hits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "builtin-direct-receipt") }))
	defer target.Close()
	dialer := &fixedDirectDialer{target: target.Listener.Addr().String(), receipts: make(chan string, 4)}
	internet.UseAlternativeSystemDialer(internet.WithAdapter(dialer))
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenPort := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	payload := fmt.Sprintf(`{"code":200,"data":{"pull_interval":3600,"push_interval":3600,"protocols":[{"type":"vless","enable":true,"port":%d,"transport":"tcp"}],"total":1,"routing":{"version":1,"outbounds":[],"rules":[],"default_outbound_id":"direct","mode":"ordered-v1-inherited","source":"global","source_revision":1}}}`, listenPort)
	panelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/server/7" {
			fmt.Fprint(w, payload)
		} else if r.URL.Path == "/v1/server/user" {
			fmt.Fprintf(w, `{"code":200,"data":{"users":[{"id":1,"uuid":%q}]}}`, dataPlaneUUID)
		} else {
			fmt.Fprint(w, `{"code":200}`)
		}
	}))
	defer panelServer.Close()
	cfg := conf.New()
	cfg.LogConfig.Level = "error"
	cfg.ApiConfig = conf.ServerApiConfig{ApiHost: panelServer.URL, ServerId: 7, Timeout: 2}
	client := panel.NewServerClient(&cfg.ApiConfig)
	nodes, x, _, err := startInitial(context.Background(), cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	defer nodes.Close()
	user, err := (&protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: dataPlaneUUID})}).ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	makeClient := func(dest string, timeout time.Duration) *http.Client {
		transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var nd net.Dialer
			conn, err := nd.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(listenPort)))
			if err != nil {
				return nil, err
			}
			req := &protocol.RequestHeader{Version: 0, Command: protocol.RequestCommandTCP, Address: xnet.ParseAddress(dest), Port: 443, User: user}
			if err := encoding.EncodeRequestHeader(conn, req, &encoding.Addons{}); err != nil {
				conn.Close()
				return nil, err
			}
			return &vlessHTTPConn{Conn: conn, req: req}, nil
		}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: timeout}
	}
	resp, err := makeClient("8.8.8.8", 5*time.Second).Get("https://127.0.0.1/proof")
	if err != nil {
		t.Fatalf("built-in direct HTTPS: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "builtin-direct-receipt" || hits.Load() != 1 {
		t.Fatalf("direct receipt %q %v", body, err)
	}
	select {
	case got := <-dialer.receipts:
		if got != "8.8.8.8:443" {
			t.Fatal(got)
		}
	case <-time.After(time.Second):
		t.Fatal("no direct egress receipt")
	}
	// Built-in Freedom must still block private destinations before dialing.
	if resp, err := makeClient("127.0.0.1", time.Second).Get("https://127.0.0.1/proof"); err == nil {
		resp.Body.Close()
		t.Fatal("private destination unexpectedly allowed")
	}
	if dialer.unexpected.Load() != 0 || hits.Load() != 1 {
		t.Fatal("private target reached dialer or HTTPS target")
	}
}

type vlessHTTPConn struct {
	net.Conn
	req  *protocol.RequestHeader
	once sync.Once
	err  error
}

func (c *vlessHTTPConn) Read(p []byte) (int, error) {
	c.once.Do(func() { _, c.err = encoding.DecodeResponseHeader(c.Conn, c.req) })
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(p)
}

func startHTTPSRelaySOCKS(t *testing.T, upstream string) (int, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	receipts := make(chan string, 4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var hdr [2]byte
				if _, err := io.ReadFull(conn, hdr[:]); err != nil {
					return
				}
				methods := make([]byte, int(hdr[1]))
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				if _, err := conn.Write([]byte{5, 0}); err != nil {
					return
				}
				var req [4]byte
				if _, err := io.ReadFull(conn, req[:]); err != nil || req[1] != 1 {
					return
				}
				var host string
				switch req[3] {
				case 3:
					var n [1]byte
					if _, err := io.ReadFull(conn, n[:]); err != nil {
						return
					}
					b := make([]byte, int(n[0]))
					if _, err := io.ReadFull(conn, b); err != nil {
						return
					}
					host = string(b)
				case 1:
					b := make([]byte, 4)
					if _, err := io.ReadFull(conn, b); err != nil {
						return
					}
					host = net.IP(b).String()
				default:
					return
				}
				var p [2]byte
				if _, err := io.ReadFull(conn, p[:]); err != nil {
					return
				}
				receipts <- fmt.Sprintf("%s:%d", host, binary.BigEndian.Uint16(p[:]))
				remote, err := net.DialTimeout("tcp", upstream, time.Second)
				if err != nil {
					return
				}
				defer remote.Close()
				if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
					return
				}
				go func() { _, _ = io.Copy(remote, conn) }()
				_, _ = io.Copy(conn, remote)
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, receipts
}

// The HTTP client speaks real VLESS to a Node controller's actual listener;
// TLS is verified against a fixed local test CA after ordered routing.
func TestHTTPSClientThroughNodeListenerDirectAndSOCKS(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "node-https-receipt") }))
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	socksPort, receipts := startHTTPSRelaySOCKS(t, target.Listener.Addr().String())
	for _, mode := range []string{"direct", "socks"} {
		t.Run(mode, func(t *testing.T) {
			reservation, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listenPort := reservation.Addr().(*net.TCPAddr).Port
			reservation.Close()
			targetPort := target.Listener.Addr().(*net.TCPAddr).Port
			ob := panel.Outbound{ID: dataPlaneOutbound, Name: "test-connection", Protocol: "socks", Address: "127.0.0.1", Port: socksPort}
			rule := map[string]any{"id": "rr_11111111-1111-4111-8111-111111111111", "enabled": true, "kind": "domain", "values": []string{"probe.example.com"}, "outbound_id": dataPlaneOutbound}
			blockRule := map[string]any{"id": "rr_22222222-2222-4222-8222-222222222222", "enabled": true, "kind": "domain", "values": []string{"suffix:probe.example.com"}, "outbound_id": "block"}
			healthRule := map[string]any{"id": "rr_33333333-3333-4333-8333-333333333333", "enabled": true, "kind": "domain", "values": []string{"health.example.com"}, "outbound_id": dataPlaneOutbound}
			address := xnet.DomainAddress("probe.example.com")
			port := xnet.Port(443)
			if mode == "direct" {
				// Explicit test fixture exception only for this local target's IP and
				// port; the builtin direct/private safety policy is not changed.
				ob = panel.Outbound{ID: dataPlaneOutbound, Name: "scoped-test-direct", Protocol: "direct", Settings: fmt.Sprintf(`{"redirect":"127.0.0.1:%d","finalRules":[{"action":"allow","ip":["127.0.0.1/32"],"port":"%d"}]}`, targetPort, targetPort)}
				address = xnet.ParseAddress("127.0.0.1")
				port = xnet.Port(targetPort)
			}
			payload := map[string]any{"code": 200, "data": map[string]any{"push_interval": 3600, "pull_interval": 3600, "protocols": []any{map[string]any{"type": "vless", "enable": true, "port": listenPort, "transport": "tcp"}}, "total": 1, "routing": map[string]any{"version": 1, "outbounds": []panel.Outbound{ob}, "rules": []any{rule, blockRule, healthRule}, "default_outbound_id": dataPlaneOutbound, "mode": "ordered-v1-inherited", "source": "global", "source_revision": 1}}}
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			var bodyMu sync.RWMutex
			panelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v2/server/7":
					bodyMu.RLock()
					defer bodyMu.RUnlock()
					w.Write(body)
				case "/v1/server/user":
					fmt.Fprintf(w, `{"code":200,"data":{"users":[{"id":1,"uuid":%q}]}}`, dataPlaneUUID)
				default:
					fmt.Fprint(w, `{"code":200}`)
				}
			}))
			defer panelServer.Close()
			cfg := conf.New()
			cfg.LogConfig.Level = "error"
			cfg.ApiConfig = conf.ServerApiConfig{ApiHost: panelServer.URL, ServerId: 7, Timeout: 2}
			client := panel.NewServerClient(&cfg.ApiConfig)
			nodes, x, _, err := startInitial(context.Background(), cfg, client, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { nodes.Close(); _ = x.Close() }()
			trace := make(chan dispatcher.RouteEvent, 16)
			installTrace := func() {
				x.Server.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher).SetRouteEventSink(trace)
			}
			waitRoute := func(ruleID, tag, host string) {
				t.Helper()
				select {
				case event := <-trace:
					if !event.MatchedRule || event.RuleID != ruleID || event.OutboundTag != tag || !strings.Contains(event.Target, host) {
						t.Fatalf("unexpected actual route event: %+v", event)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("actual dispatch event not observed")
				}
			}
			installTrace()
			user, err := (&protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: dataPlaneUUID})}).ToMemoryUser()
			if err != nil {
				t.Fatal(err)
			}
			transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer
				conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(listenPort)))
				if err != nil {
					return nil, err
				}
				req := &protocol.RequestHeader{Version: 0, Command: protocol.RequestCommandTCP, Address: address, Port: port, User: user}
				if err := encoding.EncodeRequestHeader(conn, req, &encoding.Addons{}); err != nil {
					conn.Close()
					return nil, err
				}
				return &vlessHTTPConn{Conn: conn, req: req}, nil
			}}
			defer transport.CloseIdleConnections()
			before := hits.Load()
			response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get("https://probe.example.com/proof")
			if err != nil {
				t.Fatalf("HTTPS through node %s: %v", mode, err)
			}
			got, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(got) != "node-https-receipt" || hits.Load() != before+1 {
				t.Fatalf("HTTPS receipt: %q %v", got, err)
			}
			waitRoute("rr_11111111-1111-4111-8111-111111111111", "routing_"+dataPlaneOutbound, "probe.example.com")
			if mode == "socks" {
				select {
				case got := <-receipts:
					if got != "probe.example.com:443" {
						t.Fatalf("SOCKS destination %q", got)
					}
				case <-time.After(time.Second):
					t.Fatal("no SOCKS receipt")
				}
			}
			// Reverse the same rules and reload the same listener. A Router
			// decision plus absence of target/SOCKS receipts binds the failure
			// to block rather than treating any TLS error as success.
			routingPolicy := payload["data"].(map[string]any)["routing"].(map[string]any)
			routingPolicy["rules"] = []any{blockRule, rule, healthRule}
			routingPolicy["source_revision"] = 2
			next, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			bodyMu.Lock()
			body = next
			bodyMu.Unlock()
			configPath := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(configPath, []byte(fmt.Sprintf("Log:\n  Level: error\nApi:\n  ApiHost: %q\n  ServerID: 7\n  Timeout: 2\n", panelServer.URL)), 0600); err != nil {
				t.Fatal(err)
			}
			h, err := reload(configPath, &nodes, &x, nil)
			if err != nil {
				t.Fatal(err)
			}
			if h != nil {
				defer h.Close()
			}
			if s := client.State.Snapshot(); s.Applied == nil || s.Applied.SourceRevision != 2 {
				t.Fatalf("reversed policy not applied: %+v", s)
			}
			installTrace()
			// After reload, exercise the same listener and outbound first using
			// a health domain that is not covered by the probe-specific block.
			beforeHealth := hits.Load()
			health, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get("https://health.example.com/proof")
			if err != nil {
				t.Fatalf("post-reload health %s: %v", mode, err)
			}
			healthBody, err := io.ReadAll(health.Body)
			health.Body.Close()
			if err != nil || string(healthBody) != "node-https-receipt" || hits.Load() != beforeHealth+1 {
				t.Fatalf("post-reload health receipt: %q %v", healthBody, err)
			}
			waitRoute("rr_33333333-3333-4333-8333-333333333333", "routing_"+dataPlaneOutbound, "health.example.com")
			if mode == "socks" {
				select {
				case got := <-receipts:
					if got != "health.example.com:443" {
						t.Fatalf("health SOCKS receipt %q", got)
					}
				case <-time.After(time.Second):
					t.Fatal("no post-reload SOCKS receipt")
				}
			}
			afterPositive := hits.Load()
			if response, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get("https://probe.example.com/proof"); err == nil {
				response.Body.Close()
				t.Fatal("blocked HTTPS unexpectedly succeeded")
			}
			waitRoute("rr_22222222-2222-4222-8222-222222222222", "block", "probe.example.com")
			if hits.Load() != afterPositive {
				t.Fatal("blocked request reached HTTPS target")
			}
			select {
			case got := <-receipts:
				t.Fatalf("blocked request reached SOCKS: %s", got)
			case <-time.After(200 * time.Millisecond):
			}
		})
	}
}
