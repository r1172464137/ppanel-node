package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
)

func TestV2RealListenerGlobalDeviceAdmission(t *testing.T) {
	var hits, claims, userPoll atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "device-ok") }))
	defer target.Close()
	socksPort, _ := startHTTPSRelaySOCKS(t, target.Listener.Addr().String())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	var mu sync.Mutex
	admitted := map[int]string{}
	var bodyMu sync.RWMutex
	ob := panel.Outbound{ID: dataPlaneOutbound, Name: "device-socks", Protocol: "socks", Address: "127.0.0.1", Port: socksPort}
	payload := map[string]any{"code": 200, "data": map[string]any{"push_interval": 3600, "pull_interval": 3600, "protocols": []any{map[string]any{"type": "vless", "enable": true, "port": port, "transport": "tcp"}}, "total": 1, "routing": map[string]any{"version": 2, "outbounds": []panel.Outbound{ob}, "rules": []any{}, "default_outbound_id": dataPlaneOutbound, "user_defaults": []any{}, "mode": "ordered-v2-inherited", "source": "global", "source_revision": 1}, "identity_snapshot": map[string]any{"snapshot_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "protocols": []any{map[string]any{"protocol": "vless", "users": []any{map[string]any{"id": 42, "uuid": dataPlaneUUID, "account_id": 7, "device_limit": 1}}}}}}}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	panelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/server/7":
			bodyMu.RLock()
			defer bodyMu.RUnlock()
			w.Write(body)
		case "/v1/server/user":
			userPoll.Add(1)
			http.Error(w, "unexpected", 500)
		case "/v1/server/device":
			var req struct {
				UID int    `json:"uid"`
				IP  string `json:"ip"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.UID != 42 && req.UID != 43) {
				t.Errorf("bad claim %+v: %v", req, err)
				http.Error(w, "bad", 400)
				return
			}
			claims.Add(1)
			mu.Lock()
			if admitted[req.UID] == "" {
				admitted[req.UID] = req.IP
			}
			allowed := admitted[req.UID] == req.IP
			mu.Unlock()
			fmt.Fprintf(w, `{"allowed":%t,"ttl_seconds":300}`, allowed)
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
	user, err := (&protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: dataPlaneUUID})}).ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	request := func(source string) error {
		tr := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
			conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				return nil, err
			}
			req := &protocol.RequestHeader{Version: 0, Command: protocol.RequestCommandTCP, Address: xnet.DomainAddress("device.example.com"), Port: 443, User: user}
			if err = encoding.EncodeRequestHeader(conn, req, &encoding.Addons{}); err != nil {
				conn.Close()
				return nil, err
			}
			return &vlessHTTPConn{Conn: conn, req: req}, nil
		}}
		defer tr.CloseIdleConnections()
		response, err := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Get("https://device.example.com/")
		if err != nil {
			return err
		}
		defer response.Body.Close()
		b, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		if string(b) != "device-ok" {
			return fmt.Errorf("unexpected response %q", b)
		}
		return nil
	}
	if err = request("127.0.0.1"); err != nil {
		t.Fatalf("first device: %v", err)
	}
	if err = request("127.0.0.1"); err != nil {
		t.Fatalf("same IP: %v", err)
	}
	if err = request("127.0.0.2"); err == nil {
		t.Fatal("second IP bypassed global admission")
	}
	if hits.Load() != 2 || claims.Load() != 2 || userPoll.Load() != 0 {
		t.Fatalf("hits=%d claims=%d v1 user polls=%d", hits.Load(), claims.Load(), userPoll.Load())
	}
	// Hold a real authenticated TLS stream across snapshot replacement.
	raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	req := &protocol.RequestHeader{Version: 0, Command: protocol.RequestCommandTCP, Address: xnet.DomainAddress("device.example.com"), Port: 443, User: user}
	if err := encoding.EncodeRequestHeader(raw, req, &encoding.Addons{}); err != nil {
		t.Fatal(err)
	}
	stream := tls.Client(&vlessHTTPConn{Conn: raw, req: req}, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	defer stream.Close()
	if _, err := fmt.Fprint(stream, "GET / HTTP/1.1\r\nHost: device.example.com\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stream)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	// UUID, subscription ID, and device limit belong to the new snapshot.
	const nextUUID = "00000000-0000-0000-0000-000000000002"
	payload["data"].(map[string]any)["identity_snapshot"] = map[string]any{"snapshot_id": strings.Repeat("b", 64), "protocols": []any{map[string]any{"protocol": "vless", "users": []any{map[string]any{"id": 43, "uuid": nextUUID, "account_id": 7, "device_limit": 1}}}}}
	next, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	bodyMu.Lock()
	body = next
	bodyMu.Unlock()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("Log:\n  Level: error\nApi:\n  ApiHost: %q\n  ServerID: 7\n  Timeout: 2\n", panelServer.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	h, err := reload(path, &nodes, &x, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h != nil {
		defer h.Close()
	}
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("retired snapshot stream survived reload")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("retired stream was not closed")
	}
	if err := request("127.0.0.1"); err == nil {
		t.Fatal("old UUID accepted after snapshot replacement")
	}
	user, err = (&protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: nextUUID})}).ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	if err := request("127.0.0.1"); err != nil {
		t.Fatalf("new snapshot identity: %v", err)
	}
	if claims.Load() != 3 || userPoll.Load() != 0 {
		t.Fatalf("new snapshot claims=%d user polls=%d", claims.Load(), userPoll.Load())
	}
}
