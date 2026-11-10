package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/perfect-panel/ppanel-node/core"
	"github.com/perfect-panel/ppanel-node/node"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
)

type reloadBindPanel struct {
	t        *testing.T
	server   *httptest.Server
	path     string
	port     atomic.Int32
	revision atomic.Int64
	users    atomic.Int32
	userPoll atomic.Int32
	socks    int
}

func newReloadBindPanel(t *testing.T, port int, socksPort int) *reloadBindPanel {
	t.Helper()
	p := &reloadBindPanel{t: t, socks: socksPort}
	p.port.Store(int32(port))
	p.revision.Store(1)
	p.users.Store(1)
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/server/7":
			revision := p.revision.Load()
			etag := fmt.Sprintf(`"reload-%d"`, revision)
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			outbound := panel.Outbound{ID: dataPlaneOutbound, Name: "reload-socks", Protocol: "socks", Address: "127.0.0.1", Port: p.socks}
			payload := map[string]any{"code": 200, "data": map[string]any{
				"push_interval": 3600,
				"pull_interval": 1,
				"protocols": []any{map[string]any{
					"type": "vless", "enable": true, "port": p.port.Load(), "transport": "tcp",
				}},
				"total": 1,
				"routing": map[string]any{
					"version": 1, "outbounds": []panel.Outbound{outbound}, "rules": []any{},
					"default_outbound_id": dataPlaneOutbound, "mode": "ordered-v1-inherited",
					"source": "global", "source_revision": revision,
				},
			}}
			if err := json.NewEncoder(w).Encode(payload); err != nil {
				t.Error(err)
			}
		case "/v1/server/user":
			p.userPoll.Add(1)
			if p.users.Load() == 1 {
				fmt.Fprintf(w, `{"code":200,"data":{"users":[{"id":1,"uuid":%q}]}}`, dataPlaneUUID)
				return
			}
			fmt.Fprintf(w, `{"code":200,"data":{"users":[{"id":1,"uuid":%q},{"id":2,"uuid":"00000000-0000-0000-0000-000000000002"}]}}`, dataPlaneUUID)
		default:
			fmt.Fprint(w, `{"code":200}`)
		}
	}))
	t.Cleanup(p.server.Close)
	p.path = filepath.Join(t.TempDir(), "config.yml")
	config := fmt.Sprintf("Log:\n  Level: error\nApi:\n  ApiHost: %q\n  ServerID: 7\n  Timeout: 2\n", p.server.URL)
	if err := os.WriteFile(p.path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *reloadBindPanel) start(t *testing.T) (*nodeHandle, *panel.ServerClient) {
	t.Helper()
	cfg := conf.New()
	cfg.LogConfig.Level = "error"
	cfg.ApiConfig = conf.ServerApiConfig{ApiHost: p.server.URL, ServerId: 7, Timeout: 2}
	client := panel.NewServerClient(&cfg.ApiConfig)
	nodes, core, _, err := startInitial(context.Background(), cfg, client, make(chan struct{}, 1))
	if err != nil {
		t.Fatal(err)
	}
	return &nodeHandle{nodes: nodes, core: core}, client
}

type nodeHandle struct {
	nodes *node.Node
	core  *core.XrayCore
}

func (h *nodeHandle) close() {
	if h == nil {
		return
	}
	if h.nodes != nil {
		h.nodes.Close()
		h.nodes = nil
	}
	if h.core != nil {
		_ = h.core.Close()
		h.core = nil
	}
}

func freeReloadPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func assertPortHeldByNode(t *testing.T, port int) {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	if err == nil {
		listener.Close()
		t.Fatalf("port %d is also bindable by another listener", port)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "address already in use") {
		t.Fatalf("port %d ownership check: %v", port, err)
	}
}

func waitPortBindable(t *testing.T, port int) net.Listener {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
		if err == nil {
			return listener
		}
		if time.Now().After(deadline) {
			t.Fatalf("port %d was not released: %v", port, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newReloadVLESSClient(t *testing.T, port int) *http.Client {
	t.Helper()
	user, err := (&protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: dataPlaneUUID})}).ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
		if err != nil {
			return nil, err
		}
		request := &protocol.RequestHeader{Version: 0, Command: protocol.RequestCommandTCP, Address: xnet.DomainAddress("reload.example.com"), Port: 80, User: user}
		if err := encoding.EncodeRequestHeader(conn, request, &encoding.Addons{}); err != nil {
			conn.Close()
			return nil, err
		}
		return &vlessHTTPConn{Conn: conn, req: request}, nil
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}

func assertReloadDataPlane(t *testing.T, client *http.Client, hits *atomic.Int32) {
	t.Helper()
	before := hits.Load()
	response, err := client.Get("http://reload.example.com/proof")
	if err != nil {
		t.Fatalf("real VLESS request: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "reload-data-plane" || hits.Load() != before+1 {
		t.Fatalf("real VLESS response %q, hits %d->%d, err %v", body, before, hits.Load(), err)
	}
}

func newReloadTarget(t *testing.T) (*httptest.Server, int, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "reload-data-plane")
	}))
	t.Cleanup(target.Close)
	socksPort, _ := startHTTPSRelaySOCKS(t, target.Listener.Addr().String())
	return target, socksPort, &hits
}

func TestReloadSamePortRepeatedlyKeepsSingleListener(t *testing.T) {
	_, socksPort, hits := newReloadTarget(t)
	port := freeReloadPort(t)
	p := newReloadBindPanel(t, port, socksPort)
	handle, client := p.start(t)
	defer handle.close()
	dataPlane := newReloadVLESSClient(t, port)

	for i := 0; i < 3; i++ {
		p.revision.Add(1)
		h, err := reload(p.path, &handle.nodes, &handle.core, nil)
		if err != nil {
			t.Fatalf("same-port reload %d: %v", i+1, err)
		}
		if h != nil {
			h.Close()
		}
		assertReloadDataPlane(t, dataPlane, hits)
		assertPortHeldByNode(t, port)
	}
	status := client.State.Snapshot()
	if status.Applied == nil || status.Applied.SourceRevision != 4 || status.Pending != nil {
		t.Fatalf("status after repeated reloads: %+v", status)
	}
	handle.close()
	released := waitPortBindable(t, port)
	released.Close()
}

func TestReloadCandidateBindFailureRestoresOldListener(t *testing.T) {
	_, socksPort, hits := newReloadTarget(t)
	port := freeReloadPort(t)
	p := newReloadBindPanel(t, port, socksPort)
	handle, client := p.start(t)
	defer handle.close()
	dataPlane := newReloadVLESSClient(t, port)

	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	oldNodes, oldCore := handle.nodes, handle.core
	p.port.Store(int32(blocker.Addr().(*net.TCPAddr).Port))
	p.revision.Store(2)
	_, err = reload(p.path, &handle.nodes, &handle.core, nil)
	if err == nil || !strings.Contains(err.Error(), "bind failed") || !strings.Contains(err.Error(), "previous nodes restored") {
		t.Fatalf("candidate bind failure result: %v", err)
	}
	if handle.nodes != oldNodes || handle.core != oldCore {
		t.Fatal("failed candidate displaced the old generation")
	}
	status := client.State.Snapshot()
	if status.Applied == nil || status.Applied.SourceRevision != 1 || status.Pending == nil || status.Pending.SourceRevision != 2 || status.Error == nil || status.Error.Stage != "bind" {
		t.Fatalf("status after restored bind failure: %+v", status)
	}
	assertReloadDataPlane(t, dataPlane, hits)
	assertPortHeldByNode(t, port)

	blocker.Close()
	p.port.Store(int32(port))
	p.revision.Store(3)
	h, err := reload(p.path, &handle.nodes, &handle.core, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h != nil {
		h.Close()
	}
	status = client.State.Snapshot()
	if status.Applied == nil || status.Applied.SourceRevision != 3 || status.Pending != nil {
		t.Fatalf("status after corrected reload: %+v", status)
	}
	assertReloadDataPlane(t, dataPlane, hits)
}

func TestReloadBindRetriesTransientAddressInUse(t *testing.T) {
	_, socksPort, hits := newReloadTarget(t)
	port := freeReloadPort(t)
	p := newReloadBindPanel(t, port, socksPort)
	handle, client := p.start(t)
	defer handle.close()

	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	candidatePort := blocker.Addr().(*net.TCPAddr).Port
	p.port.Store(int32(candidatePort))
	p.revision.Store(2)
	released := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		blocker.Close()
		close(released)
	}()
	h, err := reload(p.path, &handle.nodes, &handle.core, nil)
	if err != nil {
		t.Fatalf("transient bind conflict was not retried: %v", err)
	}
	if h != nil {
		h.Close()
	}
	<-released
	status := client.State.Snapshot()
	if status.Applied == nil || status.Applied.SourceRevision != 2 || status.Pending != nil {
		t.Fatalf("status after retried bind: %+v", status)
	}
	dataPlane := newReloadVLESSClient(t, candidatePort)
	assertReloadDataPlane(t, dataPlane, hits)
	assertPortHeldByNode(t, candidatePort)
}

func TestReloadDoubleBindFailureReleasesOldCoreAndRecovers(t *testing.T) {
	_, socksPort, hits := newReloadTarget(t)
	port := freeReloadPort(t)
	p := newReloadBindPanel(t, port, socksPort)
	handle, client := p.start(t)
	defer handle.close()
	dataPlane := newReloadVLESSClient(t, port)
	oldNodes, oldCore := handle.nodes, handle.core

	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	address := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	stolen := make(chan net.Listener, 1)
	go func() {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			listener, err := net.Listen("tcp", address)
			if err == nil {
				stolen <- listener
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	p.port.Store(int32(blocker.Addr().(*net.TCPAddr).Port))
	p.revision.Store(2)
	_, err = reload(p.path, &handle.nodes, &handle.core, nil)
	if err == nil || !strings.Contains(err.Error(), "bind failed") || !strings.Contains(err.Error(), "restoring previous nodes failed") {
		t.Fatalf("double bind failure result: %v", err)
	}
	if handle.nodes != oldNodes || handle.core != oldCore {
		t.Fatal("double failure displaced the old generation")
	}
	var stealer net.Listener
	select {
	case stealer = <-stolen:
	case <-time.After(time.Second):
		t.Fatal("rollback did not release the old port for the concurrent binder")
	}
	status := client.State.Snapshot()
	if status.Applied != nil || status.Pending == nil || status.Pending.SourceRevision != 2 || status.Error == nil || status.Error.Stage != "restore" {
		t.Fatalf("status after failed rollback: %+v", status)
	}
	if !oldCore.FailedClosed() {
		t.Fatal("old core remained restartable after a failed rollback")
	}
	stealer.Close()

	p.port.Store(int32(port))
	p.revision.Store(3)
	h, err := reload(p.path, &handle.nodes, &handle.core, nil)
	if err != nil {
		t.Fatalf("reload did not self-heal after failed rollback: %v", err)
	}
	if h != nil {
		h.Close()
	}
	status = client.State.Snapshot()
	if status.Applied == nil || status.Applied.SourceRevision != 3 || status.Pending != nil {
		t.Fatalf("status after self-healing reload: %+v", status)
	}
	assertReloadDataPlane(t, dataPlane, hits)
	assertPortHeldByNode(t, port)
	handle.close()
	released := waitPortBindable(t, port)
	released.Close()
}

func TestConcurrentV1UserUpdatesAndSamePortReloads(t *testing.T) {
	_, socksPort, hits := newReloadTarget(t)
	port := freeReloadPort(t)
	p := newReloadBindPanel(t, port, socksPort)
	handle, client := p.start(t)
	defer handle.close()
	dataPlane := newReloadVLESSClient(t, port)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 36; i++ {
			if i%2 == 0 {
				p.users.Store(2)
			} else {
				p.users.Store(1)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	for i := 0; i < 3; i++ {
		time.Sleep(1200 * time.Millisecond)
		p.revision.Add(1)
		h, err := reload(p.path, &handle.nodes, &handle.core, nil)
		if err != nil {
			t.Fatalf("reload during v1 user monitoring %d: %v", i+1, err)
		}
		if h != nil {
			h.Close()
		}
		assertReloadDataPlane(t, dataPlane, hits)
		assertPortHeldByNode(t, port)
	}
	<-done
	if p.userPoll.Load() < 5 {
		t.Fatalf("v1 user monitor did not run during reloads: %d polls", p.userPoll.Load())
	}
	status := client.State.Snapshot()
	if status.Applied == nil || status.Applied.SourceRevision != 4 || status.Pending != nil {
		t.Fatalf("status after concurrent reloads: %+v", status)
	}
}
