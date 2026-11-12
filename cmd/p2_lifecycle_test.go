package cmd

// P2 lifecycle tests with real Xray instances, real listeners and real
// SOCKS5 relays. A VLESS client enters the node; the policy routes everything
// to outbound B, which dials its SOCKS server through outbound A
// (sockopt.dialerProxy). The relays record what they were asked to connect
// to, so a test can prove the chain A -> B was actually used.

import (
	"bufio"
	"context"
	"encoding/binary"
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
	"github.com/perfect-panel/ppanel-node/core"
	"github.com/perfect-panel/ppanel-node/node"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
)

const (
	p2OutboundA = "ob_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	p2OutboundB = "ob_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	p2Target    = "203.0.113.10:7" // TEST-NET; the relay for B maps it to a local echo server
)

// socksRelay is a minimal SOCKS5 (no auth, CONNECT) server. It records each
// requested destination; destinations in mapTo are redirected locally.
type socksRelay struct {
	ln    net.Listener
	mu    sync.Mutex
	seen  []string
	mapTo map[string]string
}

func startSocksRelay(t *testing.T, mapTo map[string]string) *socksRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &socksRelay{ln: ln, mapTo: mapTo}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(c)
		}
	}()
	return r
}

func (r *socksRelay) addr() string { return r.ln.Addr().String() }
func (r *socksRelay) port() int    { return r.ln.Addr().(*net.TCPAddr).Port }

func (r *socksRelay) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func (r *socksRelay) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 5 {
		return
	}
	if _, err := io.ReadFull(br, make([]byte, head[1])); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[1] != 1 {
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		io.ReadFull(br, b)
		host = net.IP(b).String()
	case 3:
		l, _ := br.ReadByte()
		b := make([]byte, l)
		io.ReadFull(br, b)
		host = string(b)
	case 4:
		b := make([]byte, 16)
		io.ReadFull(br, b)
		host = net.IP(b).String()
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	dest := net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(pb)))
	r.mu.Lock()
	r.seen = append(r.seen, dest)
	r.mu.Unlock()
	dial := dest
	if m, ok := r.mapTo[dest]; ok {
		dial = m
	}
	up, err := net.DialTimeout("tcp", dial, 2*time.Second)
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go func() { io.Copy(up, br); up.(*net.TCPConn).CloseWrite() }()
	io.Copy(c, up)
}

func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func reservePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

// p2Panel serves a candidate whose fields the test can change.
type p2Panel struct {
	srv                      *httptest.Server
	mu                       sync.Mutex
	listenPort, pull, rev    int
	relayA, relayB           int
	failConfig               bool
	configFetches, userFetch atomic.Int32
}

func (p *p2Panel) set(fn func(p *p2Panel)) { p.mu.Lock(); fn(p); p.mu.Unlock() }

func (p *p2Panel) payload() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	routing := fmt.Sprintf(`{"version":3,"outbounds":[`+
		`{"id":%q,"name":"A","protocol":"socks","address":"127.0.0.1","port":%d,"rules":[],"ip_rules":[],"protocol_rules":[]},`+
		`{"id":%q,"name":"B","protocol":"socks","address":"127.0.0.1","port":%d,"stream_settings":"{\"sockopt\":{\"dialerProxy\":\"routing_%s\"}}","rules":[],"ip_rules":[],"protocol_rules":[]}],`+
		`"rules":[],"default_outbound_id":%q,"mode":"inherited","source":"global","source_revision":%d}`,
		p2OutboundA, p.relayA, p2OutboundB, p.relayB, p2OutboundA, p2OutboundB, p.rev)
	return v3JSON(fmt.Sprintf(`{"code":200,"data":{"pull_interval":%d,"push_interval":3600,"protocols":[{"type":"vless","enable":true,"port":%d,"transport":"tcp"}],"total":1,"routing":%s}}`,
		p.pull, p.listenPort, routing), dataPlaneUser)
}

func startP2Panel(t *testing.T, listenPort, relayA, relayB int) *p2Panel {
	t.Helper()
	p := &p2Panel{listenPort: listenPort, pull: 3600, rev: 1, relayA: relayA, relayB: relayB}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/server/7":
			p.configFetches.Add(1)
			p.mu.Lock()
			fail := p.failConfig
			p.mu.Unlock()
			if fail {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusBadGateway)
				fmt.Fprint(w, "<!DOCTYPE html><html><head><title>502 Bad gateway</title></head><body>"+strings.Repeat("cloudflare ", 2000)+"</body></html>")
				return
			}
			fmt.Fprint(w, p.payload())
		case "/v1/server/user":
			p.userFetch.Add(1)
			fmt.Fprintf(w, `{"code":200,"data":{"users":[{"id":1,"uuid":%q}]}}`, dataPlaneUUID)
		default:
			fmt.Fprint(w, `{"code":200}`)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// p2Node starts a node against the panel and returns pointers usable by reload.
type p2Node struct {
	path  string
	nodes *node.Node
	x     *core.XrayCore
}

func startP2Node(t *testing.T, p *p2Panel) *p2Node {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("Log:\n  Level: error\nApi:\n  ApiHost: %q\n  ServerID: 7\n  Timeout: 2\n", p.srv.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := conf.New()
	if err := cfg.LoadFromPath(path); err != nil {
		t.Fatal(err)
	}
	client := panel.NewServerClient(&cfg.ApiConfig)
	nodes, x, _, err := startInitial(context.Background(), cfg, client, make(chan struct{}, 1))
	if err != nil {
		t.Fatal(err)
	}
	n := &p2Node{path: path, nodes: nodes, x: x}
	t.Cleanup(func() { n.nodes.Close(); _ = n.x.Close() })
	return n
}

func (n *p2Node) reload() error {
	h, err := reload(n.path, &n.nodes, &n.x, nil)
	if h != nil {
		_ = h.Close()
	}
	return err
}

// dialThroughNode opens a VLESS TCP stream through the node to p2Target.
func dialThroughNode(t *testing.T, listenPort int) (net.Conn, error) {
	t.Helper()
	user, err := (&protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: dataPlaneUUID})}).ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 2*time.Second)
	if err != nil {
		return nil, err
	}
	host, port, _ := net.SplitHostPort(p2Target)
	var pn uint16
	fmt.Sscan(port, &pn)
	req := &protocol.RequestHeader{Version: 0, Command: protocol.RequestCommandTCP, Address: xnet.ParseAddress(host), Port: xnet.Port(pn), User: user}
	if err := encoding.EncodeRequestHeader(conn, req, &encoding.Addons{}); err != nil {
		conn.Close()
		return nil, err
	}
	return &vlessHTTPConn{Conn: conn, req: req}, nil
}

// roundTrip writes msg and expects it echoed back through the chain.
func roundTrip(conn net.Conn, msg string) error {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return fmt.Errorf("echo %q, want %q", buf, msg)
	}
	return nil
}

func assertChain(t *testing.T, listenPort int, a, b *socksRelay, label string) {
	t.Helper()
	beforeA, beforeB := len(a.requests()), len(b.requests())
	conn, err := dialThroughNode(t, listenPort)
	if err != nil {
		t.Fatalf("%s: dial node: %v", label, err)
	}
	defer conn.Close()
	if err := roundTrip(conn, label); err != nil {
		t.Fatalf("%s: traffic through A->B failed: %v", label, err)
	}
	ra, rb := a.requests(), b.requests()
	if len(ra) <= beforeA || ra[len(ra)-1] != b.addr() {
		t.Fatalf("%s: relay A did not carry B's connection; A saw %v", label, ra)
	}
	if len(rb) <= beforeB || rb[len(rb)-1] != p2Target {
		t.Fatalf("%s: relay B did not receive the target; B saw %v", label, rb)
	}
}

func newChain(t *testing.T) (a, b *socksRelay) {
	echo := startEcho(t)
	b = startSocksRelay(t, map[string]string{p2Target: echo})
	a = startSocksRelay(t, nil)
	return a, b
}

// A candidate that fails to bind must leave the previous service fully
// working - including outbound chains, which depend on Xray's process-wide
// outbound manager pointing at the previous instance again.
func TestFailedCandidateRestoresChainedOutbounds(t *testing.T) {
	a, b := newChain(t)
	listen := reservePort(t)
	p := startP2Panel(t, listen, a.port(), b.port())
	n := startP2Node(t, p)
	assertChain(t, listen, a, b, "initial")

	blocker, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	// The failing candidate also moves outbound A to another relay (A2). After
	// the rollback the previous instance must again be the one serving: its B
	// has to dial through the previous A, never through the candidate's A2.
	a2 := startSocksRelay(t, nil)
	fetchesBefore := p.configFetches.Load()
	p.set(func(p *p2Panel) { p.listenPort = blocker.Addr().(*net.TCPAddr).Port; p.relayA = a2.port(); p.rev = 2 })
	err = n.reload()
	if err == nil || !strings.Contains(err.Error(), "previous nodes restored") {
		t.Fatalf("reload into an occupied port: %v", err)
	}
	if got := p.configFetches.Load() - fetchesBefore; got != 1 {
		t.Fatalf("rollback fetched from the panel again (%d config fetches)", got)
	}
	assertChain(t, listen, a, b, "after-rollback")
	if got := a2.requests(); len(got) != 0 {
		t.Fatalf("restored service dialed through the failed candidate's outbound A2: %v", got)
	}
	p.set(func(p *p2Panel) { p.relayA = a.port() })

	p.set(func(p *p2Panel) { p.listenPort = listen; p.rev = 3 })
	if err := n.reload(); err != nil {
		t.Fatalf("good candidate: %v", err)
	}
	assertChain(t, listen, a, b, "after-switch")
}

// Interval-only changes and unchanged candidates must not rebuild the core or
// drop an established connection.
func TestRuntimeOnlyAndNoChangeKeepConnections(t *testing.T) {
	a, b := newChain(t)
	listen := reservePort(t)
	p := startP2Panel(t, listen, a.port(), b.port())
	n := startP2Node(t, p)
	conn, err := dialThroughNode(t, listen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := roundTrip(conn, "before"); err != nil {
		t.Fatal(err)
	}
	core0 := n.x

	if err := n.reload(); err != nil {
		t.Fatalf("unchanged candidate: %v", err)
	}
	if n.x != core0 {
		t.Fatal("unchanged candidate rebuilt the core")
	}
	if err := roundTrip(conn, "after-noop"); err != nil {
		t.Fatalf("connection dropped by an unchanged candidate: %v", err)
	}

	p.set(func(p *p2Panel) { p.pull = 1800 })
	if err := n.reload(); err != nil {
		t.Fatalf("interval-only candidate: %v", err)
	}
	if n.x != core0 {
		t.Fatal("interval-only change rebuilt the core")
	}
	if got := n.x.Client.Applied(); got == nil || got.Data.PullInterval != 1800 {
		t.Fatal("interval-only change was not committed as applied")
	}
	if err := roundTrip(conn, "after-runtime"); err != nil {
		t.Fatalf("connection dropped by an interval-only change: %v", err)
	}

	// A real data-plane change does switch, and is reported honestly as a
	// switch: the old connection is closed.
	p.set(func(p *p2Panel) { p.rev = 2 })
	if err := n.reload(); err != nil {
		t.Fatalf("routing revision change: %v", err)
	}
	if n.x == core0 {
		t.Fatal("routing change did not switch the core")
	}
	if err := roundTrip(conn, "after-switch"); err == nil {
		t.Fatal("old connection survived a full switch; it must have been closed with the old instance")
	}
	assertChain(t, listen, a, b, "new-connection")
}

// When both the candidate and the rollback fail, the node reports the service
// unavailable, holds no listener, and recovers on the next attempt once the
// port is free - without a process restart.
func TestDualFailureReportsUnavailableAndSelfHeals(t *testing.T) {
	a, b := newChain(t)
	listen := reservePort(t)
	p := startP2Panel(t, listen, a.port(), b.port())
	n := startP2Node(t, p)
	assertChain(t, listen, a, b, "initial")

	candidateBlocker, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	newPort := candidateBlocker.Addr().(*net.TCPAddr).Port
	var oldBlocker net.Listener
	afterPreviousStopped = func() {
		// Another process takes the previous port the moment it is released.
		oldBlocker, err = net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", listen))
		if err != nil {
			t.Errorf("could not occupy the released port: %v", err)
		}
	}
	defer func() { afterPreviousStopped = func() {} }()
	saved := bindRetryWindowForTest(200 * time.Millisecond)
	defer saved()

	p.set(func(p *p2Panel) { p.listenPort = newPort; p.rev = 2 })
	err = n.reload()
	afterPreviousStopped = func() {}
	if err == nil || !strings.Contains(err.Error(), "restoring previous nodes failed") {
		t.Fatalf("dual failure: %v", err)
	}
	if n.x.Running() {
		t.Fatal("previous instance reported running after a failed restore")
	}
	status := n.x.Client.State.Snapshot()
	if status.Applied != nil || status.Error == nil || status.Error.Stage != string(panel.StageRestore) {
		t.Fatalf("status after dual failure: applied=%v error=%+v", status.Applied, status.Error)
	}

	// External conditions recover: both ports are released. The next attempt
	// (the retry loop's reload) rebuilds the service on the candidate port.
	oldBlocker.Close()
	candidateBlocker.Close()
	if err := n.reload(); err != nil {
		t.Fatalf("self-heal reload: %v", err)
	}
	if !n.x.Running() {
		t.Fatal("service not running after recovery")
	}
	assertChain(t, newPort, a, b, "recovered")
	if s := n.x.Client.State.Snapshot(); s.Applied == nil {
		t.Fatal("recovered candidate not reported applied")
	}
}

// A port still held for a moment (the instance closed just before) is waited
// for within the bounded window; the switch then succeeds.
func TestTransientPortHoldIsWaitedFor(t *testing.T) {
	a, b := newChain(t)
	listen := reservePort(t)
	p := startP2Panel(t, listen, a.port(), b.port())
	n := startP2Node(t, p)
	holder, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	newPort := holder.Addr().(*net.TCPAddr).Port
	go func() { time.Sleep(700 * time.Millisecond); holder.Close() }()
	p.set(func(p *p2Panel) { p.listenPort = newPort; p.rev = 2 })
	start := time.Now()
	if err := n.reload(); err != nil {
		t.Fatalf("switch with a briefly held port: %v", err)
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Fatal("bind did not wait for the port")
	}
	assertChain(t, newPort, a, b, "after-wait")
}

// A panel outage (502 with an HTML error page) must not stop the running
// service, and the error must not carry the page.
func TestPanelErrorPageKeepsServiceAndBoundsError(t *testing.T) {
	a, b := newChain(t)
	listen := reservePort(t)
	p := startP2Panel(t, listen, a.port(), b.port())
	n := startP2Node(t, p)
	conn, err := dialThroughNode(t, listen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := roundTrip(conn, "before"); err != nil {
		t.Fatal(err)
	}
	p.set(func(p *p2Panel) { p.failConfig = true })
	err = n.reload()
	if err == nil {
		t.Fatal("panel outage reported as success")
	}
	if strings.Contains(strings.ToLower(err.Error()), "<html") || strings.Contains(err.Error(), "cloudflare") || len(err.Error()) > 400 {
		t.Fatalf("error carries the panel page (%d bytes): %.200s", len(err.Error()), err.Error())
	}
	if !strings.Contains(err.Error(), "HTML error page") {
		t.Fatalf("error does not summarise the page: %v", err)
	}
	if err := roundTrip(conn, "during-outage"); err != nil {
		t.Fatalf("panel outage dropped the running service: %v", err)
	}
	assertChain(t, listen, a, b, "new-during-outage")
}

func bindRetryWindowForTest(d time.Duration) func() { return core.SetBindRetryWindow(d) }

// Removing a user must cut that user's established connections, including
// links served through DispatchLink (VLESS), not only stop new handshakes.
func TestRemovedUserConnectionsAreCut(t *testing.T) {
	a, b := newChain(t)
	listen := reservePort(t)
	p := startP2Panel(t, listen, a.port(), b.port())
	n := startP2Node(t, p)
	conn, err := dialThroughNode(t, listen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := roundTrip(conn, "before-removal"); err != nil {
		t.Fatal(err)
	}
	tag := fmt.Sprintf("[%s]-vless:7", p.srv.URL)
	if err := n.x.DelUsers([]panel.UserInfo{{Id: 1, Uuid: dataPlaneUUID}}, tag, nil); err != nil {
		t.Fatal(err)
	}
	if err := roundTrip(conn, "after-removal"); err == nil {
		t.Fatal("a removed user's established connection kept working")
	}
	if c, err := dialThroughNode(t, listen); err == nil {
		defer c.Close()
		if roundTrip(c, "new-after-removal") == nil {
			t.Fatal("a removed user could open a new connection")
		}
	}
}
