package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xray "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	routingSession "github.com/xtls/xray-core/features/routing/session"
)

// A real HTTP client verifies the local test CA and hostname over TLS. The
// controlled SOCKS server forwards to one fixed local HTTPS server, recording
// the requested destination; it never dials the public internet.
func TestOrderedHTTPSOverControlledSOCKS(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proof" {
			t.Errorf("target path %s", r.URL.Path)
		}
		hits.Add(1)
		_, _ = w.Write([]byte("ordered-https-receipt"))
	}))
	defer target.Close()
	control, err := target.Client().Get(target.URL + "/proof")
	if err != nil {
		t.Fatalf("direct local positive control: %v", err)
	}
	controlBody, err := io.ReadAll(control.Body)
	control.Body.Close()
	if err != nil || string(controlBody) != "ordered-https-receipt" {
		t.Fatalf("positive control %q: %v", controlBody, err)
	}

	socks := startControlledSOCKSRelay(t, target.Listener.Addr().String())
	out := panel.Outbound{ID: orderedSOCKSID, Name: "https-socks", Protocol: "socks", Address: "127.0.0.1", Port: socks.port()}
	exception := orderedRule(0, "domain", "probe.example.com", orderedSOCKSID, true)
	block := orderedRule(1, "domain", "suffix:example.com", "block", true)
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	makeClient := func(instance *xray.Instance) *http.Client {
		transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return xray.Dial(ctx, instance, xnet.TCPDestination(xnet.DomainAddress("probe.example.com"), 443))
			}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 2 * time.Second}
	}
	newInstance := func(rules []panel.RouteRule) *xray.Instance {
		instance, err := getCore(conf.New(), orderedConfig(rules, []panel.Outbound{out}))
		if err != nil {
			t.Fatal(err)
		}
		if err := instance.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = instance.Close() })
		return instance
	}
	instance := newInstance([]panel.RouteRule{exception, block})
	resp, err := makeClient(instance).Get("https://probe.example.com/proof")
	if err != nil {
		t.Fatalf("HTTPS via ordered SOCKS: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || string(body) != "ordered-https-receipt" || hits.Load() != 2 {
		t.Fatalf("HTTPS receipt %q, hits=%d, error=%v", body, hits.Load(), err)
	}
	select {
	case evidence := <-socks.evidence:
		if evidence.command != 1 || evidence.host != "probe.example.com" || evidence.port != 443 {
			t.Fatalf("wrong SOCKS receipt: %+v", evidence)
		}
	case <-time.After(time.Second):
		t.Fatal("missing HTTPS SOCKS receipt")
	}

	reversed := newInstance([]panel.RouteRule{block, exception})
	router := reversed.GetFeature(routing.RouterType()).(routing.Router)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: xnet.TCPDestination(xnet.DomainAddress("probe.example.com"), 443)}})
	route, err := router.PickRoute(routingSession.AsRoutingContext(ctx))
	if err != nil || route.GetOutboundTag() != "block" {
		t.Fatalf("reverse router decision: %v %v", route, err)
	}
	if resp, err := makeClient(reversed).Get("https://probe.example.com/proof"); err == nil {
		resp.Body.Close()
		t.Fatal("blocked HTTPS unexpectedly succeeded")
	}
	if hits.Load() != 2 {
		t.Fatal("blocked request reached HTTPS target")
	}
	select {
	case evidence := <-socks.evidence:
		t.Fatalf("blocked request reached SOCKS: %+v", evidence)
	case <-time.After(200 * time.Millisecond):
	}
}
