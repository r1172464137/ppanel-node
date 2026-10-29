package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xray "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	routingSession "github.com/xtls/xray-core/features/routing/session"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

const orderedSOCKSID = "ob_11111111-1111-4111-8111-111111111111"

func orderedRule(i int, kind, value, target string, enabled bool) panel.RouteRule {
	return panel.RouteRule{ID: fmt.Sprintf("rr_11111111-1111-4111-8111-%012x", i+1), Enabled: &enabled, Kind: kind, Values: []string{value}, OutboundID: target}
}
func emptyTestRouting() *panel.RoutingPolicy {
	return orderedConfig([]panel.RouteRule{}, nil).Data.Routing
}

func orderedConfig(rules []panel.RouteRule, outbounds []panel.Outbound) *panel.ServerConfigResponse {
	if outbounds == nil {
		outbounds = []panel.Outbound{}
	}
	return &panel.ServerConfigResponse{Data: &panel.Data{Protocols: &[]panel.Protocol{}, Routing: &panel.RoutingPolicy{
		Version: 1, Rules: rules, Outbounds: outbounds, DefaultOutboundID: "direct",
		RoutingIdentity: panel.RoutingIdentity{Mode: "ordered-v1-inherited", Source: "global", SourceRevision: 1},
	}}}
}

// Called in the pinned-geodata subprocess, with both production checksums
// verified before starting it. Both standalone matches are asserted so that
// a reversed decision cannot pass merely because one label was absent.
func runOrderedProductionGeodata(t *testing.T) {
	google := orderedRule(0, "domain", "geosite:google-cn", "direct", true)
	cn := orderedRule(1, "domain", "geosite:cn", "block", true)
	for _, test := range []struct {
		name  string
		rules []panel.RouteRule
		want  string
	}{
		{"google-cn-membership", []panel.RouteRule{google}, "Default"},
		{"cn-membership", []panel.RouteRule{cn}, "block"},
		{"exception-first", []panel.RouteRule{google, cn}, "Default"},
		{"block-first", []panel.RouteRule{cn, google}, "block"},
	} {
		t.Run(test.name, func(t *testing.T) {
			instance, err := getCore(conf.New(), orderedConfig(test.rules, nil))
			if err != nil {
				t.Fatal(err)
			}
			if err := instance.Start(); err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			router := instance.GetFeature(routing.RouterType()).(routing.Router)
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: xnet.TCPDestination(xnet.DomainAddress("www.gstatic.com"), 443)}})
			route, err := router.PickRoute(routingSession.AsRoutingContext(ctx))
			if err != nil || route.GetOutboundTag() != test.want {
				t.Fatalf("picked %v, error %v; want %s", route, err, test.want)
			}
		})
	}
}

func TestOrderedAsIsTargetIPAndSniffedDomain(t *testing.T) {
	instance, err := getCore(conf.New(), orderedConfig([]panel.RouteRule{
		orderedRule(0, "domain", "sniff.example", "direct", true),
		orderedRule(1, "ip", "192.0.2.0/24", "block", true),
		orderedRule(2, "protocol", "bittorrent", "block", true),
	}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	router := instance.GetFeature(routing.RouterType()).(routing.Router)
	pick := func(target xnet.Destination, sniffed string, protocol string) (string, error) {
		ob := &session.Outbound{Target: target}
		if sniffed != "" {
			ob.RouteTarget = xnet.TCPDestination(xnet.DomainAddress(sniffed), target.Port)
		}
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{ob})
		ctx = session.ContextWithContent(ctx, &session.Content{Protocol: protocol})
		result, err := router.PickRoute(routingSession.AsRoutingContext(ctx))
		if err != nil {
			return "", err
		}
		return result.GetOutboundTag(), nil
	}
	ip := xnet.TCPDestination(xnet.ParseAddress("192.0.2.9"), 443)
	if tag, err := pick(ip, "", ""); err != nil || tag != "block" {
		t.Fatalf("target IP: %s %v", tag, err)
	}
	if tag, err := pick(ip, "sniff.example", ""); err != nil || tag != "Default" {
		t.Fatalf("sniffed domain: %s %v", tag, err)
	}
	if _, err := pick(xnet.TCPDestination(xnet.DomainAddress("not-matching.example"), 443), "", ""); err == nil {
		t.Fatal("AsIs resolved a domain into the IP rule")
	}
	if tag, err := pick(xnet.TCPDestination(xnet.DomainAddress("not-matching.example"), 443), "", "bittorrent"); err != nil || tag != "block" {
		t.Fatalf("sniffed protocol: %s %v", tag, err)
	}
}

func TestOrderedRealSniffedHTTPDomain(t *testing.T) {
	socks := startControlledSOCKSServer(t)
	ob := panel.Outbound{ID: orderedSOCKSID, Name: "sniff-controlled", Protocol: "socks", Address: "127.0.0.1", Port: socks.port()}
	cfg := orderedConfig([]panel.RouteRule{
		orderedRule(0, "domain", "sniff.example", orderedSOCKSID, true),
		orderedRule(1, "ip", "198.51.100.1/32", "block", true),
	}, []panel.Outbound{ob})
	x := New(conf.New(), nil)
	if err := x.Start(cfg); err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	port := reserveTCPUDPPort(t)
	raw := json.RawMessage(`{"address":"198.51.100.1","port":6881,"network":"tcp"}`)
	inbound, err := (&coreConf.InboundDetourConfig{
		Tag: "ordered-sniff", Protocol: "dokodemo-door",
		ListenOn: &coreConf.Address{Address: xnet.ParseAddress("127.0.0.1")},
		PortList: &coreConf.PortList{Range: []coreConf.PortRange{{From: uint32(port), To: uint32(port)}}},
		Settings: &raw, SniffingConfig: &coreConf.SniffingConfig{Enabled: true, DestOverride: coreConf.StringList{"http"}, RouteOnly: true},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := x.AddNodeConfig(inbound); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := dialTCPWithContext(ctx, net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("GET / HTTP/1.1\r\nHost: sniff.example\r\n\r\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("sniffed route did not reach SOCKS: %v", err)
	}
	if string(response) != string(payload) {
		t.Fatalf("unexpected echo: %q", response)
	}
	select {
	case evidence := <-socks.evidence:
		if evidence.host != "198.51.100.1" || evidence.port != 6881 || evidence.command != 1 {
			t.Fatalf("unexpected route-only SOCKS evidence: %+v", evidence)
		}
	case <-ctx.Done():
		t.Fatal("no receipt for sniffed domain route")
	}
}

func TestOrderedControlledSOCKSDataPlane(t *testing.T) {
	socks := startControlledSOCKSServer(t)
	ob := panel.Outbound{ID: orderedSOCKSID, Name: "controlled", Protocol: "socks", Address: "127.0.0.1", Port: socks.port()}
	cfg := orderedConfig([]panel.RouteRule{
		orderedRule(0, "domain", "route.example", orderedSOCKSID, true),
		orderedRule(1, "domain", "suffix:example", "block", true),
	}, []panel.Outbound{ob})
	instance, err := getCore(conf.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := xray.Dial(ctx, instance, xnet.TCPDestination(xnet.DomainAddress("route.example"), 443))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("ordered routing over controlled SOCKS")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, received); err != nil {
		t.Fatal(err)
	}
	if string(received) != string(payload) {
		t.Fatalf("echo = %q", received)
	}
	select {
	case evidence := <-socks.evidence:
		if evidence.transport != "tcp-control" || evidence.command != 1 || evidence.host != "route.example" || evidence.port != 443 {
			t.Fatalf("wrong SOCKS evidence: %+v", evidence)
		}
	case <-ctx.Done():
		t.Fatal("no SOCKS routing receipt")
	}

	// Reverse the same rules. Prove the block decision with the real router,
	// then verify this target did not reach the controlled SOCKS server.
	cfg.Data.Routing.Rules[0], cfg.Data.Routing.Rules[1] = cfg.Data.Routing.Rules[1], cfg.Data.Routing.Rules[0]
	blocked, err := getCore(conf.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := blocked.Start(); err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	dest := xnet.TCPDestination(xnet.DomainAddress("route.example"), 443)
	router := blocked.GetFeature(routing.RouterType()).(routing.Router)
	routeCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: dest}})
	route, err := router.PickRoute(routingSession.AsRoutingContext(routeCtx))
	if err != nil || route.GetOutboundTag() != "block" {
		t.Fatalf("reverse route = %v, %v", route, err)
	}
	blackhole, err := xray.Dial(ctx, blocked, dest)
	if err == nil {
		defer blackhole.Close()
		_ = blackhole.SetDeadline(time.Now().Add(time.Second))
		_, _ = blackhole.Write(payload)
		if _, err := io.ReadFull(blackhole, received); err == nil {
			t.Fatal("block returned the positive-control echo")
		}
	}
	select {
	case evidence := <-socks.evidence:
		t.Fatalf("blocked target reached SOCKS: %+v", evidence)
	case <-time.After(200 * time.Millisecond):
	}
}
