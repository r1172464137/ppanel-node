package node

import (
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
)

func testNodeRouting() *panel.RoutingPolicy {
	return &panel.RoutingPolicy{Version: 1, Outbounds: []panel.Outbound{}, Rules: []panel.RouteRule{}, DefaultOutboundID: "direct", RoutingIdentity: panel.RoutingIdentity{Mode: "ordered-v1-inherited", Source: "global", SourceRevision: 1}}
}

func TestNewSkipsDisabledUnsupportedProtocols(t *testing.T) {
	protocols := []panel.Protocol{
		{Type: "wireguard", Enable: false, Port: 51820},
		{Type: "vless", Enable: true, Port: 443, Transport: "tcp"},
	}
	node, err := New(nil, &conf.Conf{ApiConfig: conf.ServerApiConfig{
		ApiHost: "https://panel.example", ServerId: 7,
		ACMEEmail: "admin@example.test", ACMECADirURL: "https://acme.example.test/directory",
	}}, &panel.ServerConfigResponse{Data: &panel.Data{Protocols: &protocols, Total: len(protocols), Routing: testNodeRouting()}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if len(node.controllers) != 1 || node.controllers[0].info.Type != "vless" {
		t.Fatalf("controllers = %+v, want only supported vless protocol", node.controllers)
	}
	if got := node.controllers[0].info.ACMEEmail; got != "admin@example.test" {
		t.Fatalf("ACMEEmail = %q, want admin@example.test", got)
	}
	if got := node.controllers[0].info.ACMECADirURL; got != "https://acme.example.test/directory" {
		t.Fatalf("ACMECADirURL = %q, want configured ACME directory", got)
	}
}
