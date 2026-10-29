package outbound

import (
	"fmt"
	"strings"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

func TestLegacyAndMixedConfigurationsFailClosed(t *testing.T) {
	for _, data := range []*panel.Data{
		{}, {Block: &[]string{"example.com"}}, {Outbound: &[]panel.Outbound{{Name: "legacy", Protocol: "direct"}}},
	} {
		if _, err := Build(&panel.ServerConfigResponse{Data: data}, false); err == nil {
			t.Fatal("legacy configuration accepted")
		}
	}
	cfg := orderedFixture()
	cfg.Data.Block = &[]string{"example.com"}
	if _, err := Build(cfg, false); err == nil {
		t.Fatal("mixed configuration accepted")
	}
}
func TestOrderedDNSAndConnectionBuilders(t *testing.T) {
	cfg := orderedFixture()
	cfg.Data.Routing.Rules = []panel.RouteRule{}
	cfg.Data.Routing.Outbounds = []panel.Outbound{}
	values := make([]string, MaxRouteRules)
	for i := range values {
		values[i] = fmt.Sprintf("keyword:dns-%04d-%s", i, strings.Repeat("x", 48))
	}
	cfg.Data.DNS = &[]panel.DNSItem{{Address: "8.8.8.8", Domains: values}}
	cfg.Data.Routing.DefaultOutboundID = "direct"
	if _, err := Build(cfg, false); err != nil {
		t.Fatalf("DNS rules: %v", err)
	}
	for _, item := range []panel.Outbound{
		{ID: testOutboundID, Name: "proxy", Protocol: "vless", Address: "example.com", Port: 443, UUID: "00000000-0000-0000-0000-000000000001", Security: "tls", SNI: "example.com", Transport: "websocket", Host: "example.com", Path: "/ws"},
		{ID: testOutboundID, Name: "direct", Protocol: "direct", Settings: `{"domainStrategy":"UseIPv4"}`},
	} {
		cfg.Data.Routing.Outbounds = []panel.Outbound{item}
		result, err := Build(cfg, false)
		if err != nil || len(result.Outbounds) != 4 {
			t.Fatalf("ordered outbound %s: %v", item.Name, err)
		}
	}
	stream, err := buildOutboundStreamConfig(panel.Outbound{Protocol: "hysteria2", UUID: "user-id", Password: "auth-token"})
	if err != nil || stream.HysteriaSettings == nil || stream.HysteriaSettings.Auth != "auth-token" {
		t.Fatalf("Hysteria auth: %+v %v", stream, err)
	}
}
