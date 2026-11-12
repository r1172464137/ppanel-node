package core

import (
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

func TestGetCustomConfigEmptyOrderedRules(t *testing.T) {
	cfg := orderedConfig([]panel.RouteRule{}, nil)
	built, err := GetCustomConfig(cfg, v3TestTag)
	if err != nil {
		t.Fatal(err)
	}
	routes := built.Router
	if len(routes.GetRule()) != 1 {
		t.Fatalf("rules = %d", len(routes.GetRule()))
	}
}
func TestGetCustomConfigBuildsTypedOrderedOutbound(t *testing.T) {
	ob := panel.Outbound{ID: orderedSOCKSID, Name: "proxy", Protocol: "vless", Address: "example.com", Port: 443, UUID: "00000000-0000-0000-0000-000000000001", Security: "tls", SNI: "example.com", Transport: "websocket", Host: "example.com", Path: "/ws"}
	cfg := orderedConfig([]panel.RouteRule{orderedRule(0, "domain", "suffix:example.com", orderedSOCKSID, true)}, []panel.Outbound{ob})
	built, err := GetCustomConfig(cfg, v3TestTag)
	if err != nil {
		t.Fatal(err)
	}
	out, routes := built.Outbounds, built.Router
	if len(out) != 4 || len(routes.GetRule()) != 2 {
		t.Fatalf("outbounds=%d routes=%d", len(out), len(routes.GetRule()))
	}
}
