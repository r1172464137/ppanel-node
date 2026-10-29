package core

import (
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

func TestGetCustomConfigEmptyOrderedRules(t *testing.T) {
	cfg := orderedConfig([]panel.RouteRule{}, nil)
	_, _, routes, err := GetCustomConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes.GetRule()) != 1 {
		t.Fatalf("rules = %d", len(routes.GetRule()))
	}
}
func TestGetCustomConfigBuildsTypedOrderedOutbound(t *testing.T) {
	ob := panel.Outbound{ID: orderedSOCKSID, Name: "proxy", Protocol: "vless", Address: "example.com", Port: 443, UUID: "00000000-0000-0000-0000-000000000001", Security: "tls", SNI: "example.com", Transport: "websocket", Host: "example.com", Path: "/ws"}
	cfg := orderedConfig([]panel.RouteRule{orderedRule(0, "domain", "suffix:example.com", orderedSOCKSID, true)}, []panel.Outbound{ob})
	_, out, routes, err := GetCustomConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 4 || len(routes.GetRule()) != 2 {
		t.Fatalf("outbounds=%d routes=%d", len(out), len(routes.GetRule()))
	}
}
