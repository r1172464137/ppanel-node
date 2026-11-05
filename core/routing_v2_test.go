package core

import (
	"context"
	"strings"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	routingSession "github.com/xtls/xray-core/features/routing/session"
)

func TestV2UserRuleAndChainCompilation(t *testing.T) {
	a := panel.Outbound{ID: orderedSOCKSID, Name: "A", Protocol: "socks", Address: "127.0.0.1", Port: 1080}
	b := panel.Outbound{ID: "ob_22222222-2222-4222-8222-222222222222", Name: "B", Protocol: "socks", Address: "127.0.0.1", Port: 1081, ViaOutboundID: a.ID}
	rule := orderedRule(0, "domain", "full:example.com", b.ID, true)
	rule.UserIDs = []int64{42}
	cfg := orderedConfig([]panel.RouteRule{rule}, []panel.Outbound{a, b})
	cfg.Data.Routing.Version = 2
	cfg.Data.Routing.Mode = "ordered-v2-inherited"
	cfg.Data.Routing.UserDefaults = []panel.UserDefault{}
	cfg.Data.Protocols = &[]panel.Protocol{{Type: "vless"}}
	cfg.Data.Total = 1
	cfg.Data.IdentitySnapshot = &panel.IdentitySnapshot{SnapshotID: strings.Repeat("a", 64), Protocols: []panel.ProtocolUserSnapshot{{Protocol: "vless", Users: []panel.UserInfo{{Id: 1, Uuid: "00000000-0000-0000-0000-000000000001", AccountID: 42}, {Id: 2, Uuid: "00000000-0000-0000-0000-000000000002", AccountID: 43}}}}}
	c := conf.New()
	c.ApiConfig.ApiHost = "https://panel.invalid"
	c.ApiConfig.ServerId = 7
	instance, err := getCore(c, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	r := instance.GetFeature(routing.RouterType()).(routing.Router)
	pick := func(user, domain string) (string, error) {
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: xnet.TCPDestination(xnet.DomainAddress(domain), 443)}})
		ctx = session.ContextWithInbound(ctx, &session.Inbound{User: &protocol.MemoryUser{Email: panel.InboundTag(c.ApiConfig.ApiHost, "vless", 7) + "|" + user}})
		route, err := r.PickRoute(routingSession.AsRoutingContext(ctx))
		if err != nil {
			return "", err
		}
		return route.GetOutboundTag(), nil
	}
	if got, err := pick("00000000-0000-0000-0000-000000000001", "example.com"); err != nil || got != "routing_"+b.ID {
		t.Fatalf("selected user: %s %v", got, err)
	}
	if _, err := pick("00000000-0000-0000-0000-000000000002", "example.com"); err == nil {
		t.Fatal("wrong account matched")
	}
	if _, err := pick("00000000-0000-0000-0000-000000000001", "else.example"); err == nil {
		t.Fatal("wrong destination matched")
	}
}
