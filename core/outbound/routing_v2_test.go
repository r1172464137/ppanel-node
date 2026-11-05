package outbound

import (
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

func TestV2RawAndStructuredChainReferences(t *testing.T) {
	const other = "ob_22222222-2222-4222-8222-222222222222"
	for name, change := range map[string]func(*panel.RoutingPolicy){
		"self": func(p *panel.RoutingPolicy) { p.Outbounds[0].ViaOutboundID = testOutboundID },
		"dangling raw": func(p *panel.RoutingPolicy) {
			p.Outbounds[0].StreamSettings = `{"sockopt":{"dialerProxy":"routing_missing"}}`
		},
		"unknown terminal": func(p *panel.RoutingPolicy) { p.Outbounds[0].StreamSettings = `{"sockopt":{"dialerProxy":"dns_out"}}` },
		"conflict": func(p *panel.RoutingPolicy) {
			p.Outbounds[0].ViaOutboundID = other
			p.Outbounds[0].StreamSettings = `{"sockopt":{"dialerProxy":"Default"}}`
		},
		"mixed cycle": func(p *panel.RoutingPolicy) {
			p.Outbounds[0].ViaOutboundID = other
			p.Outbounds[1].StreamSettings = `{"sockopt":{"dialerProxy":"routing_` + testOutboundID + `"}}`
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := dnsV2Fixture()
			c.Data.Routing.DNSPolicy = nil
			c.Data.Routing.Outbounds = append(c.Data.Routing.Outbounds, panel.Outbound{ID: other, Name: "other", Protocol: "direct"})
			change(c.Data.Routing)
			if err := ValidateOrdered(c.Data); err == nil {
				t.Fatal("unsafe chain accepted")
			}
		})
	}
	for _, terminal := range []string{"Default", "block"} {
		c := dnsV2Fixture()
		c.Data.Routing.DNSPolicy = nil
		c.Data.Routing.Outbounds[0].StreamSettings = `{"sockopt":{"dialerProxy":"` + terminal + `"}}`
		if err := ValidateOrdered(c.Data); err != nil {
			t.Fatalf("existing builtin terminal rejected: %v", err)
		}
	}
}

func TestV2EmptyAccountExpansionNeverBecomesGlobal(t *testing.T) {
	c := dnsV2Fixture()
	c.Data.Routing.DNSPolicy = nil
	c.Data.Routing.Rules[0].UserIDs = []int64{42}
	result, err := Build(c, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range result.Router.Rule {
		if rule.RuleTag == c.Data.Routing.Rules[0].ID {
			t.Fatal("account without authorized identities became a rule")
		}
	}
	c.Data.IdentitySnapshot.Protocols = nil
	if err := ValidateOrdered(c.Data); err == nil {
		t.Fatal("null snapshot protocols accepted")
	}
}
