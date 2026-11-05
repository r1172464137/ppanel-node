package outbound

import (
	"strings"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/transport/internet"
)

func dnsV2Fixture() *panel.ServerConfigResponse {
	c := orderedFixture()
	c.Data.Routing.Version = 2
	c.Data.Routing.Mode = "ordered-v2-inherited"
	c.Data.Routing.UserDefaults = []panel.UserDefault{}
	c.Data.IdentitySnapshot = &panel.IdentitySnapshot{SnapshotID: strings.Repeat("a", 64), Protocols: []panel.ProtocolUserSnapshot{}}
	c.Data.Routing.DNSPolicy = &panel.DNSPolicy{QueryStrategy: "UseIPv4", Resolvers: []panel.PolicyDNSResolver{
		{ID: "dns_11111111-1111-4111-8111-111111111111", Protocol: "tcp", Address: "192.0.2.53:5353", Domains: []string{"suffix:unit.test"}, OutboundID: testOutboundID},
		{ID: "dns_22222222-2222-4222-8222-222222222222", Protocol: "https", Address: "https://resolver.test/dns-query", BootstrapIP: "192.0.2.54", Domains: []string{}, OutboundID: "direct"},
	}}
	return c
}

func TestV2DNSPolicyBuildAndValidation(t *testing.T) {
	cfg := dnsV2Fixture()
	result, err := Build(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.DNS.NameServer) != 2 || result.DNS.NameServer[0].Address.Address.GetDomain() != "tcp://192.0.2.53:5353" {
		t.Fatalf("DNS projection: %v", result.DNS)
	}
	if !result.DNS.DisableFallback || !result.DNS.DisableFallbackIfMatch || result.DNS.EnableParallelQuery {
		t.Fatal("DNS failure may escape policy")
	}
	for i, resolver := range result.DNS.NameServer {
		if !resolver.FinalQuery || !resolver.SkipFallback || resolver.Tag != PolicyDNSTag(cfg.Data.Routing.DNSPolicy.Resolvers[i].ID) {
			t.Fatal("resolver priority lost")
		}
		if result.Router.Rule[i].InboundTag[0] != resolver.Tag {
			t.Fatal("resolver route must precede UDP53 interception")
		}
	}
	if result.Router.Rule[2].GetTag() != DNSTag {
		t.Fatal("original client UDP53 route missing")
	}
	for _, out := range result.Outbounds {
		if out.Tag == "routing_"+testOutboundID {
			config, err := out.SenderSettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			sender := config.(*proxyman.SenderConfig)
			if sender.StreamSettings == nil || sender.StreamSettings.SocketSettings.GetDomainStrategy() != internet.DomainStrategy_FORCE_IP {
				t.Fatal("proxy server resolution may fall back to system DNS")
			}
		}
	}
	if len(result.DNS.StaticHosts) != 1 || result.DNS.StaticHosts[0].Ip[0][0] != 192 {
		t.Fatal("bootstrap not in DNS hosts")
	}
	for name, mutate := range map[string]func(*panel.DNSPolicy){
		"empty":         func(p *panel.DNSPolicy) { p.Resolvers = []panel.PolicyDNSResolver{} },
		"duplicate":     func(p *panel.DNSPolicy) { p.Resolvers[1].ID = p.Resolvers[0].ID },
		"no default":    func(p *panel.DNSPolicy) { p.Resolvers[1].Domains = []string{"full:x.test"} },
		"early default": func(p *panel.DNSPolicy) { p.Resolvers[0].Domains = []string{} },
		"block":         func(p *panel.DNSPolicy) { p.Resolvers[0].OutboundID = "block" },
		"unknown":       func(p *panel.DNSPolicy) { p.Resolvers[0].OutboundID = "missing" },
		"local":         func(p *panel.DNSPolicy) { p.Resolvers[1].Address = "https+local://resolver.test/dns-query" },
		"userinfo":      func(p *panel.DNSPolicy) { p.Resolvers[1].Address = "https://user:pass@resolver.test/" },
		"bootstrap":     func(p *panel.DNSPolicy) { p.Resolvers[1].BootstrapIP = "bad" },
		"cycle":         func(p *panel.DNSPolicy) { p.Resolvers[1].BootstrapIP = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := dnsV2Fixture()
			mutate(c.Data.Routing.DNSPolicy)
			if _, err := Build(c, false); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

func TestV2DNSIndependentBootstrapResolver(t *testing.T) {
	c := dnsV2Fixture()
	p := c.Data.Routing.DNSPolicy
	p.Resolvers[0].Domains = []string{"full:resolver.test"}
	p.Resolvers[1].BootstrapIP = ""
	if _, err := Build(c, false); err != nil {
		t.Fatalf("independent resolver rejected: %v", err)
	}
	// A domain-named proxy is allowed unless its DNS policy depends on itself.
	c.Data.Routing.Outbounds[0].Protocol = "socks"
	c.Data.Routing.Outbounds[0].Address = "proxy.test"
	c.Data.Routing.Outbounds[0].Port = 1080
	p.Resolvers[1].OutboundID = testOutboundID
	if _, err := Build(c, false); err == nil {
		t.Fatal("outbound DNS cycle accepted")
	}
	p.Resolvers[0].OutboundID = "direct"
	p.Resolvers[0].Domains = append(p.Resolvers[0].Domains, "full:proxy.test")
	if _, err := Build(c, false); err != nil {
		t.Fatalf("independent proxy bootstrap rejected: %v", err)
	}
}
