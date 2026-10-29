package outbound

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/xtls/xray-core/proxy/shadowsocks"
)

const testOutboundID = "ob_11111111-1111-4111-8111-111111111111"

func ruleID(i int) string { return fmt.Sprintf("rr_11111111-1111-4111-8111-%012x", i+1) }
func boolp(v bool) *bool  { return &v }
func orderedFixture() *panel.ServerConfigResponse {
	return &panel.ServerConfigResponse{Data: &panel.Data{Protocols: &[]panel.Protocol{}, Routing: &panel.RoutingPolicy{
		Version: 1, Outbounds: []panel.Outbound{{ID: testOutboundID, Name: "proxy", Protocol: "direct"}},
		Rules: []panel.RouteRule{
			{ID: ruleID(0), Enabled: boolp(true), Kind: "domain", Values: []string{"special.example"}, OutboundID: testOutboundID},
			{ID: ruleID(1), Enabled: boolp(false), Kind: "domain", Values: []string{"disabled.example"}, OutboundID: "block"},
			{ID: ruleID(2), Enabled: boolp(true), Kind: "domain", Values: []string{"suffix:example"}, OutboundID: "block"},
			{ID: ruleID(3), Enabled: boolp(true), Kind: "ip", Values: []string{"192.0.2.0/24"}, OutboundID: "direct"},
		}, DefaultOutboundID: testOutboundID, RoutingIdentity: panel.RoutingIdentity{Mode: "ordered-v1-inherited", Source: "global", SourceRevision: 1},
	}}}
}
func TestOrderedBuildPreservesRuleOrderAndExplicitDefault(t *testing.T) {
	cfg := orderedFixture()
	result, err := Build(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outbounds[0].Tag != "routing_"+testOutboundID {
		t.Fatalf("default = %s", result.Outbounds[0].Tag)
	}
	want := []string{DNSTag, "routing_" + testOutboundID, BlockTag, DefaultTag}
	if len(result.Router.Rule) != len(want) {
		t.Fatalf("rules = %d", len(result.Router.Rule))
	}
	wantRuleIDs := []string{"", ruleID(0), ruleID(2), ruleID(3)}
	for i, r := range result.Router.Rule {
		if r.GetTag() != want[i] {
			t.Errorf("rule %d = %s, want %s", i, r.GetTag(), want[i])
		}
		if r.GetRuleTag() != wantRuleIDs[i] {
			t.Errorf("rule %d stable ID=%q want %q", i, r.GetRuleTag(), wantRuleIDs[i])
		}
	}
	if len(result.Router.Rule[1].Domain) != 1 || len(result.Router.Rule[3].Ip) != 1 {
		t.Fatal("rule kinds were combined")
	}
	cfg.Data.Routing.DefaultOutboundID = "block"
	result, err = Build(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outbounds[0].Tag != BlockTag {
		t.Fatal("block must be the first outbound when selected as default")
	}
}
func TestOrderedRejectsInvalidEvenWhenDisabled(t *testing.T) {
	cases := map[string]func(*panel.Data){
		"unknown version":      func(d *panel.Data) { d.Routing.Version = 2 },
		"null policy":          func(d *panel.Data) { d.Routing = nil; d.RoutingPresent = true },
		"unknown mode":         func(d *panel.Data) { d.Routing.Mode = "future" },
		"bad identity":         func(d *panel.Data) { d.Routing.SourceRevision = 0 },
		"mixed":                func(d *panel.Data) { d.Block = &[]string{"example.com"} },
		"explicit mixed empty": func(d *panel.Data) { d.LegacyRoutingPresent = true },
		"missing enabled":      func(d *panel.Data) { d.Routing.Rules[1].Enabled = nil },
		"unknown kind":         func(d *panel.Data) { d.Routing.Rules[1].Kind = "future" },
		"bad value":            func(d *panel.Data) { d.Routing.Rules[1].Values = []string{"geoip:private"} },
		"empty values":         func(d *panel.Data) { d.Routing.Rules[1].Values = []string{""} },
		"bad reference":        func(d *panel.Data) { d.Routing.Rules[1].OutboundID = "missing" },
		"bad default":          func(d *panel.Data) { d.Routing.DefaultOutboundID = "dns_out" },
		"bad rule id":          func(d *panel.Data) { d.Routing.Rules[1].ID = "bad" },
		"duplicate rule":       func(d *panel.Data) { d.Routing.Rules[1].ID = d.Routing.Rules[0].ID },
		"duplicate outbound":   func(d *panel.Data) { d.Routing.Outbounds = append(d.Routing.Outbounds, d.Routing.Outbounds[0]) },
		"nested legacy":        func(d *panel.Data) { d.Routing.Outbounds[0].Rules = []string{"example.com"} },
		"invalid raw":          func(d *panel.Data) { d.Routing.Outbounds[0].Settings = `[]` },
		"unsupported":          func(d *panel.Data) { d.Routing.Outbounds[0].Protocol = "future" },
		"ignored plugin":       func(d *panel.Data) { d.Routing.Outbounds[0].Plugin = "obfs" },
		"remark":               func(d *panel.Data) { d.Routing.Rules[1].Remark = strings.Repeat("界", 201) },
		"raw entry flood":      func(d *panel.Data) { d.Routing.Rules[1].Values = make([]string, MaxRouteRules+1) },
		"too many rows":        func(d *panel.Data) { d.Routing.Rules = make([]panel.RouteRule, MaxOrderedRules+1) },
		"too many outbounds":   func(d *panel.Data) { d.Routing.Outbounds = make([]panel.Outbound, MaxNodeOutbounds+1) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := orderedFixture()
			change(cfg.Data)
			if _, err := Build(cfg, false); err == nil {
				t.Fatal("invalid ordered policy accepted")
			}
		})
	}
}
func TestOrderedRawAndCanonicalBudgets(t *testing.T) {
	cfg := orderedFixture()
	cfg.Data.Routing.Outbounds = []panel.Outbound{}
	cfg.Data.Routing.DefaultOutboundID = "direct"
	cfg.Data.Routing.Rules = nil
	// Exact 256 KiB of canonical matching text, <= is valid.
	for i := 0; i < 64; i++ {
		cfg.Data.Routing.Rules = append(cfg.Data.Routing.Rules, panel.RouteRule{ID: ruleID(i), Enabled: boolp(false), Kind: "domain", Values: []string{"keyword:" + strings.Repeat("x", 4088)}, OutboundID: "block"})
	}
	if err := ValidateOrdered(cfg.Data); err != nil {
		t.Fatalf("exact budget rejected: %v", err)
	}
	cfg.Data.Routing.Rules = append(cfg.Data.Routing.Rules, panel.RouteRule{ID: ruleID(64), Enabled: boolp(false), Kind: "domain", Values: []string{"a.example"}, OutboundID: "block"})
	if err := ValidateOrdered(cfg.Data); err == nil {
		t.Fatal("oversized canonical budget accepted")
	}

	// Seven legacy-sized groups (7168 distinct entries) fit the new budget.
	cfg.Data.Routing.Rules = []panel.RouteRule{}
	for i := 0; i < 7; i++ {
		values := make([]string, 1024)
		for j := range values {
			values[j] = fmt.Sprintf("keyword:legacy-%d-%04d", i, j)
		}
		cfg.Data.Routing.Rules = append(cfg.Data.Routing.Rules, panel.RouteRule{ID: ruleID(i), Enabled: boolp(true), Kind: "domain", Values: values, OutboundID: "direct"})
	}
	if err := ValidateOrdered(cfg.Data); err != nil {
		t.Fatalf("legacy-sized migration rejected: %v", err)
	}
	values := make([]string, 1024)
	for i := range values {
		values[i] = fmt.Sprintf("keyword:extra-%04d", i)
	}
	cfg.Data.Routing.Rules = append(cfg.Data.Routing.Rules, panel.RouteRule{ID: ruleID(7), Enabled: boolp(true), Kind: "domain", Values: values, OutboundID: "direct"})
	if err := ValidateOrdered(cfg.Data); err != nil {
		t.Fatalf("8192-value limit rejected: %v", err)
	}
	cfg.Data.Routing.Rules = append(cfg.Data.Routing.Rules, panel.RouteRule{ID: ruleID(8), Enabled: boolp(false), Kind: "domain", Values: []string{"keyword:extra-0000"}, OutboundID: "direct"})
	if err := ValidateOrdered(cfg.Data); err == nil {
		t.Fatal("8193 raw values accepted")
	}
	cfg.Data.Routing.Rules = cfg.Data.Routing.Rules[:8]
	cfg.Data.Routing.Rules[0].Values = append(cfg.Data.Routing.Rules[0].Values, "keyword:duplicate")
	if err := ValidateOrdered(cfg.Data); err == nil {
		t.Fatal("raw per-rule limit ignored")
	}
}

func TestOrdered128OutboundBuildBoundary(t *testing.T) {
	cfg := orderedFixture()
	cfg.Data.Routing.Rules = []panel.RouteRule{}
	cfg.Data.Routing.DefaultOutboundID = "direct"
	cfg.Data.Routing.Outbounds = make([]panel.Outbound, 128)
	for i := range cfg.Data.Routing.Outbounds {
		cfg.Data.Routing.Outbounds[i] = panel.Outbound{ID: fmt.Sprintf("ob_11111111-1111-4111-8111-%012x", i+1), Name: fmt.Sprintf("ob-%d", i), Protocol: "direct"}
	}
	built, err := Build(cfg, false)
	if err != nil || len(built.Outbounds) != 131 {
		t.Fatalf("128 outbound build = %v, %v", built, err)
	}
	cfg.Data.Routing.Outbounds = append(cfg.Data.Routing.Outbounds, panel.Outbound{})
	if _, err := Build(cfg, false); err == nil {
		t.Fatal("129 outbounds accepted")
	}
}

func TestOrderedShadowsocksUOTFailsClosedAndFinalConfig(t *testing.T) {
	cfg := orderedFixture()
	cfg.Data.Routing.Outbounds[0] = panel.Outbound{ID: testOutboundID, Name: "ss", Protocol: "shadowsocks", Address: "127.0.0.1", Port: 1234, Cipher: "aes-128-gcm", Password: "secret"}
	for name, mutate := range map[string]func(*panel.Outbound){
		"uot true": func(o *panel.Outbound) { o.UoT = true },
		"version":  func(o *panel.Outbound) { o.UoTVersion = 2 },
		"raw true": func(o *panel.Outbound) {
			o.Settings = `{"address":"127.0.0.1","port":1234,"method":"aes-128-gcm","password":"secret","uot":true}`
		},
		"raw nested": func(o *panel.Outbound) { o.Settings = `{"servers":[{"uotVersion":2}]}` },
		"raw stream": func(o *panel.Outbound) { o.StreamSettings = `{"sockopt":{"uot":true}}` },
		"raw duplicate": func(o *panel.Outbound) {
			o.Settings = `{"address":"127.0.0.1","port":1234,"method":"aes-128-gcm","password":"secret","uot":true,"uot":false}`
		},
	} {
		t.Run(name, func(t *testing.T) {
			original := cfg.Data.Routing.Outbounds[0]
			defer func() { cfg.Data.Routing.Outbounds[0] = original }()
			mutate(&cfg.Data.Routing.Outbounds[0])
			if _, err := Build(cfg, false); err == nil {
				t.Fatal("unsupported UoT was ignored")
			}
		})
	}
	protocol, raw, err := buildOutboundSettings(cfg.Data.Routing.Outbounds[0])
	if err != nil || protocol != "shadowsocks" {
		t.Fatal(err)
	}
	if err := validateNoUOT(cfg.Data.Routing.Outbounds[0]); err != nil || strings.Contains(strings.ToLower(string(*raw)), "uot") {
		t.Fatalf("ordered settings = %s, %v", *raw, err)
	}
	built, err := Build(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	message, err := built.Outbounds[0].ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	ss, ok := message.(*shadowsocks.ClientConfig)
	if !ok || ss.Server == nil {
		t.Fatalf("wrong final client config: %T", message)
	}
	if ss.ProtoReflect().Descriptor().Fields().ByName("uot") != nil {
		t.Fatal("dependency unexpectedly exposes UoT")
	}
}

func TestOrderedJSONByteLimitInclusive(t *testing.T) {
	cfg := orderedFixture()
	p := cfg.Data.Routing
	p.Rules = []panel.RouteRule{}
	p.Outbounds[0].Rules, p.Outbounds[0].IPRules, p.Outbounds[0].ProtocolRules = []string{}, []string{}, []string{}
	p.Outbounds[0].Settings = `{"padding":""}`
	content := func() []byte {
		b, err := json.Marshal(struct {
			Version   int               `json:"version"`
			Outbounds []panel.Outbound  `json:"outbounds"`
			Rules     []panel.RouteRule `json:"rules"`
			Default   string            `json:"default_outbound_id"`
		}{p.Version, p.Outbounds, p.Rules, p.DefaultOutboundID})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	missing := MaxOrderedJSONBytes - len(content())
	if missing <= 0 {
		t.Fatal("fixture too large")
	}
	p.Outbounds[0].Settings = `{"padding":"` + strings.Repeat("x", missing) + `"}`
	if len(content()) != MaxOrderedJSONBytes {
		t.Fatalf("fixture = %d bytes", len(content()))
	}
	if err := ValidateOrdered(cfg.Data); err != nil {
		t.Fatalf("exact 1 MiB rejected: %v", err)
	}
	p.Outbounds[0].Settings = `{"padding":"` + strings.Repeat("x", missing+1) + `"}`
	if err := ValidateOrdered(cfg.Data); err == nil {
		t.Fatal("1 MiB + 1 accepted")
	}
	// A bare domain grows by "full:" during canonicalization. Raw input can
	// fit while the final package exceeds the inclusive 1 MiB limit.
	p.Rules = []panel.RouteRule{{ID: ruleID(0), Enabled: boolp(true), Kind: "domain", Values: []string{"example.com"}, OutboundID: "direct"}}
	p.Outbounds[0].Settings = `{"padding":""}`
	missing = MaxOrderedJSONBytes - len(content())
	p.Outbounds[0].Settings = `{"padding":"` + strings.Repeat("x", missing) + `"}`
	if len(content()) != MaxOrderedJSONBytes {
		t.Fatal("raw expansion fixture is not at the limit")
	}
	if err := ValidateOrdered(cfg.Data); err == nil {
		t.Fatal("canonical package expansion beyond 1 MiB accepted")
	}
}
