package outbound

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

func TestBuildDomainRulesCanonicalizesEverySupportedForm(t *testing.T) {
	got, err := buildDomainRules([]string{
		" example.com. ",
		"FULL:exact.example.",
		" KEYWORD:tracker ",
		"SuFfIx:example.net.",
		"DOMAIN:canonical.example",
		`ReGeX:(^|\.)tracker\.example$`,
		`REGEXP:(?i)^announce\.example$`,
		"GEOSITE:category-pt",
		"suffix:example.net",
		"",
	})
	if err != nil {
		t.Fatalf("buildDomainRules() error = %v", err)
	}
	want := []string{
		"full:example.com",
		"full:exact.example",
		"keyword:tracker",
		"domain:example.net",
		"domain:canonical.example",
		`regexp:(^|\.)tracker\.example$`,
		`regexp:(?i)^announce\.example$`,
		"geosite:category-pt",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildDomainRules() = %#v, want %#v", got, want)
	}
}

func TestBuildIPRulesAcceptsGeoIPAddressesAndCIDRs(t *testing.T) {
	got, err := buildIPRules([]string{
		" GEOIP:private ",
		"geoip:CN",
		"127.0.0.1",
		"10.2.3.4/8",
		"2001:0db8::1/32",
		"fc00::1/7",
		"geoip:private",
	})
	if err != nil {
		t.Fatalf("buildIPRules() error = %v", err)
	}
	want := []string{"geoip:private", "geoip:CN", "127.0.0.1", "10.0.0.0/8", "2001:db8::/32", "fc00::/7"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildIPRules() = %#v, want %#v", got, want)
	}
}

func TestRouteLabelGrammarMatchesWireContract(t *testing.T) {
	domains, err := buildDomainRules([]string{"geosite:A_b.c!-d@attr_1@!neg"})
	if err != nil || !reflect.DeepEqual(domains, []string{"geosite:A_b.c!-d@attr_1@!neg"}) {
		t.Fatalf("valid geosite label = %#v, %v", domains, err)
	}
	for _, rule := range []string{"geosite:_cn", "geosite:cn@attr.dot", "geosite:cn/other"} {
		if _, err := buildDomainRules([]string{rule}); err == nil {
			t.Errorf("unsafe geosite label %q accepted", rule)
		}
	}

	ips, err := buildIPRules([]string{"geoip:A_b-1"})
	if err != nil || !reflect.DeepEqual(ips, []string{"geoip:A_b-1"}) {
		t.Fatalf("valid geoip label = %#v, %v", ips, err)
	}
	for _, rule := range []string{"geoip:_cn", "geoip:cn.other", "geoip:cn@ads"} {
		if _, err := buildIPRules([]string{rule}); err == nil {
			t.Errorf("unsafe geoip label %q accepted", rule)
		}
	}
}

func TestBuildProtocolRulesCanonicalizeBitTorrentCase(t *testing.T) {
	got, err := buildProtocolRules([]string{" bittorrent ", "", "BitTorrent", "BITTORRENT"})
	if err != nil {
		t.Fatalf("buildProtocolRules() error = %v", err)
	}
	if !reflect.DeepEqual(got, []string{"bittorrent"}) {
		t.Fatalf("buildProtocolRules() = %#v", got)
	}
	for _, invalid := range []string{"http", "unknown-protocol"} {
		if _, err := buildProtocolRules([]string{invalid}); err == nil {
			t.Fatalf("buildProtocolRules(%q) succeeded", invalid)
		}
	}
}

func TestStructuredRuleParsersRejectInvalidInput(t *testing.T) {
	domainCases := []string{
		"geoip:private",
		"unknown:value",
		"full:",
		"example.com..",
		"full:BITTORRENT.",
		"suffix:BitTorrent",
		"domain:bittorrent.",
		"keyword:",
		"keyword:two words",
		"keyword:two\twords",
		`regex:(?=tracker)`,
		`regexp:(?<!tracker)example`,
		`regex:(tracker)\1`,
		`regex:[unterminated`,
		"-bad.example",
		"bad-.example",
		"bad..example",
		"bad_example",
		"example.com/path",
		"example com",
		"example.com\nother.example",
		string([]byte{0xff}),
	}
	for _, rule := range domainCases {
		if _, err := buildDomainRules([]string{rule}); err == nil {
			t.Errorf("buildDomainRules(%q) succeeded", rule)
		}
	}

	ipCases := []string{
		"geoip:",
		"geoip:../cn",
		"geosite:cn",
		"10.0.0.0/33",
		"2001:db8::/129",
		"127.0.0.1:443",
		"fe80::1%eth0",
	}
	for _, rule := range ipCases {
		if _, err := buildIPRules([]string{rule}); err == nil {
			t.Errorf("buildIPRules(%q) succeeded", rule)
		}
	}
}

func TestDomainRulesRejectMisclassifiedValuesWithCategoryErrors(t *testing.T) {
	for _, rule := range []string{
		"127.0.0.1",
		"2001:db8::1",
		"10.0.0.0/8",
		"full:127.0.0.1",
		"full:2001:db8::/32",
		"suffix:10.0.0.0/8",
		"domain:2001:db8::1",
	} {
		_, err := buildDomainRules([]string{rule})
		if err == nil || !strings.Contains(err.Error(), "IP rule field") {
			t.Errorf("buildDomainRules(%q) error = %v, want IP category guidance", rule, err)
		}
	}
	_, err := buildDomainRules([]string{"BiTtOrReNt."})
	if err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("bare bittorrent error = %v, want protocol category guidance", err)
	}
	if got, err := buildDomainRules([]string{"keyword:bittorrent"}); err != nil || !reflect.DeepEqual(got, []string{"keyword:bittorrent"}) {
		t.Fatalf("explicit domain keyword = %#v, %v", got, err)
	}
}

func TestRE2ValidationHasNoTextualFalsePositives(t *testing.T) {
	input := []string{
		`regex:\123`,
		`regex:[()=?<]+`,
		`regex:\Q(?=literal)(captured)\1\E`,
	}
	got, err := buildDomainRules(input)
	if err != nil {
		t.Fatalf("valid RE2 forms rejected: %v", err)
	}
	want := []string{
		`regexp:\123`,
		`regexp:[()=?<]+`,
		`regexp:\Q(?=literal)(captured)\1\E`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RE2 canonical forms = %#v, want %#v", got, want)
	}
}

func TestStructuredRuleParserLimits(t *testing.T) {
	tooLong := "regex:" + strings.Repeat("a", MaxRouteRuleBytes)
	if _, err := buildDomainRules([]string{tooLong}); err == nil || !strings.Contains(err.Error(), "exceeds 4096 raw bytes") {
		t.Fatalf("per-rule limit error = %v", err)
	}

	tooManyUnique := make([]string, MaxRouteRules+1)
	for i := range tooManyUnique {
		tooManyUnique[i] = fmt.Sprintf("keyword:value-%d", i)
	}
	if _, err := buildDomainRules(tooManyUnique); err == nil || !strings.Contains(err.Error(), "more than 1024 canonical unique") {
		t.Fatalf("canonical count limit error = %v", err)
	}
	duplicates := make([]string, MaxRouteRules+1)
	for i := range duplicates {
		duplicates[i] = "keyword:value"
	}
	if got, err := buildDomainRules(duplicates); err != nil || !reflect.DeepEqual(got, []string{"keyword:value"}) {
		t.Fatalf("canonical duplicate handling = %#v, %v", got, err)
	}
	rawFlood := make([]string, MaxRawRouteEntriesPerCategory+1)
	for i := range rawFlood {
		rawFlood[i] = "keyword:value"
	}
	if _, err := buildDomainRules(rawFlood); err == nil || !strings.Contains(err.Error(), "raw entries") {
		t.Fatalf("raw pre-bound error = %v", err)
	}

	largeRules := make([]string, 13)
	for i := range largeRules {
		largeRules[i] = "regex:" + strings.Repeat("a", MaxRouteRuleBytes-len("regexp:")-4) + fmt.Sprintf("%03d", i)
	}
	largeOutbound := []panel.Outbound{{Name: "large", Protocol: "unsupported", Rules: largeRules}}
	if _, err := Build(&panel.ServerConfigResponse{Data: &panel.Data{Outbound: &largeOutbound}}, false); err == nil || !strings.Contains(err.Error(), "outbound route rules exceed 49152 canonical payload bytes") {
		t.Fatalf("outbound payload-byte limit error = %v", err)
	}

	uniqueIPs := make([]string, MaxRouteRules)
	for i := range uniqueIPs {
		uniqueIPs[i] = fmt.Sprintf("1.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255)
	}
	outbounds := make([]panel.Outbound, 5)
	for i := range outbounds {
		outbounds[i] = panel.Outbound{Name: fmt.Sprintf("bulk-%d", i), Protocol: "unsupported", IPRules: append([]string(nil), uniqueIPs...)}
	}
	if _, err := Build(&panel.ServerConfigResponse{Data: &panel.Data{Outbound: &outbounds}}, false); err == nil || !strings.Contains(err.Error(), "outbound route rules exceed 4096 canonical values") {
		t.Fatalf("outbound canonical aggregate-count error = %v", err)
	}

	tooManyOutbounds := make([]panel.Outbound, MaxNodeOutbounds+1)
	if err := validateRouteConfigRawLimits(&panel.Data{Outbound: &tooManyOutbounds}); err == nil || !strings.Contains(err.Error(), "128 outbounds") {
		t.Fatalf("outbound count error = %v", err)
	}
}

func TestLargeBackendValidGlobalBlocksAreIndependentFromOutboundAggregate(t *testing.T) {
	blockDomains := make([]string, 800)
	for i := range blockDomains {
		blockDomains[i] = fmt.Sprintf("host-%04d-%s.example", i, strings.Repeat("x", 40))
	}
	blockIPs := make([]string, MaxRouteRules)
	for i := range blockIPs {
		blockIPs[i] = fmt.Sprintf("2001:db8:aaaa:bbbb:cccc:dddd:1:%x/128", i+1)
	}
	blockProtocols := []string{"bittorrent"}

	canonicalDomains, err := buildDomainRules(blockDomains)
	if err != nil {
		t.Fatal(err)
	}
	canonicalIPs, err := buildIPRules(blockIPs)
	if err != nil {
		t.Fatal(err)
	}
	canonicalProtocols, err := buildProtocolRules(blockProtocols)
	if err != nil {
		t.Fatal(err)
	}
	canonicalBytes := 0
	persistedSizes := make(map[string]int, 3)
	for _, group := range []struct {
		name   string
		values []string
	}{
		{name: "block", values: canonicalDomains},
		{name: "block_ips", values: canonicalIPs},
		{name: "block_protocols", values: canonicalProtocols},
	} {
		persisted, err := json.Marshal(group.values)
		if err != nil {
			t.Fatal(err)
		}
		persistedSizes[group.name] = len(persisted)
		if len(persisted) >= MaxPersistedRouteJSONBytes {
			t.Fatalf("%s fixture is %d bytes, want backend-valid persisted JSON below %d", group.name, len(persisted), MaxPersistedRouteJSONBytes)
		}
		for _, value := range group.values {
			canonicalBytes += len(value)
		}
	}
	t.Logf("backend-valid globals: persisted block=%d block_ips=%d block_protocols=%d; canonical payload=%d (> outbound %d)", persistedSizes["block"], persistedSizes["block_ips"], persistedSizes["block_protocols"], canonicalBytes, MaxOutboundAggregateBytes)
	if canonicalBytes <= MaxOutboundAggregateBytes {
		t.Fatalf("global fixture is only %d canonical bytes; it must exceed outbound-only %d-byte limit", canonicalBytes, MaxOutboundAggregateBytes)
	}

	if _, err := Build(&panel.ServerConfigResponse{Data: &panel.Data{
		Block: &blockDomains, BlockIPs: &blockIPs, BlockProtocols: &blockProtocols,
	}}, false); err != nil {
		t.Fatalf("backend-valid large global block categories were rejected: %v", err)
	}
}

func TestExcessiveDirectGlobalBlockPayloadIsBounded(t *testing.T) {
	blockDomains := make([]string, MaxRouteRules)
	for i := range blockDomains {
		blockDomains[i] = fmt.Sprintf("keyword:%04d-%s", i, strings.Repeat("x", 190))
	}
	_, err := Build(&panel.ServerConfigResponse{Data: &panel.Data{Block: &blockDomains}}, false)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("global block route rules exceed %d canonical payload bytes", MaxGlobalBlockAggregateBytes)) {
		t.Fatalf("excessive direct global block payload error = %v", err)
	}
}

func TestDNSRulesAreExcludedFromStructuredAggregate(t *testing.T) {
	domains := make([]string, MaxRouteRules)
	for i := range domains {
		domains[i] = fmt.Sprintf("keyword:dns-%04d-%s", i, strings.Repeat("x", 48))
	}
	dns := []panel.DNSItem{{Address: "8.8.8.8", Domains: domains}}
	if _, err := Build(&panel.ServerConfigResponse{Data: &panel.Data{DNS: &dns}}, false); err != nil {
		t.Fatalf("DNS was incorrectly included in 48 KiB structured route aggregate: %v", err)
	}
}

func TestBuildBuildsTypedOutbound(t *testing.T) {
	dns := []panel.DNSItem{}
	block := []string{}
	outbound := []panel.Outbound{
		{
			Name:      "proxy",
			Protocol:  "vless",
			Address:   "example.com",
			Port:      443,
			UUID:      "00000000-0000-0000-0000-000000000001",
			Security:  "tls",
			SNI:       "example.com",
			Transport: "websocket",
			Host:      "example.com",
			Path:      "/ws",
			Rules:     []string{"suffix:example.com"},
		},
	}
	protocols := []panel.Protocol{}

	result, err := Build(&panel.ServerConfigResponse{
		Data: &panel.Data{
			IPStrategy: "prefer_ipv4",
			DNS:        &dns,
			Block:      &block,
			Outbound:   &outbound,
			Protocols:  &protocols,
		},
	}, false)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if got := len(result.Outbounds); got != 4 {
		t.Fatalf("outbounds len = %d, want 4", got)
	}
	if got := len(result.Router.GetRule()); got != 2 {
		t.Fatalf("route rules len = %d, want default DNS + custom outbound", got)
	}
}

func TestBuildUsesRawOutboundSettings(t *testing.T) {
	dns := []panel.DNSItem{}
	block := []string{}
	outbound := []panel.Outbound{
		{
			Name:     "direct-cn",
			Protocol: "direct",
			Settings: `{"domainStrategy":"UseIPv4"}`,
			Rules:    []string{"suffix:cn"},
		},
	}
	protocols := []panel.Protocol{}

	result, err := Build(&panel.ServerConfigResponse{
		Data: &panel.Data{
			IPStrategy: "prefer_ipv4",
			DNS:        &dns,
			Block:      &block,
			Outbound:   &outbound,
			Protocols:  &protocols,
		},
	}, false)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if got := len(result.Outbounds); got != 4 {
		t.Fatalf("outbounds len = %d, want 4", got)
	}
	if got := result.Outbounds[3].Tag; got != "direct-cn" {
		t.Fatalf("custom outbound tag = %q, want direct-cn", got)
	}
	if got := len(result.Router.GetRule()); got != 2 {
		t.Fatalf("route rules len = %d, want default DNS + custom outbound", got)
	}
}

func TestBuildSkipsUnsupportedOutboundWithoutRawSettings(t *testing.T) {
	dns := []panel.DNSItem{}
	block := []string{}
	outbound := []panel.Outbound{
		{
			Name:     "legacy-naive",
			Protocol: "naive",
			Address:  "example.com",
			Port:     443,
			Rules:    []string{"suffix:example.com"},
		},
	}
	protocols := []panel.Protocol{}

	result, err := Build(&panel.ServerConfigResponse{
		Data: &panel.Data{
			IPStrategy: "prefer_ipv4",
			DNS:        &dns,
			Block:      &block,
			Outbound:   &outbound,
			Protocols:  &protocols,
		},
	}, false)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if got := len(result.Outbounds); got != 3 {
		t.Fatalf("outbounds len = %d, want only default outbounds", got)
	}
	if got := len(result.Router.GetRule()); got != 1 {
		t.Fatalf("route rules len = %d, want only default DNS rule", got)
	}
}

func TestTUICOutboundUsesID(t *testing.T) {
	item := panel.Outbound{Name: "tuic", Protocol: "tuic", Address: "example.com", Port: 443, UUID: "00000000-0000-0000-0000-000000000001", Password: "password"}
	result, err := Build(&panel.ServerConfigResponse{Data: &panel.Data{Protocols: &[]panel.Protocol{}, Outbound: &[]panel.Outbound{item}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outbounds) != 4 {
		t.Fatal("TUIC outbound was silently dropped")
	}
}

func TestInvalidOutboundIsNotSilentlyDropped(t *testing.T) {
	item := panel.Outbound{Name: "invalid-tls", Protocol: "vless", Address: "example.com", Port: 443, UUID: "00000000-0000-0000-0000-000000000001", Security: "tls", AllowInsecure: true}
	_, err := Build(&panel.ServerConfigResponse{Data: &panel.Data{Protocols: &[]panel.Protocol{}, Outbound: &[]panel.Outbound{item}}}, false)
	if err == nil {
		t.Fatal("removed allowInsecure setting was silently accepted")
	}
}

func TestHysteria2OutboundUsesTransportAuthentication(t *testing.T) {
	stream, err := buildOutboundStreamConfig(panel.Outbound{Protocol: "hysteria2", UUID: "user-id", Password: "auth-token"})
	if err != nil {
		t.Fatal(err)
	}
	if stream.HysteriaSettings == nil || stream.HysteriaSettings.Version != 2 || stream.HysteriaSettings.Auth != "auth-token" {
		t.Fatalf("Hysteria settings = %+v", stream.HysteriaSettings)
	}
}

func TestBuildCreatesSeparateORRulesInRequiredPriorityOrder(t *testing.T) {
	blockDomains := []string{"blocked.example"}
	blockIPs := []string{"203.0.113.0/24"}
	blockProtocols := []string{"bittorrent"}
	outbounds := []panel.Outbound{
		{
			Name: "outbound-1", Protocol: "direct",
			Rules: []string{"first.example"}, IPRules: []string{"198.51.100.0/24"}, ProtocolRules: []string{"bittorrent"},
		},
		{
			Name: "outbound-2", Protocol: "direct",
			Rules: []string{"second.example"}, IPRules: []string{"192.0.2.0/24"}, ProtocolRules: []string{"bittorrent"},
		},
	}
	result, err := Build(&panel.ServerConfigResponse{Data: &panel.Data{
		Block: &blockDomains, BlockIPs: &blockIPs, BlockProtocols: &blockProtocols,
		Outbound: &outbounds, Protocols: &[]panel.Protocol{},
	}}, false)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	rules := result.Router.GetRule()
	if len(rules) != 10 {
		t.Fatalf("route rules len = %d, want DNS + 3 block + 3 per outbound", len(rules))
	}
	wantTags := []string{DNSTag, BlockTag, BlockTag, BlockTag, "outbound-1", "outbound-1", "outbound-1", "outbound-2", "outbound-2", "outbound-2"}
	wantMatchers := []string{"dns", "protocol", "ip", "domain", "domain", "ip", "protocol", "domain", "ip", "protocol"}
	for i, rule := range rules {
		if got := rule.GetTag(); got != wantTags[i] {
			t.Errorf("rule %d tag = %q, want %q", i, got, wantTags[i])
		}
		if i == 0 {
			continue
		}
		categories := 0
		matcher := ""
		if len(rule.GetDomain()) > 0 {
			categories++
			matcher = "domain"
		}
		if len(rule.GetIp()) > 0 {
			categories++
			matcher = "ip"
		}
		if len(rule.GetProtocol()) > 0 {
			categories++
			matcher = "protocol"
		}
		if categories != 1 {
			t.Errorf("rule %d combines %d matcher categories; domain=%d ip=%d protocol=%d", i, categories, len(rule.GetDomain()), len(rule.GetIp()), len(rule.GetProtocol()))
		}
		if matcher != wantMatchers[i] {
			t.Errorf("rule %d matcher = %q, want %q", i, matcher, wantMatchers[i])
		}
	}
}

func TestBuildRejectsInvalidRulesOnEveryOutboundField(t *testing.T) {
	tests := []struct {
		name     string
		outbound panel.Outbound
	}{
		{name: "legacy domain", outbound: panel.Outbound{Rules: []string{"geoip:private"}}},
		{name: "IP", outbound: panel.Outbound{IPRules: []string{"10.0.0.0/33"}}},
		{name: "protocol", outbound: panel.Outbound{ProtocolRules: []string{"http"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			item := test.outbound
			item.Name = "must-fail"
			// Even an otherwise unsupported outbound may not hide malformed rules.
			item.Protocol = "unsupported"
			_, err := Build(&panel.ServerConfigResponse{Data: &panel.Data{
				Outbound: &[]panel.Outbound{item}, Protocols: &[]panel.Protocol{},
			}}, false)
			if err == nil {
				t.Fatal("Build() accepted an invalid outbound rule")
			}
			if !strings.Contains(err.Error(), "must-fail") {
				t.Fatalf("Build() error = %v, want outbound context", err)
			}
		})
	}
}

func TestBuildRejectsInvalidGlobalRules(t *testing.T) {
	tests := []struct {
		name string
		data *panel.Data
	}{
		{name: "domain", data: &panel.Data{Block: &[]string{"geoip:private"}}},
		{name: "IP", data: &panel.Data{BlockIPs: &[]string{"10.0.0.0/33"}}},
		{name: "protocol", data: &panel.Data{BlockProtocols: &[]string{"unknown"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.data.Protocols = &[]panel.Protocol{}
			if _, err := Build(&panel.ServerConfigResponse{Data: test.data}, false); err == nil {
				t.Fatal("Build() accepted an invalid global rule")
			}
		})
	}
}
