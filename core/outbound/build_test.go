package outbound

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
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

}
