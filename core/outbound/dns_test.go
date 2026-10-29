package outbound

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	xnet "github.com/xtls/xray-core/common/net"
)

func TestUDPResolverAddressPortProjection(t *testing.T) {
	cases := []struct {
		name string
		item panel.DNSItem
		host string
		port uint16
	}{
		{"ipv4-default", panel.DNSItem{Address: "1.1.1.1"}, "1.1.1.1", 53},
		{"ipv4-port", panel.DNSItem{Proto: "udp", Address: "1.1.1.1:5353"}, "1.1.1.1", 5353},
		{"canonical-protocol", panel.DNSItem{Proto: " UDP ", Address: "1.1.1.1:5353"}, "1.1.1.1", 5353},
		{"hostname", panel.DNSItem{Proto: "udp", Address: "DNS.Example.COM.:8053"}, "dns.example.com.", 8053},
		{"hostname-default", panel.DNSItem{Address: "dns.example.com"}, "dns.example.com", 53},
		{"numeric-hostname", panel.DNSItem{Address: "123.456"}, "123.456", 53},
		{"bare-ipv6", panel.DNSItem{Address: "2001:db8::53"}, "2001:db8::53", 53},
		{"bracket-ipv6", panel.DNSItem{Address: "[2001:db8::53]"}, "2001:db8::53", 53},
		{"ipv6-port", panel.DNSItem{Proto: "udp", Address: "[2001:db8::53]:5353"}, "2001:db8::53", 5353},
		{"localhost-special", panel.DNSItem{Proto: "udp", Address: "LOCALHOST:5300"}, "localhost.", 5300},
		{"fakedns-special", panel.DNSItem{Address: "fakedns"}, "fakedns.", 53},
		{"max-port", panel.DNSItem{Address: "dns.example:65535"}, "dns.example", 65535},
		{"max-host-and-port", panel.DNSItem{Address: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) + ".:65535"}, strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) + ".", 65535},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseDNSResolver(tc.item)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.protocol != "udp" || parsed.host != tc.host || parsed.port != tc.port {
				t.Fatalf("normalized=%+v", parsed)
			}
			cfg := orderedFixture()
			cfg.Data.DNS = &[]panel.DNSItem{tc.item}
			built, err := Build(cfg, false)
			if err != nil {
				t.Fatal(err)
			}
			if len(built.DNS.NameServer) != 2 {
				t.Fatalf("nameservers=%d", len(built.DNS.NameServer))
			}
			endpoint := built.DNS.NameServer[1].GetAddress()
			if endpoint.Network != xnet.Network_UDP || endpoint.Port != uint32(tc.port) {
				t.Fatalf("endpoint=%+v", endpoint)
			}
			address := endpoint.Address.AsAddress()
			if ip := net.ParseIP(tc.host); ip != nil {
				if !address.Family().IsIP() || !address.IP().Equal(ip) {
					t.Fatalf("address=%v, want IP %s", address, tc.host)
				}
			} else if !address.Family().IsDomain() || address.Domain() != tc.host {
				t.Fatalf("address=%v, want domain %s", address, tc.host)
			}
		})
	}
}

func TestInvalidUDPResolversFailClosed(t *testing.T) {
	for _, protocol := range []string{"tcp", "tls", "https", "quic", "dns", "unknown", strings.Repeat("u", 65)} {
		t.Run("proto="+protocol, func(t *testing.T) {
			if _, err := parseDNSResolver(panel.DNSItem{Proto: protocol, Address: "1.1.1.1"}); err == nil {
				t.Fatal("unsupported DNS protocol accepted")
			}
		})
	}
	for _, name := range []string{"example.com", " ", "\n"} {
		if _, err := parseDNSResolver(panel.DNSItem{Address: "1.1.1.1", ServerName: name}); err == nil {
			t.Fatalf("server_name %q accepted", name)
		}
	}
	bad := []string{
		"", " ", " 1.1.1.1", "1.1.1.1 ", "udp://1.1.1.1", "https://dns.example/dns-query", "user@dns.example", "dns.example/path", "dns.example?x=1", "dns.example#frag", "dns.example\\bad",
		"1.2.3.999", "01.2.3.4", "dns..example", "-dns.example", "dns_.example", ".", strings.Repeat("a", 64) + ".example",
		":53", "dns.example:", "dns.example:0", "dns.example:65536", "dns.example:+53", "dns.example:-1", "dns.example:abc", "dns.example:53:44", "dns.example:" + strings.Repeat("0", 261),
		"[::1", "::1]", "[127.0.0.1]", "[::1]:0", "[::1]:65536", "[::1]:53:7", "[::1]tail", "[fe80::1%eth0]:53", "2001:db8::zz", "2001:db8:::1",
	}
	for _, address := range bad {
		t.Run(fmt.Sprintf("address=%q", address), func(t *testing.T) {
			if _, err := parseDNSResolver(panel.DNSItem{Proto: "udp", Address: address}); err == nil {
				t.Fatalf("invalid DNS address accepted: %q", address)
			}
			cfg := orderedFixture()
			cfg.Data.DNS = &[]panel.DNSItem{{Proto: "udp", Address: address}}
			if err := ValidateDNS(cfg.Data); err == nil {
				t.Fatal("invalid DNS passed candidate validation")
			}
			if _, err := Build(cfg, false); err == nil {
				t.Fatal("invalid DNS built")
			}
		})
	}
	cfg := orderedFixture()
	cfg.Data.DNS = &[]panel.DNSItem{{Address: "1.1.1.1", Domains: []string{"geoip:private"}}}
	if err := ValidateDNS(cfg.Data); err == nil {
		t.Fatal("invalid DNS domain rule accepted")
	}
}

func TestDNSDomainRulesRemainCanonical(t *testing.T) {
	item := panel.DNSItem{Address: "1.1.1.1:5300", Domains: []string{"Example.COM.", "suffix:example.net", "Example.COM."}}
	resolver, err := parseDNSResolver(item)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"full:Example.COM", "domain:example.net"}
	if len(resolver.domains) != len(want) {
		t.Fatalf("domains=%v", resolver.domains)
	}
	for i, v := range want {
		if resolver.domains[i] != v {
			t.Fatalf("domains=%v", resolver.domains)
		}
	}
	cfg := orderedFixture()
	cfg.Data.DNS = &[]panel.DNSItem{item}
	built, err := Build(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(built.DNS.NameServer[1].Domain); got != 2 {
		t.Fatalf("compiled DNS domains=%d", got)
	}
}
