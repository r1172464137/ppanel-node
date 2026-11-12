package outbound

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/perfect-panel/ppanel-node/api/panel"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// buildDNSPolicy compiles routing.dns into Xray's DNS configuration and the
// router rules for resolver queries.
//
//   - Resolvers are matched by domain in array order; the first match is
//     final (finalQuery) and its failure never falls back to another resolver
//     or to system DNS.
//   - Only the last resolver is the default; every other one is skipFallback,
//     so unmatched names reach exactly the default.
//   - Each network resolver has its policy ID as tag; a router rule sends its
//     queries to the chosen outbound (direct or a custom chain).
//   - bootstrap_ip becomes a hosts entry: the resolver is dialled at that IP
//     while TLS SNI and certificate checks keep the URL host.
func buildDNSPolicy(p *panel.RoutingPolicy) (*coreConf.DNSConfig, []json.RawMessage, error) {
	d := p.DNS
	servers := make([]map[string]any, 0, len(d.Resolvers))
	hosts := map[string]string{}
	var rules []json.RawMessage
	last := len(d.Resolvers) - 1
	for i, r := range d.Resolvers {
		entry := map[string]any{"finalQuery": true}
		if i != last {
			domains, err := buildDomainRules(r.Domains)
			if err != nil {
				return nil, nil, fmt.Errorf("dns resolver %d domains: %w", i+1, err)
			}
			entry["domains"], entry["skipFallback"] = domains, true
		}
		if r.Protocol == "system" {
			entry["address"] = "localhost"
			servers = append(servers, entry)
			continue
		}
		host, err := resolverHost(r.Protocol, r.Address)
		if err != nil {
			return nil, nil, fmt.Errorf("dns resolver %d: %w", i+1, err)
		}
		if net.ParseIP(host) == nil {
			if r.BootstrapIP != "" {
				hosts[host] = r.BootstrapIP
			} else if r.OutboundID == "direct" {
				// Resolving the resolver's own name would need this policy
				// (and possibly itself): no implicit system DNS, no loop.
				return nil, nil, fmt.Errorf("dns resolver %d: a direct resolver given by host name needs bootstrap_ip", i+1)
			}
		}
		switch r.Protocol {
		case "udp":
			h, port, err := parseDNSAddress(r.Address)
			if err != nil {
				return nil, nil, err
			}
			entry["address"], entry["port"] = h, port
		case "tcp":
			h, port, err := parseDNSAddress(r.Address)
			if err != nil {
				return nil, nil, err
			}
			entry["address"] = "tcp://" + net.JoinHostPort(h, strconv.Itoa(int(port)))
		case "https":
			entry["address"] = r.Address
		}
		entry["tag"] = r.ID
		servers = append(servers, entry)
		outboundTag := DefaultTag
		if r.OutboundID != "direct" {
			outboundTag = "routing_" + r.OutboundID
		}
		rule, err := json.Marshal(map[string]any{"inboundTag": []string{r.ID}, "outboundTag": outboundTag, "ruleTag": r.ID})
		if err != nil {
			return nil, nil, err
		}
		rules = append(rules, rule)
	}
	raw := map[string]any{"servers": servers, "queryStrategy": d.QueryStrategy}
	if len(hosts) > 0 {
		raw["hosts"] = hosts
	}
	body, err := json.Marshal(raw)
	if err != nil {
		return nil, nil, err
	}
	var cfg coreConf.DNSConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, nil, fmt.Errorf("dns policy: %w", err)
	}
	return &cfg, rules, nil
}

// hasEnabledIPRule reports whether target IPs must be rechecked after DNS.
func hasEnabledIPRule(p *panel.RoutingPolicy) bool {
	for _, r := range p.Rules {
		if r.Enabled != nil && *r.Enabled && r.Kind == "ip" {
			return true
		}
	}
	return false
}
