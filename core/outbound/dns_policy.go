package outbound

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// PolicyDNSHost identifies the resolver transport peer, not the queried domain.
func PolicyDNSHost(r panel.PolicyDNSResolver) (string, uint16, error) {
	switch r.Protocol {
	case "udp", "tcp":
		return parseDNSAddress(r.Address)
	case "https":
		u, err := url.Parse(r.Address)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(r.Address, "\r\n\t") {
			return "", 0, fmt.Errorf("DNS resolver requires an HTTPS URL without credentials or fragment")
		}
		port := uint16(443)
		if u.Port() != "" {
			port, err = parseDNSPort(u.Port())
			if err != nil {
				return "", 0, err
			}
		}
		host := u.Hostname()
		if ip, err := netip.ParseAddr(host); err == nil {
			if ip.Zone() != "" {
				return "", 0, fmt.Errorf("scoped resolver address")
			}
			return ip.String(), port, nil
		}
		host, err = validateDNSHostname(host)
		return host, port, err
	default:
		return "", 0, fmt.Errorf("unsupported DNS resolver protocol")
	}
}

func PolicyDNSTag(id string) string { return "pp_dns_" + id }

func policyBootstrapHosts(policy *panel.DNSPolicy) (map[string]string, error) {
	hosts := make(map[string]string)
	for _, resolver := range policy.Resolvers {
		if resolver.BootstrapIP == "" {
			continue
		}
		host, _, err := PolicyDNSHost(resolver)
		if err != nil {
			return nil, err
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		ip, err := netip.ParseAddr(resolver.BootstrapIP)
		if err != nil {
			return nil, err
		}
		if previous, ok := hosts[host]; ok && previous != ip.String() {
			return nil, fmt.Errorf("conflicting bootstrap IPs for resolver hostname")
		}
		hosts[host] = ip.String()
	}
	return hosts, nil
}

func validateDNSPolicy(p *panel.RoutingPolicy) error {
	policy := p.DNSPolicy
	if policy == nil {
		return nil
	}
	switch policy.QueryStrategy {
	case "UseIP", "UseIPv4", "UseIPv6":
	default:
		return fmt.Errorf("invalid DNS query strategy")
	}
	if len(policy.Resolvers) == 0 || len(policy.Resolvers) > 128 {
		return fmt.Errorf("DNS policy requires 1..128 resolvers")
	}
	ids := map[string]bool{"direct": true}
	byID := make(map[string]panel.Outbound, len(p.Outbounds))
	for _, out := range p.Outbounds {
		ids[out.ID] = true
		byID[out.ID] = out
	}
	links, err := chainLinks(p.Outbounds)
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	budget := routeRuleBudget{scope: "ordered DNS and routing", maxRules: MaxOrderedValues, maxBytes: MaxOrderedMatchBytes}
	for _, rule := range p.Rules {
		values, err := orderedValues(rule)
		if err != nil {
			return err
		}
		if err := budget.add(rule.Kind, values); err != nil {
			return err
		}
	}
	for i, r := range policy.Resolvers {
		if !orderedID(r.ID, "dns_") || seen[r.ID] {
			return fmt.Errorf("invalid or duplicate DNS resolver ID")
		}
		seen[r.ID] = true
		if !ids[r.OutboundID] {
			return fmt.Errorf("invalid DNS outbound")
		}
		if r.Protocol == "udp" {
			// SOCKS and Freedom forward UDP as UDP; an HTTP predecessor cannot
			// carry it. Encapsulating protocols have their own transport contract.
			for id := r.OutboundID; id != "direct" && id != ""; id = links[id] {
				protocol := normalizeOutboundProtocol(byID[id].Protocol)
				if protocol == "http" {
					return fmt.Errorf("UDP DNS cannot use an HTTP outbound or UDP predecessor")
				}
				if protocol != "socks" && protocol != "freedom" {
					break
				}
			}
		}
		if r.Domains == nil || (i == len(policy.Resolvers)-1) != (len(r.Domains) == 0) {
			return fmt.Errorf("only the last DNS resolver must have empty domains")
		}
		values, err := buildDomainRules(r.Domains)
		if err != nil {
			return err
		}
		if (i == len(policy.Resolvers)-1) != (len(values) == 0) {
			return fmt.Errorf("only the last DNS resolver may have empty normalized domains")
		}
		if err := budget.add("DNS domains", values); err != nil {
			return err
		}
		host, _, err := PolicyDNSHost(r)
		if err != nil {
			return err
		}
		if r.BootstrapIP != "" {
			ip, err := netip.ParseAddr(r.BootstrapIP)
			if err != nil || ip.Zone() != "" {
				return fmt.Errorf("invalid DNS bootstrap IP")
			}
			if _, err := netip.ParseAddr(host); err == nil {
				return fmt.Errorf("IP resolver does not use a bootstrap IP")
			}
		}
	}
	return nil
}

// Validate resolver/outbound bootstrap dependencies using the same domain data
// as the core. A separate IP-addressed resolver can break a hostname cycle.
func validateDNSDependencies(p *panel.RoutingPolicy) error {
	policy := p.DNSPolicy
	bootstrapHosts, err := policyBootstrapHosts(policy)
	if err != nil {
		return err
	}
	matchers := make([]geodata.DomainMatcher, len(policy.Resolvers)-1)
	for i, r := range policy.Resolvers[:len(policy.Resolvers)-1] {
		values, err := buildDomainRules(r.Domains)
		if err != nil {
			return err
		}
		rules, err := geodata.ParseDomainRules(values, geodata.Domain_Full)
		if err != nil {
			return err
		}
		matchers[i], err = geodata.DomainReg.BuildDomainMatcher(rules)
		if err != nil {
			return err
		}
	}
	resolverFor := func(host string) int {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		for i, matcher := range matchers {
			if len(matcher.Match(host)) != 0 {
				return i
			}
		}
		return len(policy.Resolvers) - 1
	}
	byID := make(map[string]panel.Outbound, len(p.Outbounds))
	for _, out := range p.Outbounds {
		byID[out.ID] = out
	}
	links, err := chainLinks(p.Outbounds)
	if err != nil {
		return err
	}
	dependencies := make([][]int, len(policy.Resolvers))
	for i, r := range policy.Resolvers {
		host, _, err := PolicyDNSHost(r)
		if err != nil {
			return err
		}
		if _, err := netip.ParseAddr(host); err != nil && r.BootstrapIP == "" {
			dependencies[i] = append(dependencies[i], resolverFor(host))
		}
		for id := r.OutboundID; id != "direct" && id != ""; {
			out := byID[id]
			// Raw settings may contain several upstream servers. Inspect their
			// endpoint addresses without treating passwords or paths as hosts.
			_, settings, err := buildOutboundSettings(out)
			if err != nil {
				return err
			}
			var object any
			if settings != nil && json.Unmarshal(*settings, &object) == nil {
				var endpoints func(any)
				endpoints = func(value any) {
					switch value := value.(type) {
					case map[string]any:
						for key, child := range value {
							if strings.EqualFold(key, "address") {
								if host, ok := child.(string); ok && host != "" && bootstrapHosts[strings.ToLower(strings.TrimSuffix(host, "."))] == "" {
									if _, err := netip.ParseAddr(host); err != nil {
										dependencies[i] = append(dependencies[i], resolverFor(host))
									}
								}
							} else {
								endpoints(child)
							}
						}
					case []any:
						for _, child := range value {
							endpoints(child)
						}
					}
				}
				endpoints(object)
			}
			id = links[out.ID]
		}
	}
	state := make([]uint8, len(dependencies))
	var visit func(int) error
	visit = func(i int) error {
		if state[i] == 1 {
			return fmt.Errorf("DNS bootstrap dependency cycle at %s; use an independent resolver or bootstrap IP", policy.Resolvers[i].ID)
		}
		if state[i] == 2 {
			return nil
		}
		state[i] = 1
		for _, dependency := range dependencies[i] {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		state[i] = 2
		return nil
	}
	for i := range dependencies {
		if err := visit(i); err != nil {
			return err
		}
	}
	return nil
}

func buildPolicyDNS(p *panel.RoutingPolicy) (*coreConf.DNSConfig, []json.RawMessage, error) {
	if err := validateDNSPolicy(p); err != nil {
		return nil, nil, err
	}
	if err := validateDNSDependencies(p); err != nil {
		return nil, nil, err
	}
	policy := p.DNSPolicy
	config := &coreConf.DNSConfig{QueryStrategy: policy.QueryStrategy, DisableFallback: true, DisableFallbackIfMatch: true}
	hosts, err := policyBootstrapHosts(policy)
	if err != nil {
		return nil, nil, err
	}
	if len(hosts) != 0 {
		staticHosts := make(map[string]string, len(hosts))
		for host, ip := range hosts {
			staticHosts["full:"+host] = ip
		}
		raw, err := json.Marshal(staticHosts)
		if err != nil {
			return nil, nil, err
		}
		config.Hosts = &coreConf.HostsWrapper{}
		if err := json.Unmarshal(raw, config.Hosts); err != nil {
			return nil, nil, err
		}
	}
	var routes []json.RawMessage
	for _, r := range policy.Resolvers {
		host, port, err := PolicyDNSHost(r)
		if err != nil {
			return nil, nil, err
		}
		address := host
		if r.Protocol == "tcp" {
			address = (&url.URL{Scheme: "tcp", Host: xnet.JoinHostPort(host, strconv.Itoa(int(port)))}).String()
		}
		if r.Protocol == "https" {
			address = r.Address
		}
		values, err := buildDomainRules(r.Domains)
		if err != nil {
			return nil, nil, err
		}
		if len(values) == 0 {
			values = []string{"regexp:.*"}
		}
		tag := PolicyDNSTag(r.ID)
		config.Servers = append(config.Servers, &coreConf.NameServerConfig{Address: &coreConf.Address{Address: xnet.ParseAddress(address)}, Port: port, Domains: values, Tag: tag, FinalQuery: true, SkipFallback: true})
		out := r.OutboundID
		if out == "direct" {
			out = DefaultTag
		} else {
			out = "routing_" + out
		}
		rule, err := json.Marshal(map[string]any{"inboundTag": []string{tag}, "outboundTag": out})
		if err != nil {
			return nil, nil, err
		}
		routes = append(routes, rule)
	}
	return config, routes, nil
}
