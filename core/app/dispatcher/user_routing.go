package dispatcher

import (
	stderrors "errors"
	"fmt"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
)

func (d *DefaultDispatcher) SetIPRuleChecks(enabled bool, blocked map[string]bool) {
	d.guardIPRules, d.blockedOutbounds = enabled, blocked
}

// SetIPStrategy selects the preferred family after DNS resolution. It does not
// change DNS queries or routing predicates; it only orders eligible addresses.
func (d *DefaultDispatcher) SetIPStrategy(strategy string) {
	d.ipStrategy = strategy
}

// orderCandidateIPs keeps the original order for unset/unknown strategies.
func orderCandidateIPs(ips []net.IP, strategy string) []net.IP {
	if strategy != "prefer_ipv4" && strategy != "prefer_ipv6" {
		return ips
	}
	v4 := make([]net.IP, 0, len(ips))
	v6 := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	if strategy == "prefer_ipv6" {
		return append(v6, v4...)
	}
	return append(v4, v6...)
}

// A user selector must not change how the destination predicates are checked.
// For v2 policies with IP conditions, re-evaluate with resolved addresses before
// dialing, retaining domain/user predicates and ordered explicit exceptions.
func (d *DefaultDispatcher) checkedDestination(ctx routing.Context, domain string) (routing.Route, net.IP, error) {
	if d.dnsClient == nil {
		return nil, nil, fmt.Errorf("DNS client unavailable")
	}
	ips, _, err := d.dnsClient.LookupIP(domain, dns.IPOption{IPv4Enable: true, IPv6Enable: true})
	if err != nil {
		return nil, nil, err
	}
	if len(ips) == 0 {
		return nil, nil, fmt.Errorf("target lookup returned no addresses")
	}
	selected, err := d.router.PickRoute(resolvedRoutingContext{Context: ctx, ips: ips})
	if err != nil && !stderrors.Is(err, common.ErrNoClue) {
		return nil, nil, err
	}
	// Keep block detection and route-consistency errors in the original DNS
	// order. Only the eligible addresses are reordered for family preference.
	var candidates []net.IP
	for _, ip := range ips {
		route, err := d.router.PickRoute(resolvedRoutingContext{Context: ctx, ips: []net.IP{ip}})
		if err != nil && !stderrors.Is(err, common.ErrNoClue) {
			return nil, nil, err
		}
		if route != nil && (route.GetOutboundTag() == "block" || d.blockedOutbounds[route.GetOutboundTag()]) {
			return route, ip, nil
		}
		if selected == nil && route == nil || selected != nil && route != nil && selected.GetRuleTag() == route.GetRuleTag() && selected.GetOutboundTag() == route.GetOutboundTag() {
			candidates = append(candidates, ip)
		}
	}
	if len(candidates) == 0 {
		return nil, nil, fmt.Errorf("no address matches selected route")
	}
	return selected, orderCandidateIPs(candidates, d.ipStrategy)[0], nil
}
